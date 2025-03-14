#include <iostream>
#include <thread>
#include <vector>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <functional>
#include <sstream>
#include <cstring>
#include <csignal>
#include <queue>
#include <condition_variable>
#include <chrono>
#include <iomanip>
#include <memory>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#define SOCKET int
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#define closesocket close
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>

// Configuration
struct ServerConfig
{
    int port = 8080;
    int thread_pool_size = 4;
    int connection_timeout_sec = 30;
    int max_connections = 100;
    std::string cert_path;
    std::string key_path;
};

std::atomic<bool> server_running(true);
std::mutex cout_mutex;

// Logger class with timestamps
class Logger
{
public:
    enum class Level
    {
        DEBUG,
        INFO,
        WARN,
        FATAL
    };

    static void log(const std::string &message, Level level = Level::INFO)
    {
        std::lock_guard<std::mutex> lock(cout_mutex);
        auto now = std::chrono::system_clock::now();
        std::time_t now_time = std::chrono::system_clock::to_time_t(now);

        const char *level_str;
        switch (level)
        {
        case Level::DEBUG:
            level_str = "DEBUG";
            break;
        case Level::INFO:
            level_str = "INFO";
            break;
        case Level::WARN:
            level_str = "WARN";
            break;
        case Level::FATAL:
            level_str = "ERROR";
            break;
        default:
            level_str = "UNKNOWN";
        }

        std::cout << "[" << std::put_time(std::localtime(&now_time), "%Y-%m-%d %H:%M:%S")
                  << "] [" << level_str << "] " << message << std::endl;
    }
};

// Thread pool for handling client connections
class ThreadPool
{
public:
    ThreadPool(size_t num_threads) : stop(false)
    {
        for (size_t i = 0; i < num_threads; ++i)
        {
            workers.emplace_back([this]
                                 {
                while (true) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(queue_mutex);
                        condition.wait(lock, [this] { return stop || !tasks.empty(); });
                        if (stop && tasks.empty()) {
                            return;
                        }
                        task = std::move(tasks.front());
                        tasks.pop();
                    }
                    task();
                } });
        }
    }

    template <class F>
    void enqueue(F &&f)
    {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            if (stop)
            {
                throw std::runtime_error("ThreadPool has been stopped");
            }
            tasks.emplace(std::forward<F>(f));
        }
        condition.notify_one();
    }

    ~ThreadPool()
    {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            stop = true;
        }
        condition.notify_all();
        for (std::thread &worker : workers)
        {
            if (worker.joinable())
            {
                worker.join();
            }
        }
    }

private:
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;
    std::mutex queue_mutex;
    std::condition_variable condition;
    bool stop;
};

// HTTP Request structure
struct HTTPRequest
{
    std::string method;
    std::string path;
    std::string http_version;
    std::unordered_map<std::string, std::string> headers;
    std::string body;
    std::unordered_map<std::string, std::string> query_params;
};

// HTTP Response structure
class HTTPResponse
{
public:
    HTTPResponse(int status_code = 200, const std::string &status_text = "OK")
        : status_code(status_code), status_text(status_text)
    {
        headers["Content-Type"] = "text/plain";
        headers["Connection"] = "close";
    }

    void set_header(const std::string &name, const std::string &value)
    {
        headers[name] = value;
    }

    void set_body(const std::string &new_body)
    {
        body = new_body;
        headers["Content-Length"] = std::to_string(body.length());
    }

    std::string to_string() const
    {
        std::stringstream ss;
        ss << "HTTP/1.1 " << status_code << " " << status_text << "\r\n";

        for (const auto &header : headers)
        {
            ss << header.first << ": " << header.second << "\r\n";
        }
        ss << "\r\n"
           << body;

        return ss.str();
    }

private:
    int status_code;
    std::string status_text;
    std::unordered_map<std::string, std::string> headers;
    std::string body;
};

// SSL Manager for handling TLS setup
class SSLManager
{
private:
    SSL_CTX *ctx;

public:
    SSLManager() : ctx(nullptr) {}

    ~SSLManager()
    {
        if (ctx)
        {
            SSL_CTX_free(ctx);
        }
        // Cleanup OpenSSL
        EVP_cleanup();
        ERR_free_strings();
    }

    bool init(const std::string &cert_path, const std::string &key_path)
    {
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();

        ctx = SSL_CTX_new(TLS_server_method());
        if (!ctx)
        {
            log_ssl_error("Failed to create SSL context");
            return false;
        }

        // Set up modern security options
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
        SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);

        // Set the cipher list to secure ones
        if (SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!MD5:!RC4") != 1)
        {
            log_ssl_error("Failed to set cipher list");
            return false;
        }

        // Set up session caching
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);
        SSL_CTX_set_timeout(ctx, 300); // 5 minutes session timeout

        // Load certificate and private key
        if (SSL_CTX_use_certificate_file(ctx, cert_path.c_str(), SSL_FILETYPE_PEM) <= 0)
        {
            log_ssl_error("Failed to load certificate file");
            return false;
        }

        if (SSL_CTX_use_PrivateKey_file(ctx, key_path.c_str(), SSL_FILETYPE_PEM) <= 0)
        {
            log_ssl_error("Failed to load private key file");
            return false;
        }

        if (!SSL_CTX_check_private_key(ctx))
        {
            log_ssl_error("Private key does not match certificate");
            return false;
        }

        return true;
    }

    SSL_CTX *get_context()
    {
        return ctx;
    }

private:
    void log_ssl_error(const std::string &message)
    {
        unsigned long err = ERR_get_error();
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        Logger::log(message + ": " + err_buf, Logger::Level::FATAL);
    }
};

// Helper function to parse HTTP requests
HTTPRequest parse_http_request(const std::string &request_str)
{
    HTTPRequest req;
    std::istringstream stream(request_str);

    // Parse request line
    stream >> req.method >> req.path >> req.http_version;

    // Parse query parameters
    size_t query_start = req.path.find('?');
    if (query_start != std::string::npos)
    {
        std::string query_string = req.path.substr(query_start + 1);
        req.path = req.path.substr(0, query_start);

        std::istringstream query_stream(query_string);
        std::string param;
        while (std::getline(query_stream, param, '&'))
        {
            size_t equals_pos = param.find('=');
            if (equals_pos != std::string::npos)
            {
                std::string name = param.substr(0, equals_pos);
                std::string value = param.substr(equals_pos + 1);
                req.query_params[name] = value;
            }
        }
    }

    // Parse headers
    std::string line;
    while (std::getline(stream, line) && line != "\r")
    {
        size_t colon_pos = line.find(':');
        if (colon_pos != std::string::npos)
        {
            std::string header_name = line.substr(0, colon_pos);
            // Skip the colon and any spaces
            size_t value_start = line.find_first_not_of(" ", colon_pos + 1);
            if (value_start != std::string::npos)
            {
                std::string header_value = line.substr(value_start);
                // Remove trailing \r if present
                if (!header_value.empty() && header_value.back() == '\r')
                {
                    header_value.pop_back();
                }
                req.headers[header_name] = header_value;
            }
        }
    }

    // Parse body if Content-Length is provided
    if (req.headers.count("Content-Length"))
    {
        int content_length = std::stoi(req.headers["Content-Length"]);
        if (content_length > 0)
        {
            // Read the body
            char *body_buffer = new char[content_length + 1];
            stream.read(body_buffer, content_length);
            body_buffer[content_length] = '\0';
            req.body = std::string(body_buffer);
            delete[] body_buffer;
        }
    }

    return req;
}

// Set socket to non-blocking mode
bool set_nonblocking(SOCKET sock)
{
#ifdef _WIN32
    u_long mode = 1;
    return (ioctlsocket(sock, FIONBIO, &mode) == 0);
#else
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1)
        return false;
    return (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == 0);
#endif
}

// Router class with path parameter support
class Router
{
public:
    using RouteHandler = std::function<HTTPResponse(const HTTPRequest &)>;

    void add_route(const std::string &method, const std::string &path, RouteHandler handler)
    {
        routes[method][path] = handler;
    }

    HTTPResponse handle_request(const HTTPRequest &request)
    {
        if (routes[request.method].find(request.path) != routes[request.method].end())
        {
            try
            {
                return routes[request.method][request.path](request);
            }
            catch (const std::exception &e)
            {
                Logger::log("Error in route handler: " + std::string(e.what()), Logger::Level::FATAL);
                HTTPResponse response(500, "Internal Server Error");
                response.set_body("Internal server error occurred");
                return response;
            }
        }

        // Not found
        HTTPResponse response(404, "Not Found");
        response.set_body("Route not found: " + request.method + " " + request.path);
        return response;
    }

private:
    std::unordered_map<std::string, std::unordered_map<std::string, RouteHandler>> routes;
};

// Client connection class
class ClientConnection
{
public:
    ClientConnection(SOCKET socket, SSL *ssl, sockaddr_in addr)
        : client_socket(socket), ssl(ssl), client_addr(addr),
          creation_time(std::chrono::steady_clock::now()) {}

    ~ClientConnection()
    {
        if (ssl)
        {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        if (client_socket != INVALID_SOCKET)
        {
            closesocket(client_socket);
        }
    }

    SOCKET get_socket() const { return client_socket; }
    SSL *get_ssl() const { return ssl; }

    std::string get_client_ip() const
    {
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(client_addr.sin_addr), ip, INET_ADDRSTRLEN);
        return std::string(ip);
    }

    bool is_timed_out(int timeout_seconds) const
    {
        auto now = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - creation_time).count();
        return duration > timeout_seconds;
    }

private:
    SOCKET client_socket;
    SSL *ssl;
    sockaddr_in client_addr;
    std::chrono::steady_clock::time_point creation_time;
};

// Server class
class Server
{
public:
    Server(const ServerConfig &config) : config(config), server_fd(INVALID_SOCKET),
                                         thread_pool(config.thread_pool_size) {}

    ~Server()
    {
        shutdown();
    }

    bool init()
    {
#ifdef _WIN32
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        {
            Logger::log("WSAStartup failed", Logger::Level::FATAL);
            return false;
        }
#endif

        // Initialize SSL
        if (!ssl_manager.init(config.cert_path, config.key_path))
        {
            Logger::log("SSL initialization failed", Logger::Level::FATAL);
            return false;
        }

        // Create socket
        server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd == INVALID_SOCKET)
        {
            Logger::log("Failed to create socket", Logger::Level::FATAL);
            return false;
        }

        // Set socket options
        int opt = 1;
        if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt)) < 0)
        {
            Logger::log("Failed to set socket options", Logger::Level::FATAL);
            return false;
        }

        // Set non-blocking mode
        if (!set_nonblocking(server_fd))
        {
            Logger::log("Failed to set non-blocking mode", Logger::Level::FATAL);
            return false;
        }

        // Bind and listen
        sockaddr_in server_addr = {0};
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_port = htons(config.port);

        if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR)
        {
            Logger::log("Bind failed", Logger::Level::FATAL);
            return false;
        }

        if (listen(server_fd, SOMAXCONN) == SOCKET_ERROR)
        {
            Logger::log("Listen failed", Logger::Level::FATAL);
            return false;
        }

        return true;
    }

    void register_route(const std::string &method, const std::string &path, Router::RouteHandler handler)
    {
        router.add_route(method, path, handler);
    }

    void run()
    {
        Logger::log("Server listening on port " + std::to_string(config.port));

        // Start connection cleanup thread
        std::thread cleanup_thread(&Server::cleanup_connections, this);
        cleanup_thread.detach();

        while (server_running)
        {
            if (active_connections.size() >= static_cast<size_t>(config.max_connections))
            {
                // Too many connections, wait a bit
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }

            sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);

            // Non-blocking accept
            SOCKET client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
            if (client_fd == INVALID_SOCKET)
            {
                // In non-blocking mode, this is not necessarily an error
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            }

            // Set client socket to non-blocking
            if (!set_nonblocking(client_fd))
            {
                Logger::log("Failed to set client socket to non-blocking mode", Logger::Level::FATAL);
                closesocket(client_fd);
                continue;
            }

            // Set up SSL
            SSL *ssl = SSL_new(ssl_manager.get_context());
            if (!ssl)
            {
                Logger::log("Failed to create SSL structure", Logger::Level::FATAL);
                closesocket(client_fd);
                continue;
            }

            SSL_set_fd(ssl, client_fd);

            // Create connection object
            auto connection = std::make_shared<ClientConnection>(client_fd, ssl, client_addr);

            // Add to active connections
            {
                std::lock_guard<std::mutex> lock(connections_mutex);
                active_connections.push_back(connection);
            }

            // Handle connection in thread pool
            thread_pool.enqueue([this, connection]()
                                {
                handle_client(connection);
                
                // Remove from active connections
                std::lock_guard<std::mutex> lock(connections_mutex);
                active_connections.erase(
                    std::remove_if(active_connections.begin(), active_connections.end(),
                        [&connection](const std::shared_ptr<ClientConnection>& conn) {
                            return conn->get_socket() == connection->get_socket();
                        }),
                    active_connections.end()
                ); });
        }
    }

    void shutdown()
    {
        server_running = false;

        // Close all connections
        std::lock_guard<std::mutex> lock(connections_mutex);
        active_connections.clear();

        if (server_fd != INVALID_SOCKET)
        {
            closesocket(server_fd);
            server_fd = INVALID_SOCKET;
        }

#ifdef _WIN32
        WSACleanup();
#endif
    }

private:
    ServerConfig config;
    SOCKET server_fd;
    SSLManager ssl_manager;
    Router router;
    ThreadPool thread_pool;

    std::vector<std::shared_ptr<ClientConnection>> active_connections;
    std::mutex connections_mutex;

    void cleanup_connections()
    {
        while (server_running)
        {
            std::this_thread::sleep_for(std::chrono::seconds(5));

            std::lock_guard<std::mutex> lock(connections_mutex);
            active_connections.erase(
                std::remove_if(active_connections.begin(), active_connections.end(),
                               [this](const std::shared_ptr<ClientConnection> &conn)
                               {
                                   return conn->is_timed_out(config.connection_timeout_sec);
                               }),
                active_connections.end());
        }
    }

    void handle_client(std::shared_ptr<ClientConnection> connection)
    {
        SSL *ssl = connection->get_ssl();
        std::string client_ip = connection->get_client_ip();

        Logger::log("New client connected from " + client_ip);

        // Perform SSL handshake (with timeout)
        bool ssl_connected = false;
        auto handshake_start_time = std::chrono::steady_clock::now();

        while (!ssl_connected && server_running)
        {
            // Check for timeout during handshake
            auto current_time = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(
                    current_time - handshake_start_time)
                    .count() > config.connection_timeout_sec)
            {
                Logger::log("SSL handshake timed out", Logger::Level::WARN);
                return;
            }

            int ret = SSL_accept(ssl);
            if (ret == 1)
            {
                // Handshake completed successfully
                ssl_connected = true;
            }
            else
            {
                int ssl_err = SSL_get_error(ssl, ret);
                if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE)
                {
                    // Would block, wait a bit and try again
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    continue;
                }
                else
                {
                    // Real error
                    Logger::log("SSL error code: " + std::to_string(ssl_err), Logger::Level::FATAL);

                    // Get all queued error messages
                    char err_buf[256];
                    unsigned long err;
                    while ((err = ERR_get_error()) != 0)
                    {
                        ERR_error_string_n(err, err_buf, sizeof(err_buf));
                        Logger::log("SSL error details: " + std::string(err_buf), Logger::Level::FATAL);
                    }
                    return;
                }
            }
        }

        if (!ssl_connected)
        {
            Logger::log("SSL handshake failed", Logger::Level::FATAL);
            return;
        }

        // Buffer for receiving data
        const int buffer_size = 8192 * 2;
        std::unique_ptr<char[]> buffer(new char[buffer_size]);

        // Read request
        std::string request_data;
        int bytes_received = 0;
        bool headers_complete = false;

        // Read with timeout
        auto start_time = std::chrono::steady_clock::now();

        while (server_running)
        {
            // Check for timeout
            auto current_time = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(
                    current_time - start_time)
                    .count() > config.connection_timeout_sec)
            {
                Logger::log("Client connection timed out", Logger::Level::WARN);
                return;
            }

            // Try to read data
            bytes_received = SSL_read(ssl, buffer.get(), buffer_size - 1);

            if (bytes_received > 0)
            {
                buffer[bytes_received] = '\0';
                request_data.append(buffer.get(), bytes_received);

                // Check if we've received the end of headers
                if (!headers_complete &&
                    (request_data.find("\r\n\r\n") != std::string::npos))
                {
                    headers_complete = true;

                    // If this is not a POST/PUT request or doesn't have Content-Length, we're done
                    if (request_data.find("POST") != 0 && request_data.find("PUT") != 0)
                    {
                        break;
                    }

                    // For POST/PUT, check if we have all the body based on Content-Length
                    size_t content_length_pos = request_data.find("Content-Length:");
                    if (content_length_pos == std::string::npos)
                    {
                        break; // No Content-Length header, we're done
                    }

                    // Extract Content-Length
                    size_t value_start = request_data.find_first_not_of(" ", content_length_pos + 15);
                    size_t value_end = request_data.find("\r\n", value_start);
                    std::string length_str = request_data.substr(value_start, value_end - value_start);
                    int content_length = std::stoi(length_str);

                    // Calculate how much of the body we already have
                    size_t headers_end = request_data.find("\r\n\r\n") + 4;
                    size_t body_received = request_data.length() - headers_end;

                    // If we have the full body, we're done
                    if (body_received >= static_cast<size_t>(content_length))
                    {
                        break;
                    }
                }
                else if (headers_complete)
                {
                    // We're already reading the body, check if we have a Content-Length
                    size_t content_length_pos = request_data.find("Content-Length:");
                    if (content_length_pos != std::string::npos)
                    {
                        size_t value_start = request_data.find_first_not_of(" ", content_length_pos + 15);
                        size_t value_end = request_data.find("\r\n", value_start);
                        std::string length_str = request_data.substr(value_start, value_end - value_start);
                        int content_length = std::stoi(length_str);

                        size_t headers_end = request_data.find("\r\n\r\n") + 4;
                        size_t body_received = request_data.length() - headers_end;

                        if (body_received >= static_cast<size_t>(content_length))
                        {
                            break; // We have the full body
                        }
                    }
                    else
                    {
                        break; // No Content-Length, assume we're done
                    }
                }
            }
            else if (bytes_received == 0)
            {
                // Connection closed
                break;
            }
            else
            {
                // Error or would block
                int ssl_error = SSL_get_error(ssl, bytes_received);
                if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE)
                {
                    // Would block, wait a bit and try again
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    continue;
                }
                else
                {
                    // Real error
                    Logger::log("SSL_read error: " + std::to_string(ssl_error), Logger::Level::FATAL);
                    return;
                }
            }
        }

        if (!request_data.empty())
        {
            // Parse the request
            HTTPRequest request = parse_http_request(request_data);

            // Handle the request
            HTTPResponse response = router.handle_request(request);

            // Send the response
            std::string response_str = response.to_string();
            SSL_write(ssl, response_str.c_str(), static_cast<int>(response_str.size()));

            Logger::log("Processed " + request.method + " " + request.path + " from " + client_ip);
        }
    }
};

void signal_handler(int signal)
{
    if (signal == SIGINT)
    {
        Logger::log("Shutting down server...", Logger::Level::WARN);
        server_running = false;
    }
}

int main(int argc, char *argv[])
{
    std::signal(SIGINT, signal_handler);

    ServerConfig config;

    // Parse command-line arguments
    for (int i = 1; i < argc; i++)
    {
        std::string arg = argv[i];
        if (arg == "--port" && i + 1 < argc)
        {
            config.port = std::stoi(argv[i + 1]);
            i++;
        }
        else if (arg == "--threads" && i + 1 < argc)
        {
            config.thread_pool_size = std::stoi(argv[i + 1]);
            i++;
        }
        else if (arg == "--timeout" && i + 1 < argc)
        {
            config.connection_timeout_sec = std::stoi(argv[i + 1]);
            i++;
        }
        else if (arg == "--max-connections" && i + 1 < argc)
        {
            config.max_connections = std::stoi(argv[i + 1]);
            i++;
        }
        else if (arg == "--cert" && i + 1 < argc)
        {
            config.cert_path = argv[i + 1];
            i++;
        }
        else if (arg == "--key" && i + 1 < argc)
        {
            config.key_path = argv[i + 1];
            i++;
        }
    }

    // Check for environment variables if not set via command line
    if (config.cert_path.empty())
    {
        const char *cert_path = std::getenv("SSL_CERT_PATH");
        if (cert_path)
        {
            config.cert_path = cert_path;
        }
        else
        {
            Logger::log("SSL certificate path not provided", Logger::Level::FATAL);
            return 1;
        }
    }

    if (config.key_path.empty())
    {
        const char *key_path = std::getenv("SSL_KEY_PATH");
        if (key_path)
        {
            config.key_path = key_path;
        }
        else
        {
            Logger::log("SSL key path not provided", Logger::Level::FATAL);
            return 1;
        }
    }

    Server server(config);

    if (!server.init())
    {
        Logger::log("Server initialization failed", Logger::Level::FATAL);
        return 1;
    }

    // Register routes
    server.register_route("GET", "/", [](const HTTPRequest &)
                          {
        HTTPResponse response;
        response.set_header("Content-Type", "text/plain");
        response.set_body("Welcome to the optimized HTTP server!");
        return response; });

    server.register_route("GET", "/info", [&config](const HTTPRequest &)
                          {
        HTTPResponse response;
        response.set_header("Content-Type", "application/json");
        
        std::stringstream json;
        json << "{\n";
        json << "  \"server\": \"Optimized HTTP Server\",\n";
        json << "  \"port\": " << config.port << ",\n";
        json << "  \"thread_pool_size\": " << config.thread_pool_size << ",\n";
        json << "  \"max_connections\": " << config.max_connections << ",\n";
        json << "  \"connection_timeout\": " << config.connection_timeout_sec << "\n";
        json << "}";
        
        response.set_body(json.str());
        return response; });

    server.register_route("POST", "/register", [](const HTTPRequest &request)
                          {
        HTTPResponse response;
        response.set_header("Content-Type", "application/json");
        
        std::string success_json = "{\"status\":\"success\",\"message\":\"User registered\",\"data\":" + 
                                   request.body + "}";
        
        response.set_body(success_json);
        return response; });

    server.run();

    return 0;
}