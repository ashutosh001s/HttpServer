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
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#define SOCKET int
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#define closesocket close
#endif
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <chrono>
#include <iomanip>

int PORT = 8080;
#define BUFFER_SIZE 8192

std::atomic<bool> server_running(true);
std::mutex cout_mutex;

// Logger class with timestamps
class Logger
{
public:
    static void safe_print(const std::string &message, const std::string &level = "INFO")
    {
        std::lock_guard<std::mutex> lock(cout_mutex);
        auto now = std::chrono::system_clock::now();
        std::time_t now_time = std::chrono::system_clock::to_time_t(now);
        std::cout << "[" << std::put_time(std::localtime(&now_time), "%Y-%m-%d %H:%M:%S")
                  << "] [" << level << "] " << message << std::endl;
    }
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
            SSL_CTX_free(ctx);
    }

    bool init()
    {
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        ctx = SSL_CTX_new(TLS_server_method());
        if (!ctx)
            return false;

        const char *certPath = std::getenv("SSL_CERT_PATH");
        const char *keyPath = std::getenv("SSL_KEY_PATH");

        if (!certPath || !keyPath)
        {
            std::cerr << "Error: SSL certificate or key path not set in environment variables." << std::endl;
            return false;
        }

        if (SSL_CTX_use_certificate_file(ctx, certPath, SSL_FILETYPE_PEM) <= 0 ||
            SSL_CTX_use_PrivateKey_file(ctx, keyPath, SSL_FILETYPE_PEM) <= 0 ||
            !SSL_CTX_check_private_key(ctx))
        {
            std::cerr << "Error: Failed to load SSL certificate or key." << std::endl;
            return false;
        }

        // if (SSL_CTX_use_certificate_file(ctx, "C:\\SSL_CERT\\server.crt", SSL_FILETYPE_PEM) <= 0 ||
        //     SSL_CTX_use_PrivateKey_file(ctx, "C:\\SSL_CERT\\server.key", SSL_FILETYPE_PEM) <= 0 ||
        //     !SSL_CTX_check_private_key(ctx)) {
        //     return false;
        // }
        return true;
    }
    SSL_CTX *getContext() { return ctx; }
};

using RouteHandler = std::function<std::string(const std::string &)>;

// Router class to manage HTTP routes
class Router
{
private:
    std::unordered_map<std::string, std::unordered_map<std::string, RouteHandler>> routes;

public:
    void add_route(const std::string &method, const std::string &path, RouteHandler handler)
    {
        routes[method][path] = handler;
    }
    std::string handle_request(const std::string &method, const std::string &path, const std::string &body)
    {
        if (routes[method].find(path) != routes[method].end())
        {
            return routes[method][path](body);
        }
        return "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\nRoute not found";
    }
};

// Client handler for processing requests
class ClientHandler
{
public:
    static void handle(SSL *ssl, sockaddr_in client_addr, Router &router)
    {
        Logger::safe_print("New client connected...");

        char buffer[BUFFER_SIZE] = {0};
        int bytes_received = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
        if (bytes_received <= 0)
        {
            Logger::safe_print("Error reading request. Closing connection.", "ERROR");
            SSL_shutdown(ssl);
            SSL_free(ssl);
            return;
        }

        std::string request(buffer);
        std::istringstream request_stream(request);
        std::string method, path, http_version, body;
        request_stream >> method >> path >> http_version;

        size_t body_start = request.find("\r\n\r\n");
        if (body_start != std::string::npos)
        {
            body = request.substr(body_start + 4);
        }

        // Handle query parameters
        size_t query_start = path.find('?');
        if (query_start != std::string::npos)
        {
            path = path.substr(0, query_start);
        }

        Logger::safe_print("Method: " + method + ", Path: " + path);
        std::string response = router.handle_request(method, path, body);
        SSL_write(ssl, response.c_str(), static_cast<int>(response.size()));

        Logger::safe_print("Response sent. Closing connection.");
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
};

// Main Server class
class Server
{
private:
    SOCKET server_fd;
    SSLManager sslManager;
    Router router;

public:
    Server() : server_fd(INVALID_SOCKET) {}
    ~Server()
    {
        if (server_fd != INVALID_SOCKET)
            closesocket(server_fd);
    }

    bool init()
    {
#ifdef _WIN32
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
            return false;
#endif
        if (!sslManager.init())
            return false;

        server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd == INVALID_SOCKET)
            return false;

        sockaddr_in server_addr = {0};
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_port = htons(PORT);

        if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR ||
            listen(server_fd, SOMAXCONN) == SOCKET_ERROR)
            return false;

        return true;
    }

    void register_route(const std::string &method, const std::string &path, RouteHandler handler)
    {
        router.add_route(method, path, handler);
    }

    void run()
    {
        Logger::safe_print("Server listening on port " + std::to_string(PORT));

        while (server_running)
        {
            sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            SOCKET client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
            if (client_fd == INVALID_SOCKET)
                continue;

            SSL *ssl = SSL_new(sslManager.getContext());
            SSL_set_fd(ssl, client_fd);
            if (SSL_accept(ssl) <= 0)
            {
                SSL_free(ssl);
                closesocket(client_fd);
                continue;
            }

            std::thread client_thread([ssl, client_addr, this]()
                                      { ClientHandler::handle(ssl, client_addr, router); });
            client_thread.detach();
        }
    }
};

void signal_handler(int signal)
{
    if (signal == SIGINT)
    {
        Logger::safe_print("Shutting down server...", "WARN");
        server_running = false;
    }
}

int main(int argc, char* argv[])
{

    PORT = 8080; // Default port

    // Parse command-line arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--port" && i + 1 < argc) {
            PORT = std::stoi(argv[i + 1]);
            i++; // Skip the next argument since it's the port number
        }
    }

    std::signal(SIGINT, signal_handler);
    Server server;
    if (!server.init())
    {
        Logger::safe_print("Server initialization failed", "ERROR");
        return 1;
    }

    server.register_route("GET", "/", [](const std::string &)
                          { return "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nWelcome!"; });
    // server.register_route("GET", "/", [](const std::string&) { return "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nWelcome!"; });
    server.register_route("POST", "/register", [](const std::string &body)
                          { return "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nUser Registered: " + body; });
    server.run();
    return 0;
}
