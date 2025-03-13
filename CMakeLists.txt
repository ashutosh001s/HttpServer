cmake_minimum_required(VERSION 3.15)
project(HttpServer)

set(CMAKE_CXX_STANDARD 17)

# Find OpenSSL
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# Gather source files from src/
file(GLOB_RECURSE SRC_FILES src/*.cpp)

# Ensure we have source files
if(NOT SRC_FILES)
    message(FATAL_ERROR "No source files found in src/")
endif()

# Create executable
add_executable(HttpServer ${SRC_FILES})

# Link OpenSSL
target_link_libraries(HttpServer OpenSSL::SSL OpenSSL::Crypto)
