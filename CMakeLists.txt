cmake_minimum_required(VERSION 3.16)

project(minimal-socks5
    DESCRIPTION "A minimal SOCKS5 proxy"
    VERSION 0.0.0
    LANGUAGES CXX
)

find_package(ntc-cmake 1.1.0 REQUIRED)
include(ntc-dev-build)

find_package(Boost 1.74 REQUIRED COMPONENTS context log thread)

add_subdirectory(utils)
add_subdirectory(asio-utils)
add_subdirectory(minimal-socks5-proxy)
