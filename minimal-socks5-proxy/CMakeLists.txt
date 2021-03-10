add_executable(minimal-socks5-proxy
    src/main.cpp
)

target_link_libraries(minimal-socks5-proxy PRIVATE ce::asio-main)

ntc_target(minimal-socks5-proxy)
