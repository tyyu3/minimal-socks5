# minimal-socks5

`minimal-socks5` is a basic SOCKS5 server implementation that doesn't support anything beside no authentication and outgoing TCP/IPv4 or TCP/domain connections without port binding.

## Implementation

The implementation is based on [custom coroutines](https://github.com/palebedev/cosec-examples/blob/master/asio-utils/include/ce/spawn.hpp) by P.A. Lebedev.

## Usage
```bash
minimal-socks5 <port> [<number of threads>]
```
