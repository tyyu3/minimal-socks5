Examples for COSEC students
===========================

- Serialization:
  - `interprocess-copy`: benchmark of various interprocess data copy implementations.
- Asynchrony:
  - `thread-pool`: simple thread pool and executor usage.
  - `asio-basic`: basic asynchronous tcp server with logging and error handling.
- Qt:
  - `layouts-painting`: basic use signals/slots, Qt Designer, layouts and mouse/paint events for custom-looking widgets.
  - `item-models`: usage of Qt Item Models and Views/Widgets.
  - `gui-progress`: offloading lengthy tasks to a non-gui QThread and communicating with it using queued signals/slots.
  - `geohash`: qtpositioning + simple use of `QNetworkAccessManager` from qtnetwork.

Dependencies:
- C++ compiler and standard library with sufficient support for C++20.
- \>=ntc-cmake-1.0.1 - see https://github.com/palebedev/ntc-cmake
- \>=Boost-1.74.0
- \>=google-benchmark-1.5.0
