cmake_minimum_required(VERSION 3.16)
project(libpki)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "-O0 -ggdb")

find_package(OpenSSL REQUIRED)

add_executable(libpki main.cpp)

target_link_libraries(libpki OpenSSL::Crypto)