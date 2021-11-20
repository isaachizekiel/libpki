cmake_minimum_required(VERSION 3.16)
project(pkitool)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS "-O0 -ggdb")

find_package(OpenSSL REQUIRED)

add_executable(pkitool main.c)

target_link_libraries(pkitool OpenSSL::Crypto)
