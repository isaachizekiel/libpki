cmake_minimum_required(VERSION 3.16)
project(pkitool-test)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS "-O0 -ggdb -Wall")

find_package(OpenSSL REQUIRED)

add_library(pkitool pkitool.c)
target_link_libraries(pkitool OpenSSL::Crypto)

add_executable(pkitool-test pkitool-test.c)
target_link_libraries(pkitool-test pkitool)

