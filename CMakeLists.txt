cmake_minimum_required(VERSION 2.8)

project(final)

set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} -std=c++11)

find_package(Threads)

add_executable(final main.cpp)

target_link_libraries(final ${CMAKE_THREAD_LIBS_INIT})
