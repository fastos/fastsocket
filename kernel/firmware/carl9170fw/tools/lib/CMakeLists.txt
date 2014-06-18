cmake_minimum_required(VERSION 2.8)

project(libcarlfw)

set(carlfw_src carlfw.c)

add_library( carlfw STATIC ${carlfw_src})
