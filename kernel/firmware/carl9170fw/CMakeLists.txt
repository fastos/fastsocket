cmake_minimum_required(VERSION 2.8)

project(carl9170)

#if you don't want the full compiler output, remove the following line
#set(CMAKE_VERBOSE_MAKEFILE ON)

include("config.cmake")

add_subdirectory(carlfw)

if (CONFIG_CARL9170FW_BUILD_MINIBOOT)
	add_subdirectory(minifw)
endif (CONFIG_CARL9170FW_BUILD_MINIBOOT)

if (CONFIG_CARL9170FW_BUILD_TOOLS)
	add_subdirectory(tools)
endif (CONFIG_CARL9170FW_BUILD_TOOLS)

