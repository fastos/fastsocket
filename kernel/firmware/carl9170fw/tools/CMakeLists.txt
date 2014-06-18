cmake_minimum_required(VERSION 2.8)

project(tools)

if (CONFIG_CARL9170FW_MAKE_RELEASE)
	set(CMAKE_BUILD_TYPE Release)
endif (CONFIG_CARL9170FW_MAKE_RELEASE)

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/extra)

include(GCCVersion)
include("../config.cmake")

_COMPILER_DUMPVERSION(_COMPILER_VERSION)

if (("${_COMPILER_VERSION}" VERSION_GREATER 44) OR
    ("${_COMPILER_VERSION}" VERSION_EQUAL 44))

	include_directories (../include/linux ../include/shared ../include lib include)
	add_subdirectory(lib)
	add_subdirectory(src)

	if (CONFIG_CARL9170FW_BUILD_TOOLS_CARLU)
		find_package(SDL QUIET)
		find_package(USB-1.0 QUIET)

		if ("${USB-1.0_FOUND}" AND "${SDL_FOUND}")
			add_subdirectory(carlu)
		else()
			if ("${USB-1.0_FOUND}")
				MESSAGE(ERROR "LibUSB not found\n")
			endif ("${USB-1.0_FOUND}")
			if ("${SDL_FOUND}")
				MESSAGE(ERROR "SDL not found\n")
			endif ("${SDL_FOUND}")
		endif ()
	endif (CONFIG_CARL9170FW_BUILD_TOOLS_CARLU)
endif ()
