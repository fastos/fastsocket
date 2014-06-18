cmake_minimum_required(VERSION 2.8)

project(carlu)

find_package(SDL REQUIRED)
find_package(USB-1.0 REQUIRED)

set(carlu_src src/debug.c src/cmd.c src/usb.c src/rx.c src/tx.c src/fw.c
	      src/test.c src/main.c)

add_definitions(-D_GNU_SOURCE ${USB-1.0_DEFINITIONS})
add_definitions(-DCARLU_PATH="${CMAKE_CURRENT_SOURCE_DIR}")

include_directories(${SDL_INCLUDE_DIR} ${USB-1.0_INCLUDE_DIRS})

add_executable(carlu ${carlu_src})

target_link_libraries (carlu ${SDL_LIBRARY} ${USB-1.0_LIBRARIES} SDLmain carlfw)
