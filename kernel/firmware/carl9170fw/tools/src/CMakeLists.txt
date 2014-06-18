cmake_minimum_required(VERSION 2.8)

project(tools)

add_custom_target(wol ALL COMMAND gcc wol.c -o wol)

set(tools fwinfo miniboot checksum eeprom_fix)

foreach(tool ${tools})
	add_executable( ${tool} ${tool}.c )
	add_definitions("-std=gnu99 -Wall -Wextra -Wshadow")
	target_link_libraries( ${tool} carlfw )
endforeach()
