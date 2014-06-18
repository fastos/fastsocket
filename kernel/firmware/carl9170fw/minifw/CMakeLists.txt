cmake_minimum_required(VERSION 2.8)

project(miniboot.fw)

include("../extra/sh-elf-linux.cmake")
include("../config.cmake")

set(miniboot_src miniboot.S)
set_source_files_properties(miniboot.S PROPERTIES LANGUAGE C)

add_executable(miniboot.elf miniboot.S)

set_target_properties(miniboot.elf PROPERTIES LINKER_LANGUAGE C)

set_target_properties(miniboot.elf PROPERTIES LINK_FLAGS "-Tminiboot.lds")

add_custom_target(
	miniboot.fw ALL
	${OBJCOPY} --strip-unneeded -O binary -R .sram -R .eeprom -R .fwdsc miniboot.elf miniboot.fw
	DEPENDS miniboot.elf)
