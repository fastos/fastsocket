set(CMAKE_SYSTEM_NAME "Generic")
set(CMAKE_SYSTEM_PROCESSOR "sh2")

set_property(DIRECTORY PROPERTY TARGET_SUPPORTS_SHARED_LIBS FALSE)

set(CMAKE_FIND_ROOT_PATH ${CMAKE_SOURCE_DIR}/toolchain/inst/)

set(CMAKE_C_FLAGS "-m2 -ml -Os -ffreestanding -nostartfiles")
set(CMAKE_C_LINK_FLAGS "-static -EL -x --gc-sections")

set(OBJCOPY ${CMAKE_SOURCE_DIR}/toolchain/inst/bin/sh-elf-objcopy)
set(CMAKE_C_COMPILER "${CMAKE_SOURCE_DIR}/toolchain/inst/bin/sh-elf-gcc")
set(CMAKE_AR ${CMAKE_SOURCE_DIR}/toolchain/inst/bin/sh-elf-ar)
set(CMAKE_ASM_COMPILER ${CMAKE_SOURCE_DIR}/toolchain/inst/bin/sh-elf-as)
set(CMAKE_ASM-ATT_COMPILER ${CMAKE_SOURCE_DIR}/toolchain/inst/bin/sh-elf-as)
set(CMAKE_LINKER ${CMAKE_SOURCE_DIR}/toolchain/inst/bin/sh-elf-ld)
set(CMAKE_C_LINK_EXECUTABLE "${CMAKE_SOURCE_DIR}/toolchain/inst/bin/sh-elf-ld <OBJECTS> <CMAKE_C_LINK_FLAGS> <LINK_FLAGS> -o <TARGET>")

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
