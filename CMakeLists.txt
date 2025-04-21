# Copyright (C) 2024-present, Guanyou.Chen. All rights reserved.

cmake_minimum_required(VERSION 3.21.1)
project(OpenLinuxAnalysisKit)

string(TOUPPER "${CMAKE_BUILD_TARGET_ARCH}" BUILD_TARGET_ARCH)
add_definitions(-D${BUILD_TARGET_ARCH})
add_definitions(-D__LITTLE_ENDIAN)

set(LINUX_PARSER_SOURCES
    parser.c
    core/core.c
    zram/zram.c
    zram/zram_drv.c
    crypto.c
    lib/lzo/lzo1x_decompress_safe.c
    lib/lz4/lz4_decompress.c
    shmem/shmem.c
    binder/binder.c
    pageowner/page_owner.c
    trace/trace.c
    cpu/cpu.c
    time/time.c
    cmdline/cmd.c)

if (CMAKE_BUILD_TARGET_ARCH STREQUAL "arm64")
add_definitions(-D__LP64__)
list(APPEND LINUX_PARSER_SOURCES
            core/core64.c
            core/core32.c
            core/core_arm64.c
            core/core_arm.c)
elseif(CMAKE_BUILD_TARGET_ARCH STREQUAL "arm")
add_definitions(-D__LP32__)
set(MACHINE_CFLAGS "-m32")
list(APPEND LINUX_PARSER_SOURCES
            core/core32.c
            core/core_arm.c)
elseif(CMAKE_BUILD_TARGET_ARCH STREQUAL "x86_64")
add_definitions(-D__LP64__)
list(APPEND LINUX_PARSER_SOURCES
            core/core64.c
            core/core32.c
            core/core_x86_64.c
            core/core_x86.c)
elseif(CMAKE_BUILD_TARGET_ARCH STREQUAL "x86")
add_definitions(-D__LP32__)
set(MACHINE_CFLAGS "-m32")
list(APPEND LINUX_PARSER_SOURCES
            core/core32.c
            core/core_x86.c)
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${MACHINE_CFLAGS} -rdynamic -Wall")

include_directories(.)
include_directories(lib)

add_library(linux-parser SHARED ${LINUX_PARSER_SOURCES})
set_target_properties(linux-parser PROPERTIES PREFIX "")
