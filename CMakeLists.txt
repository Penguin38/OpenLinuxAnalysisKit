# Copyright (C) 2024-present, Guanyou.Chen. All rights reserved.

cmake_minimum_required(VERSION 3.21.1)
project(OpenLinuxAnalysisKit)

string(TOUPPER "${CMAKE_BUILD_TARGET_ARCH}" BUILD_TARGET_ARCH)
add_definitions(-D${BUILD_TARGET_ARCH})
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -rdynamic -Wall")

include_directories(.)
include_directories(lib)
add_library(linux-parser SHARED
            parser.c
            core/core.c
            core/core32.c
            core/core64.c
            core/core_arm64.c
            core/core_arm.c
            core/core_x86_64.c
            core/core_x86.c
            zram/zram.c
            zram/zram_drv.c
            crypto.c
            lib/lzo/lzo1x_decompress_safe.c)
set_target_properties(linux-parser PROPERTIES PREFIX "")
