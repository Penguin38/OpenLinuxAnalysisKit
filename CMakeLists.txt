# Copyright (C) 2024-present, Guanyou.Chen. All rights reserved.

cmake_minimum_required(VERSION 3.21.1)
project(OpenLinuxAnalysisKit)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -rdynamic -Wall")

include_directories(.)
add_library(linux-parser SHARED
            parser.c
            core/core.c
            core/core32.c
            core/core64.c
            core/core_arm64.c
            core/core_arm.c
            core/core_x86_64.c
            core/core_x86.c)
set_target_properties(linux-parser PROPERTIES PREFIX "")
