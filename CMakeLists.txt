# Copyright (C) 2024-present, Guanyou.Chen. All rights reserved.

cmake_minimum_required(VERSION 3.21.1)
project(OpenLinuxAnalysisKit)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -rdynamic -Wall")

include_directories(.)
add_library(linux-parser SHARED
            parser.c
            core/core.c)
set_target_properties(linux-parser PROPERTIES PREFIX "")
