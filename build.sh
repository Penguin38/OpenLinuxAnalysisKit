# Copyright (C) 2024-present, Guanyou.Chen. All rights reserved.

cmake -DCMAKE_C_COMPILER="/usr/bin/gcc" \
      -DCMAKE_CXX_COMPILER="/usr/bin/g++" \
      -DCMAKE_BUILD_TYPE="Debug" \
      -DCMAKE_BUILD_TARGET_ARCH="arm64" \
      CMakeLists.txt \
      -B output/arm64

make -C output/arm64 -j8

cmake -DCMAKE_C_COMPILER="/usr/bin/gcc" \
      -DCMAKE_CXX_COMPILER="/usr/bin/g++" \
      -DCMAKE_BUILD_TYPE="Debug" \
      -DCMAKE_BUILD_TARGET_ARCH="x86_64" \
      CMakeLists.txt \
      -B output/x86_64

make -C output/x86_64 -j8
