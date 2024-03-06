# Copyright (C) 2024-present, Guanyou.Chen. All rights reserved.

cmake -DCMAKE_C_COMPILER="/usr/bin/gcc" \
      -DCMAKE_CXX_COMPILER="/usr/bin/g++" \
      -DCMAKE_BUILD_TYPE="Debug" \
      CMakeLists.txt \
      -B output

make -C output -j8
