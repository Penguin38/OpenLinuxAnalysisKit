# Copyright (C) 2024-present, Guanyou.Chen. All rights reserved.

export BUILD_TARGET_ABIS="arm64 x86_64"
if [ -z $BUILD_TYPE ];then
    export BUILD_TYPE="Debug"
fi

for CURRENT_TARGET_ABI in $BUILD_TARGET_ABIS
do
cmake -DCMAKE_C_COMPILER="/usr/bin/gcc" \
      -DCMAKE_CXX_COMPILER="/usr/bin/g++" \
      -DCMAKE_BUILD_TYPE=$BUILD_TYPE \
      -DCMAKE_BUILD_TARGET_ARCH=$CURRENT_TARGET_ABI \
      CMakeLists.txt \
      -B output/$CURRENT_TARGET_ABI

make -C output/$CURRENT_TARGET_ABI -j8
done
