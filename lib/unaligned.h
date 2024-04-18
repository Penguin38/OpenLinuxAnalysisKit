// Copyright (C) 2024-present, Guanyou.Chen. All rights reserved.

#ifndef LIB_UNALIGNED_H_
#define LIB_UNALIGNED_H_

#include "le_byteshift.h"
#include "be_byteshift.h"

#if defined(__LITTLE_ENDIAN)
#define get_unaligned_8 get_unaligned_le8
#define put_unaligned_8 put_unaligned_le8
#define get_unaligned_16 get_unaligned_le16
#define put_unaligned_16 put_unaligned_le16
#define get_unaligned_32 get_unaligned_le32
#define put_unaligned_32 put_unaligned_le32
#define get_unaligned_64 get_unaligned_le64
#define put_unaligned_64 put_unaligned_le64
#else
#define get_unaligned_8 get_unaligned_be8
#define put_unaligned_8 put_unaligned_be8
#define get_unaligned_16 get_unaligned_be16
#define put_unaligned_16 put_unaligned_be16
#define get_unaligned_32 get_unaligned_be32
#define put_unaligned_32 put_unaligned_be32
#define get_unaligned_64 get_unaligned_be64
#define put_unaligned_64 put_unaligned_be64
#endif

#endif // LIB_UNALIGNED_H_
