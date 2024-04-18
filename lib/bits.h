// Copyright (C) 2024-present, Guanyou.Chen. All rights reserved.

#ifndef LIB_BITS_H_
#define LIB_BITS_H_

#define BIT(nr)         (1UL << (nr))
#define BIT_ULL(nr)     (1ULL << (nr))

#define PARSER_BITS_PER_LONG (sizeof(long) * 8)
#define BIT_WORD(nr)    ((nr) / PARSER_BITS_PER_LONG)
#define BIT_MASK(nr)    (1UL << ((nr) % PARSER_BITS_PER_LONG))

#define GENMASK(h, l) (((1ULL<<(h+1))-1)&(~((1ULL<<l)-1)))

static inline int _test_bit(unsigned long nr, const volatile unsigned long *addr) {
    return 1UL & (addr[BIT_WORD(nr)] >> (nr & (PARSER_BITS_PER_LONG-1)));
}

static inline int const_test_bit(unsigned long nr, const volatile unsigned long *addr) {
    const unsigned long *p = (const unsigned long *)addr + BIT_WORD(nr);
    unsigned long mask = BIT_MASK(nr);
    unsigned long val = *p;
    return !!(val & mask);
}

#define bitop(op, nr, addr)                     \
    ((__builtin_constant_p(nr) &&                   \
      __builtin_constant_p((uintptr_t)(addr) != (uintptr_t)NULL) && \
      (uintptr_t)(addr) != (uintptr_t)NULL &&           \
      __builtin_constant_p(*(const unsigned long *)(addr))) ?   \
      const##op(nr, addr) : op(nr, addr))

#define test_bit(nr, addr)      bitop(_test_bit, nr, addr)
#define IS_ALIGNED(x, a)        (((x) & ((typeof(x))(a) - 1)) == 0)

static inline unsigned long __ffs(unsigned long word)
{
    int num = 0;

#if defined(X86_64) || defined(ARM64)
    if ((word & 0xffffffff) == 0) {
        num += 32;
        word >>= 32;
    }
#endif
    if ((word & 0xffff) == 0) {
        num += 16;
        word >>= 16;
    }
    if ((word & 0xff) == 0) {
        num += 8;
        word >>= 8;
    }
    if ((word & 0xf) == 0) {
        num += 4;
        word >>= 4;
    }
    if ((word & 0x3) == 0) {
        num += 2;
        word >>= 2;
    }
    if ((word & 0x1) == 0)
        num += 1;
    return num;
}

static inline unsigned long __fls(unsigned long word)
{
    int num = PARSER_BITS_PER_LONG - 1;

#if defined(X86_64) || defined(ARM64)
    if (!(word & (~0ul << 32))) {
        num -= 32;
        word <<= 32;
    }
#endif
    if (!(word & (~0ul << (PARSER_BITS_PER_LONG-16)))) {
        num -= 16;
        word <<= 16;
    }
    if (!(word & (~0ul << (PARSER_BITS_PER_LONG-8)))) {
        num -= 8;
        word <<= 8;
    }
    if (!(word & (~0ul << (PARSER_BITS_PER_LONG-4)))) {
        num -= 4;
        word <<= 4;
    }
    if (!(word & (~0ul << (PARSER_BITS_PER_LONG-2)))) {
        num -= 2;
        word <<= 2;
    }
    if (!(word & (~0ul << (PARSER_BITS_PER_LONG-1))))
        num -= 1;
    return num;
}

#endif // LIB_BITS_H_
