// Copyright (C) 2024-present, Guanyou.Chen. All rights reserved.

#ifndef LIB_BITS_H_
#define LIB_BITS_H_

#define BIT(nr)         (1UL << (nr))
#define BIT_ULL(nr)     (1ULL << (nr))

#define BIT_WORD(nr)    ((nr) / BITS_PER_LONG)
#define BIT_MASK(nr)    (1UL << ((nr) % BITS_PER_LONG))

#define GENMASK(h, l) (((1ULL<<(h+1))-1)&(~((1ULL<<l)-1)))

static inline bool _test_bit(unsigned long nr, const volatile unsigned long *addr) {
    return 1UL & (addr[BIT_WORD(nr)] >> (nr & (BITS_PER_LONG-1)));
}

static inline bool const_test_bit(unsigned long nr, const volatile unsigned long *addr) {
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

#endif // LIB_BITS_H_
