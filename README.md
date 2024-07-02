# Getting Started

```
$ ./build.sh
```

To load the module's commands to a running crash-8.0.4+ session, enter:

```
crash> extend <path-to>/output/arm64/linux-parser.so
```
To show the module's commands, enter:

```
crash> extend
SHARED OBJECT                           COMMANDS
<path-to>/output/arm64/linux-parser.so  lp
```

# Usage

```
crash> lp help
core        zram        shmem       binder
meminfo     page_owner  dmabuf      help

crash> lp help core
Usage: core -p <PID> [--output|-o <FILE_PATH>] [option]
   Option:
       --zram: decompress zram page
       --shmem: decompress shared memory on zram page
       --filter|-f: filter vma flags
   Filter Vma:
       0x01: filter-special-vma
       0x02: filter-file-vma
       0x04: filter-shared-vma
       0x08: filter-sanitizer-shadow-vma (default)
       0x10: filter-non-read-vma (default)
   Example:
       lp core -p 1 --zram --shmem -f 0x18
```

# Example

```
crash> mod -s zram zram.ko
crash> mod -s zsmalloc zsmalloc.ko

crash> lp core -p 1515 --zram --shmem -f 0x18
Saved [1515.core].
```

```
crash> vtop 0x12c00100
VIRTUAL     PHYSICAL
12c00100    (not mapped)

PAGE DIRECTORY: ffffff8160232000
   PGD: ffffff8160232000 => 8000001a0233003
   PMD: ffffff81602334b0 => 8000001a0234003
   PTE: ffffff8160234000 => 112a1700

  PTE                     SWAP                  OFFSET
112a1700  /first_stage_ramdisk/dev/block/zram0  1124887

      VMA           START       END     FLAGS FILE
ffffff8160c68e80   12c00000   32c00000 100073

SWAP: /first_stage_ramdisk/dev/block/zram0  OFFSET: 1124887

crash> lp zram -r 0x12c00100 -e 0x12c00200
        12c00100:  0000000000000000 0000000000000000  ................
        12c00110:  0000000000000000 0000000000000000  ................
        12c00120:  0000000000000000 00000000705f0f78  ........x._p....
        12c00130:  0000000000000046 72756f7365722041  F.......A.resour
        12c00140:  656c696166206563 6c6163206f742064  ce.failed.to.cal
        12c00150:  7361656c6572206c 0000000000202e65  l.release.......
        12c00160:  0000000070615c70 0000002312c001f0  p\ap........#...
        12c00170:  00000000705d10a0 0000000000000010  ..]p............
        12c00180:  0000000000000000 0000000000000000  ................
        12c00190:  0000000000000000 0000000000000000  ................
        12c001a0:  00000000705d10a0 0020004100000022  ..]p...."...A...
        12c001b0:  006f007300650072 0065006300720075  r.e.s.o.u.r.c.e.
        12c001c0:  0069006100660020 002000640065006c  ..f.a.i.l.e.d...
        12c001d0:  00630020006f0074 0020006c006c0061  t.o...c.a.l.l...
        12c001e0:  0065006c00650072 0000006500730061  r.e.l.e.a.s.e...
        12c001f0:  00000000705d10a0 0020004100000046  ..]p....F...A...
```

```
crash> vtop 98be9000
VIRTUAL     PHYSICAL
98be9000    (not mapped)

PAGE DIRECTORY: ffffff8160232000
   PGD: ffffff8160232010 => 8000001a1586003
   PMD: ffffff8161586628 => 800000154766003
   PTE: ffffff8114766f48 => 0

      VMA           START       END     FLAGS FILE
ffffff8161ccbed0   98be9000   9abe9000 2000000dd memfd:jit-zygote-cache

FILE: memfd:jit-zygote-cache  OFFSET: 2000000

crash> lp shmem -r 98be9000 -e 98be9100
        98be9000:  0000000000000000 00000000000003b3  ................
        98be9010:  0000000000000000 0000000000000000  ................
        98be9020:  0000000000002bd0 000000741ec00000  .+..........t...
        98be9030:  0000000000000000 000000741ec053e0  .........S..t...
        98be9040:  0000000000200000 ffffffffffffffff  ................
        98be9050:  0000000031dcfbb8 0000000000000000  ...1............
        98be9060:  0000000000000000 000000741ec00058  ........X...t...
        98be9070:  000000741ec00058 000000741ec00068  X...t...h...t...
        98be9080:  000000741ec00068 000000741ec00078  h...t...x...t...
        98be9090:  000000741ec00078 000000741ec00088  x...t.......t...
        98be90a0:  000000741ec00088 000000741ec00098  ....t.......t...
        98be90b0:  000000741ec00098 000000741ec000a8  ....t.......t...
        98be90c0:  000000741ec000a8 000000741ec000b8  ....t.......t...
        98be90d0:  000000741ec000b8 000000741ec000c8  ....t.......t...
        98be90e0:  000000741ec000c8 000000741ec000d8  ....t.......t...
        98be90f0:  000000741ec000d8 000000741ec000e8  ....t.......t...
```

```
crash> lp binder -a | grep outgoing
    outgoing transaction 363543018: 0xffffff8170b4a000 from 7417:7417 to 1709:1728 code 18 flags 12 pri SCHED_NORMAL:120 r1
    outgoing transaction 363543023: 0xffffff806b8a9c00 from 7335:7335 to 1709:2599 code 28 flags 12 pri SCHED_NORMAL:120 r1
    outgoing transaction 363542714: 0xffffff8196ae6400 from 7310:7310 to 1709:3784 code 17 flags 12 pri SCHED_NORMAL:120 r1
    outgoing transaction 363538861: 0xffffff808380de00 from 7203:7203 to 1709:3251 code 6 flags 12 pri SCHED_NORMAL:120 r1
    outgoing transaction 363542702: 0xffffff80f6931c00 from 6948:7200 to 1709:2793 code 6b flags 12 pri SCHED_NORMAL:120 r1
    outgoing transaction 363542574: 0xffffff80f6931500 from 6948:7381 to 1709:3250 code d flags 12 pri SCHED_NORMAL:120 r1
    outgoing transaction 363542463: 0xffffff81439d9d00 from 6948:7456 to 1709:15269 code 6 flags 12 pri SCHED_NORMAL:120 r1
    outgoing transaction 363542516: 0xffffff8092d63900 from 6909:7330 to 1709:2794 code 1e flags 12 pri SCHED_NORMAL:139 r1
```
