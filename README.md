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
       0x08: filter-sanitizer-shadow-vma
       0x10: filter-non-read-vma
   Example:
       lp core -p 1 --zram --shmem -f 0x1b
```

# Example

```
crash> mod -s zram zram.ko
crash> mod -s zsmalloc zsmalloc.ko

crash> lp core -p 1515 --zram --shmem -f 0x18
Saved [1515.core].
```
