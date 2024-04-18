# Mac 微信多开

自动在 `main` 函数中找到下面的代码

```asm
cmp    QWORD PTR [rbp-0x30],0x2
jb     loc_00000012345678
```

并将 `jb` 修改为 `jmp`


# TLDR
```console
# 查看签名
codesign --display --verbose=4 /Applications/WeChat.app/Contents/MacOS/WeChat

# 改权限
sudo chown -R $(whoami) /Applications/WeChat.app

# 备份
cp /Applications/WeChat.app/Contents/MacOS/WeChat /Applications/WeChat.app/Contents/MacOS/WeChat.bak

# 去除签名
# https://keith.github.io/xcode-man-pages/codesign.1.html
codesign --remove-signature /Applications/WeChat.app/Contents/MacOS/WeChat

cargo install --git https://github.com/hangj/wechat-multi.git
wechat-multi /Applications/WeChat.app/Contents/MacOS/WeChat
echo 'done'
```

================================================================

# 先找到 architecture 的偏移

```console
otool -f /Applications/WeChat.app/Contents/MacOS/WeChat
Fat headers
fat_magic 0xcafebabe
nfat_arch 2
architecture 0
    cputype 16777223
    cpusubtype 3
    capabilities 0x0
    offset 16384
    size 103002112
    align 2^14 (16384)
architecture 1
    cputype 16777228
    cpusubtype 0
    capabilities 0x0
    offset 103022592
    size 88922496
    align 2^14 (16384)

```

第一个 architecture 就是 X86_64, 它的 offset 是 16384


# 找到 X86_64 对应的 MachO Header

```console
xxd -s 16384 -l 32 /Applications/WeChat.app/Contents/MacOS/WeChat
00004000: cffa edfe 0700 0001 0300 0000 0200 0000  ................
00004010: 6b00 0000 d82e 0000 8580 a100 0000 0000  k...............
```

可以看到前 4 个字节就是 `MachO Header` 的 magic number

0x6b 是 number of load commands, 转换成十进制就是 107

# 遍历 load_command 找到 entry_point_command


# 结构体

```c
#define FAT_MAGIC    0xcafebabe
#define FAT_CIGAM    0xbebafeca    /* NXSwapLong(FAT_MAGIC) */

// https://opensource.apple.com/source/xnu/xnu-4570.41.2/EXTERNAL_HEADERS/mach-o/fat.h.auto.html
// big-endian order
struct fat_header {
    uint32_t    magic;        /* FAT_MAGIC */
    uint32_t    nfat_arch;    /* number of structs that follow */
};
// big-endian order
struct fat_arch {
    cpu_type_t    cputype;    /* cpu specifier (int) */
    cpu_subtype_t    cpusubtype;    /* machine specifier (int) */
    uint32_t    offset;        /* file offset to this object file */
    uint32_t    size;        /* size of this object file */
    uint32_t    align;        /* alignment as a power of 2 */
};
// https://opensource.apple.com/source/xnu/xnu-4570.41.2/EXTERNAL_HEADERS/mach-o/loader.h.auto.html
struct mach_header {
    uint32_t    magic;        /* mach magic number identifier 固定的值为 0xfeedface */
    cpu_type_t    cputype;    /* cpu specifier */
    cpu_subtype_t    cpusubtype;    /* machine specifier */
    uint32_t    filetype;    /* type of file */
    uint32_t    ncmds;        /* number of load commands */
    uint32_t    sizeofcmds;    /* the size of all the load commands */
    uint32_t    flags;        /* flags */
};
struct mach_header_64 {
    uint32_t    magic;        /* mach magic number identifier 固定的值为 0xfeedfacf */
    cpu_type_t    cputype;    /* cpu specifier */
    cpu_subtype_t    cpusubtype;    /* machine specifier */
    uint32_t    filetype;    /* type of file */
    uint32_t    ncmds;        /* number of load commands */
    uint32_t    sizeofcmds;    /* the size of all the load commands */
    uint32_t    flags;        /* flags */
    uint32_t    reserved;    /* reserved */
};
struct load_command {
    uint32_t cmd;        /* type of load command */
    uint32_t cmdsize;    /* total size of command in bytes */
    // ...
};
struct entry_point_command {
    uint32_t  cmd;    /* LC_MAIN only used in MH_EXECUTE filetypes 0x80000028 */
    uint32_t  cmdsize;    /* 24 */
    uint64_t  entryoff;    /* file (__TEXT) offset of main() 这个偏移是相对于代码段起始地址的*/
    uint64_t  stacksize;/* if not zero, initial stack size */
};
```


# 参考链接

https://zhuanlan.zhihu.com/p/24858664  

https://opensource.apple.com/source/xnu/xnu-4570.41.2/EXTERNAL_HEADERS/mach-o/fat.h.auto.html

https://defuse.ca/online-x86-assembler.htm

https://shell-storm.org/online/Online-Assembler-and-Disassembler/?arch=arm64