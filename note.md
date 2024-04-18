
# note
https://defuse.ca/online-x86-assembler.htm


https://shell-storm.org/online/Online-Assembler-and-Disassembler/?arch=arm64

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
```

# opcode

Raw Hex (zero bytes in bold):

48837DD002   

String Literal:

"\x48\x83\x7D\xD0\x02"

Array Literal:

{ 0x48, 0x83, 0x7D, 0xD0, 0x02 }

Disassembly:
0:  48 83 7d d0 02          cmp    QWORD PTR [rbp-0x30],0x2


------

Raw Hex (zero bytes in bold):

E9CF020000

String Literal:

"\xE9\xCF\x02\x00\x00"

Array Literal:

{ 0xE9, 0xCF, 0x02, 0x00, 0x00 }

Disassembly:
0:  e9 cf 02 00 00          jmp    0x2d4


----

Raw Hex (zero bytes in bold):

0F82CE020000

String Literal:

"\x0F\x82\xCE\x02\x00\x00"

Array Literal:

{ 0x0F, 0x82, 0xCE, 0x02, 0x00, 0x00 }

Disassembly:
0:  0f 82 ce 02 00 00       jb     0x2d4



# arm64

```asm
cmp        x21, #0x2
b.lo   loc_1014b2e48
```

B.LO (less than, unsigned)
