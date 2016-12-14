@echo off
del *.obj *.bin *.exe
yasm -fbin -DBIN sx.asm -osx.bin
yasm -fwin32 sx.asm -osx.obj
cl /nologo /DUSE_ASM /O2 /Os /GS- test.c sx.obj
del *.obj