@echo off
mkdir bin
del bin\ipfixify.exe
dmake clean
makefile.pl
dmake
del version.info
