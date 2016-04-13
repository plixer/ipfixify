@echo off
del bin\Win64\ipfixify.exe
dmake clean
makefile.pl
dmake
del version.info
move bin\ipfixify.exe bin\Win64\ipfixify.exe
