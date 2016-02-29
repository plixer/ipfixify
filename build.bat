@echo off
cd \repos\Plixer\ipfixify\trunk
svn up --accept theirs-full

del bin\ipfixify.exe
dmake clean
makefile.pl
dmake
del version.info
