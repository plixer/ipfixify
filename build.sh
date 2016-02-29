PLIXER_BASE=/home/plixer/repos/Plixer

cd $PLIXER_BASE/ipfixify/trunk
svn up --accept theirs-full

make clean
rm -f bin/ipfixify.exe
perl Makefile.PL
make
rm version.info

