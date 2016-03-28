PLIXER_BASE=~/repos/ipfixify

cd $PLIXER_BASE/ipfixify/trunk
mkdir -p bin/
make clean
rm -f bin/ipfixify.exe
perl Makefile.PL
make
rm version.info

