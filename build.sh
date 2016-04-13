PLIXER_BASE=~/repos/ipfixify

cd $PLIXER_BASE
mkdir -p bin/CentOS_x86_64
make clean
rm -f bin/CentOS_x86_64/ipfixify.exe
perl Makefile.PL
make
rm version.info
mv -f bin/ipfixify.exe bin/CentOS_x86_64/ipfixify.exe
