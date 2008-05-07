#!/bin/sh
# generates the "automake hell"!
#
# 1. delete all auto generated files (or get a fresh working copy from svn)
# 2. run this script

aclocal
echo "aclocal done!"
libtoolize --copy
echo "libtoolize done!"
autoheader
echo "autoheader done!"
automake --add-missing --copy
echo "automake done!"
autoconf
echo "autoconf done!"
