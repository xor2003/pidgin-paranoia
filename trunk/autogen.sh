#!/bin/sh
# generates the "automake hell"!
#
# 1. delete all auto generated files (or get a fresh working copy from svn)
# 2. run this script

(intltoolize --version) < /dev/null > /dev/null 2>&1 || {
    echo;
    echo "You must have intltool installed to compile pidgin-paranoia";
    echo;
    exit;
}
intltoolize --force --copy
echo "intltoolize done!"
aclocal
echo "aclocal done!"
libtoolize --force --copy
echo "libtoolize done!"
autoheader
echo "autoheader done!"
automake --add-missing --copy
echo "automake done!"
autoconf
echo "autoconf done!"

