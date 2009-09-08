#!/bin/sh
# generates the "automake hell"!
#
# 1. delete all auto generated files (or get a fresh working copy from svn)
# 2. run this script

automake --add-missing --copy
echo "automake done!"
(intltoolize --version) < /dev/null > /dev/null 2>&1 || {
    echo;
    echo "You must have intltool installed to compile pidgin-paranoia";
    echo;
    exit;
}
intltoolize --force --copy --automake
echo "intltoolize done!"
libtoolize --force --copy
echo "libtoolize done!"
autoheader
echo "autoheader done!"
aclocal
echo "aclocal done!"
autoconf
echo "autoconf done!"

