#!/bin/bash
# Help: http://www.network-theory.co.uk/docs/gccintro/gccintro_11.html
# Help: http://developer.gnome.org/doc/API/2.0/glib/glib-compiling.html
# '-lm' is for math.h
echo "gcc -lm -Wall `pkg-config --cflags --libs glib-2.0` otptester.c libotp.c -o otptester"
gcc -lm -Wall `pkg-config --cflags --libs glib-2.0` otptester.c libotp.c -o otptester
