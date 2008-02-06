#!/bin/sh
gcc -Wall -o keygen  keygen.c `pkg-config --cflags glib-2.0 gthread-2.0 gobject-2.0 --libs glib-2.0 gthread-2.0 gobject-2.0`
