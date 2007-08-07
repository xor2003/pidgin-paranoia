#!/bin/bash

# Help: http://www.network-theory.co.uk/docs/gccintro/gccintro_11.html
echo "gcc -Wall otptester.c libotp.c -o otptester"
gcc -Wall otptester.c libotp.c -o otptester
