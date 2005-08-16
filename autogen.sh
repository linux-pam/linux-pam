#!/bin/sh -x

#aclocal -I m4
aclocal
autoheader
libtoolize --automake --copy
automake --add-missing --copy
autoconf
automake

