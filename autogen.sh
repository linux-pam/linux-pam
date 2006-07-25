#!/bin/sh -x

aclocal -I m4
autoheader
libtoolize --force --automake --copy
automake --add-missing --copy
autoreconf
chmod 755 configure
