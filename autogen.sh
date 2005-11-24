#!/bin/sh -x

aclocal -I m4
autoheader
automake --add-missing --copy
autoreconf
chmod 755 configure
