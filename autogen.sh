#!/bin/sh -x

aclocal -I m4
automake --add-missing --copy
autoreconf
