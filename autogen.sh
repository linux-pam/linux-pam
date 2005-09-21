#!/bin/sh -x

echo "Please look at CHANGELOG" > NEWS
aclocal -I m4
automake --add-missing --copy
autoreconf
