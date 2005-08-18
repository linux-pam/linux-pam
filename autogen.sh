#!/bin/sh -x

echo "Please look at CHANGELOG" > NEWS
touch AUTHORS
echo "Please look at CHANGELOG" > ChangeLog
automake --add-missing --copy
autoreconf
