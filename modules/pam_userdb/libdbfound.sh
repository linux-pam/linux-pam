#!/bin/sh

if [ -f "/usr/include/ndbm.h" ]; then
    echo "-DUSE_NDBM_H"
    exit 0
fi

list=`/bin/ls /lib/libdb.so.* 2> /dev/null`
if [ -n "$list" ]; then
    echo ""
    exit 0
fi

echo "none"
exit 0
