#!/bin/sh
list=`/bin/ls /lib/libnsl.so.* 2> /dev/null`
if [ -z "$list" ]; then
   echo no
else
   echo yes
fi
