#!/bin/bash
export LD_PRELOAD=../libpam/libpam.so:../libpam_misc/libpam_misc.so
ldd ./xsh
./xsh "$@"

