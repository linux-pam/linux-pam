#!/bin/sh -x

umask 022
touch ChangeLog
autoreconf -fiv
