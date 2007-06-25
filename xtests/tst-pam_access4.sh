#!/bin/bash

/usr/sbin/useradd -p '!!' tstpamaccess
./tst-pam_access4
RET=$?
/usr/sbin/userdel -r tstpamaccess 2> /dev/null
exit $RET
