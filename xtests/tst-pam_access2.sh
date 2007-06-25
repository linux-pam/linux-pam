#!/bin/bash

/usr/sbin/groupadd -p '!!' tstpamaccess
/usr/sbin/useradd -p '!!' tstpamaccess
./tst-pam_access2
RET=$?
/usr/sbin/userdel -r tstpamaccess 2> /dev/null
/usr/sbin/groupdel tstpamaccess 2> /dev/null
exit $RET
