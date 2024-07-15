#!/bin/sh

/usr/sbin/useradd -p '!!' tstpamnamespace
./tst-pam_namespace1
RET=$?
/usr/sbin/userdel -r tstpamnamespace 2> /dev/null
exit $RET
