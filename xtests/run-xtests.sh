#!/bin/sh

SRCDIR=$1
shift 1
[ -z "${SRCDIR}" ] && SRCDIR='.'

if test `id -u` -ne 0 ; then
  echo "You need to be root to run the tests"
  exit 1
fi

XTESTS="$@"

failed=0
pass=0
skiped=0
all=0

mkdir -p /etc/security
for config in access.conf group.conf time.conf limits.conf ; do
	cp /etc/security/$config /etc/security/$config-pam-xtests
	install -m 644 "${SRCDIR}"/$config /etc/security/$config
done
mv /etc/security/opasswd /etc/security/opasswd-pam-xtests

for testname in $XTESTS ; do
	  for cfg in "${SRCDIR}"/$testname*.pamd ; do
	    install -m 644 $cfg /etc/pam.d/$(basename $cfg .pamd)
	  done
	  if test -f "${SRCDIR}"/$testname.sh ; then
            test -x "${SRCDIR}"/$testname.sh || chmod 755 "${SRCDIR}"/$testname.sh
            "${SRCDIR}"/$testname.sh > /dev/null
          else
	    ./$testname > /dev/null
	  fi
          RETVAL=$?
          if test $RETVAL -eq 77 ; then
            echo "SKIP: $testname"
            skiped=`expr $skiped + 1`
	  elif test $RETVAL -ne 0 ; then
	    echo "FAIL: $testname"
	    failed=`expr $failed + 1`
          else
	    echo "PASS: $testname"
	    pass=`expr $pass + 1`
          fi
	  all=`expr $all + 1`
	  rm -f /etc/pam.d/$testname*
done
mv /etc/security/access.conf-pam-xtests /etc/security/access.conf
mv /etc/security/group.conf-pam-xtests /etc/security/group.conf
mv /etc/security/time.conf-pam-xtests /etc/security/time.conf
mv /etc/security/limits.conf-pam-xtests /etc/security/limits.conf
mv /etc/security/opasswd-pam-xtests /etc/security/opasswd
if test "$failed" -ne 0; then
	  echo "==================="
	  echo "$failed of $all tests failed"
          echo "$skiped tests not run"
	  echo "==================="
	  exit 1
else
	  echo "=================="
	  echo "$all tests passed"
	  echo "$skiped tests not run"
	  echo "=================="
fi
exit 0
