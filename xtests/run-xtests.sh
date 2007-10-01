#!/bin/bash

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
cp /etc/security/access.conf /etc/security/access.conf-pam-xtests
install -m 644 "${SRCDIR}"/access.conf /etc/security/access.conf
cp /etc/security/group.conf /etc/security/group.conf-pam-xtests
install -m 644 "${SRCDIR}"/group.conf /etc/security/group.conf
cp /etc/security/limits.conf /etc/security/limits.conf-pam-xtests
install -m 644 "${SRCDIR}"/limits.conf /etc/security/limits.conf
for testname in $XTESTS ; do
	  install -m 644 "${SRCDIR}"/$testname.pamd /etc/pam.d/$testname
	  if test -x "${SRCDIR}"/$testname.sh ; then
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
	  rm -f /etc/pam.d/$testname
done
mv /etc/security/access.conf-pam-xtests /etc/security/access.conf
mv /etc/security/group.conf-pam-xtests /etc/security/group.conf
mv /etc/security/limits.conf-pam-xtests /etc/security/limits.conf
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
