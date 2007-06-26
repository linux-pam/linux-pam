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
all=0

mkdir -p /etc/security
cp /etc/security/access.conf /etc/security/access.conf-pam-xtests
install -m 644 "${SRCDIR}"/access.conf /etc/security/access.conf
cp /etc/security/limits.conf /etc/security/limits.conf-pam-xtests
install -m 644 "${SRCDIR}"/limits.conf /etc/security/limits.conf
for testname in $XTESTS ; do
	  install -m 644 "${SRCDIR}"/$testname.pamd /etc/pam.d/$testname
	  if test -x "${SRCDIR}"/$testname.sh ; then
            "${SRCDIR}"/$testname.sh > /dev/null
          else
	    ./$testname > /dev/null
	  fi
	  if test $? -ne 0 ; then
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
mv /etc/security/limits.conf-pam-xtests /etc/security/limits.conf
if test "$failed" -ne 0; then
	  echo "==================="
	  echo "$failed of $all tests failed"
	  echo "==================="
	  exit 1
else
	  echo "=================="
	  echo "All $all tests passed"
	  echo "=================="
fi
exit 0
