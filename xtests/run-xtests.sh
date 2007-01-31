#!/bin/bash

if test `id -u` -ne 0 ; then
  echo "You need to be root to run the tests"
  exit 1
fi

XTESTS="$@"

failed=0
pass=0
all=0

for testname in $XTESTS ; do
	  install -m 644 $testname.pamd /etc/pam.d/$testname
	  if test -x ./$testname.sh ; then
            ./$testname.sh > /dev/null
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
