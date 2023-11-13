#!/bin/sh -ex
#
# Copyright (c) 2018-2019 The strace developers.
# All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-or-later

DISTCHECK_CONFIGURE_FLAGS='--disable-dependency-tracking --enable-Werror --enable-lastlog'
export DISTCHECK_CONFIGURE_FLAGS

case "${TARGET-}" in
	x32)
		CC="$CC -mx32"
		;;
	x86)
		CC="$CC -m32"
		DISTCHECK_CONFIGURE_FLAGS="$DISTCHECK_CONFIGURE_FLAGS --build=i686-pc-linux-gnu --target=i686-pc-linux-gnu"
		;;
esac

CPPFLAGS=

case "${CHECK-}" in
	coverage)
		DISTCHECK_CONFIGURE_FLAGS="$DISTCHECK_CONFIGURE_FLAGS --enable-code-coverage"
		CFLAGS='-g -O0'
		CFLAGS_FOR_BUILD="$CFLAGS"
		export CFLAGS CFLAGS_FOR_BUILD
		;;
	valgrind)
		DISTCHECK_CONFIGURE_FLAGS="$DISTCHECK_CONFIGURE_FLAGS --enable-valgrind"
		;;
esac

case "${VENDORDIR-}" in
	*/*)
		DISTCHECK_CONFIGURE_FLAGS="$DISTCHECK_CONFIGURE_FLAGS --enable-vendordir=$VENDORDIR"
		;;
esac

case "${USE_OPENSSL-}" in
	yes)
		DISTCHECK_CONFIGURE_FLAGS="$DISTCHECK_CONFIGURE_FLAGS --enable-openssl"
		;;
esac

case "${ENABLE_DEBUG-}" in
	yes)
		DISTCHECK_CONFIGURE_FLAGS="$DISTCHECK_CONFIGURE_FLAGS --enable-debug"
		;;
esac

echo 'BEGIN OF BUILD ENVIRONMENT INFORMATION'
uname -a |head -1
libc="$(ldd /bin/sh |sed -n 's|^[^/]*\(/[^ ]*/libc\.so[^ ]*\).*|\1|p' |head -1)"
$libc |head -1
$CC --version |head -1
make --version |head -1
autoconf --version |head -1
automake --version |head -1
libtoolize --version |head -1
kver="$(printf '%s\n%s\n' '#include <linux/version.h>' 'LINUX_VERSION_CODE' | $CC $CPPFLAGS -E -P -)"
printf 'kernel-headers %s.%s.%s\n' $((kver/65536)) $((kver/256%256)) $((kver%256))
echo 'END OF BUILD ENVIRONMENT INFORMATION'

export CC_FOR_BUILD="$CC"

./autogen.sh
./configure $DISTCHECK_CONFIGURE_FLAGS \
	|| {
	rc=$?
	cat config.log
	echo "$CC -dumpspecs follows"
	$CC -dumpspecs
	exit $rc
}

j=-j`nproc` || j=

case "${CHECK-}" in
	coverage)
		make -k $j all VERBOSE=${VERBOSE-}
		make -k $j check VERBOSE=${VERBOSE-}
		codecov --gcov-args=-abcp ||:
		echo 'BEGIN OF TEST SUITE INFORMATION'
		tail -n 99999 -- tests*/test-suite.log
		echo 'END OF TEST SUITE INFORMATION'
		;;
	valgrind)
		make -k $j all VERBOSE=${VERBOSE-}
		rc=$?
		for n in ${VALGRIND_TOOLS:-memcheck helgrind drd}; do
			make -k $j -C "${VALGRIND_TESTDIR:-.}" \
				check-valgrind-$n VERBOSE=${VERBOSE-} ||
					rc=$?
		done
		echo 'BEGIN OF TEST SUITE INFORMATION'
		tail -n 99999 -- tests*/test-suite*.log ||
			rc=$?
		echo 'END OF TEST SUITE INFORMATION'
		[ "$rc" -eq 0 ]
		;;
	*)
		make -k $j distcheck VERBOSE=${VERBOSE-}
		;;
esac

if git status --porcelain |grep '^?'; then
	echo >&2 'git status reported untracked files'
	exit 1
fi
