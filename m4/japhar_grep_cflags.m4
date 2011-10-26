dnl
dnl JAPHAR_GREP_CFLAGS(flag, cmd_if_missing, cmd_if_present)
dnl
dnl From Japhar.  Report changes to japhar@hungry.com
dnl
AC_DEFUN([JAPHAR_GREP_CFLAGS],
[case "$CFLAGS" in
"$1" | "$1 "* | *" $1" | *" $1 "* )
  ifelse($#, 3, [$3], [:])
  ;;
*)
  $2
  ;;
esac
])

dnl
dnl Test for __attribute__ ((unused))
dnl Based on code from the tcpdump version 3.7.2 source.
dnl

AC_DEFUN([AC_C___ATTRIBUTE__], [
AC_MSG_CHECKING(for __attribute__)
AC_CACHE_VAL(ac_cv___attribute__, [
AC_TRY_COMPILE([
#include <stdlib.h>
static void foo (void) __attribute__ ((unused));

static void
foo (void)
{
  exit(1);
}
],
[
  exit (0);
],
ac_cv___attribute__=yes,
ac_cv___attribute__=no)])
if test "$ac_cv___attribute__" = "yes"; then
  AC_DEFINE(UNUSED, __attribute__ ((unused)), [define if your compiler has __att
ribute__ ((unused))])
else
  AC_DEFINE(UNUSED,,)
fi
AC_MSG_RESULT($ac_cv___attribute__)
])
