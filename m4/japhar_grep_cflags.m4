dnl
dnl Test for __attribute__ ((unused))
dnl Based on code from the tcpdump version 3.7.2 source.
dnl

AC_DEFUN([AC_C___ATTRIBUTE__], [
AC_MSG_CHECKING(for __attribute__)
AC_CACHE_VAL(ac_cv___attribute__, [
AC_COMPILE_IFELSE([
AC_LANG_PROGRAM([[
#include <stdlib.h>
static void foo (void) __attribute__ ((unused));

static void
foo (void)
{
  exit(1);
}
]],
[[
  exit (0);
]])],
[ac_cv___attribute__=yes],
[ac_cv___attribute__=no])])
if test "$ac_cv___attribute__" = "yes"; then
  AC_DEFINE(UNUSED, __attribute__ ((unused)), [define if your compiler has __att
ribute__ ((unused))])
else
  AC_DEFINE(UNUSED,,)
fi
AC_MSG_RESULT($ac_cv___attribute__)
])
