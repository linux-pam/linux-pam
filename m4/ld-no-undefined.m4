# ld-no-undefined.m4 serial 1

# Test if ld supports --no-undefined

AC_DEFUN([PAM_LD_NO_UNDEFINED],
  [
    AC_CACHE_CHECK(whether ld supports --no-undefined,
      pam_cv_ld_no_undefined, [ dnl
    cat > conftest.c <<EOF
int main (void) { return 0; }
EOF
     if AC_TRY_COMMAND([${CC-cc} $CFLAGS $CPPFLAGS $LDFLAGS
                                 -o conftest.o conftest.c
                                 -Wl,--no-undefined 1>&AS_MESSAGE_LOG_FD])
  then
    pam_cv_ld_no_undefined=yes
    LDFLAGS="$LDFLAGS -Wl,--no-undefined"
  else
    pam_cv_ld_no_undefined=no
  fi
  rm -f conftest*])
  AC_SUBST(pam_cv_ld_no_undefined)
  ]
)
