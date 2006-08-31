# ld-as-needed.m4 serial 2

# Test if ld supports --as-needed

AC_DEFUN([PAM_LD_AS_NEEDED],
  [
    AC_CACHE_CHECK(whether ld supports --as-needed,
      pam_cv_ld_as_needed, [ dnl
    cat > conftest.c <<EOF
int main (void) { return 0; }
EOF
     if AC_TRY_COMMAND([${CC-cc} $CFLAGS $CPPFLAGS $LDFLAGS
                                 -o conftest.o conftest.c
                                 -Wl,--as-needed 1>&AS_MESSAGE_LOG_FD])
  then
    pam_cv_ld_as_needed=yes
    LDFLAGS="$LDFLAGS -Wl,--as-needed"
  else
    pam_cv_ld_as_needed=no
  fi
  rm -f conftest*])
  AC_SUBST(pam_cv_ld_as_needed)
  ]
)
