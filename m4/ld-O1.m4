# ld-O1.m4 serial 3

# Test if ld supports -O1

AC_DEFUN([PAM_LD_O1],
  [
    AC_CACHE_CHECK(whether ld supports -O1,
      pam_cv_ld_O1, [ dnl
    cat > conftest.c <<EOF
int main (void) { return 0; }
EOF
     if AC_TRY_COMMAND([${CC-cc} $CFLAGS $CPPFLAGS $LDFLAGS
                                 -o conftest.o conftest.c
                                 -Wl,-O1 1>&AS_MESSAGE_LOG_FD])
  then
    pam_cv_ld_O1=yes
    LDFLAGS="$LDFLAGS -Wl,-O1"
  else
    pam_cv_ld_O1=no
  fi
  rm -f conftest*])
  AC_SUBST(pam_cv_ld_O1)
  ]
)
