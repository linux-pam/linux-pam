dnl PAM_CACHE_LOAD()
dnl Load the specified variable from the toplevel PAM config.cache, and
dnl call AC_SUBST

AC_DEFUN(PAM_CACHE_LOAD,
[ifelse([$2], , $1=$ac_cv_pam_[$1], $1=$ac_cv_[$2]) AC_SUBST($1)])

dnl PAM_CACHE_SAVE()
dnl Save the specified variable to the config.cache and call AC_SUBST

AC_DEFUN(PAM_CACHE_SAVE,
[ac_cv_pam_$1=$$1 AC_SUBST($1)])
