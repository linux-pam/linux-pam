/* pam_audit.c -- Instrumentation code for Linux Auditing System  */

/* (C) 2005-2006 Red Hat, Inc. -- Licensing details are in the COPYING
   file accompanying the Linux-PAM source distribution.

   Authors:
   Steve Grubb <sgrubb@redhat.com> */

#include <stdio.h>
#include <syslog.h>
#include "pam_private.h"
#include "pam_modutil_private.h"

#ifdef HAVE_LIBAUDIT
#include <libaudit.h>
#include <pwd.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>

#define PAMAUDIT_LOGGED 1

static int
_pam_audit_writelog(pam_handle_t *pamh, int audit_fd, int type,
	const char *message, int retval)
{
  static int old_errno = -1;
  int rc;
  char buf[32];

  snprintf(buf, sizeof(buf), "PAM:%s", message);

  rc = audit_log_acct_message (audit_fd, type, NULL, buf,
       (retval != PAM_USER_UNKNOWN && pamh->user) ? pamh->user : "?",
	-1, pamh->rhost, NULL, pamh->tty, retval == PAM_SUCCESS );

  /* libaudit sets errno to his own negative error code. This can be
     an official errno number, but must not. It can also be a audit
     internal error code. Which makes errno useless :-((. Try the
     best to fix it. */
  errno = -rc;

  pamh->audit_state |= PAMAUDIT_LOGGED;

  if (rc < 0) {
      if (rc == -EPERM && getuid() != 0)
          return 0;
      if (errno != old_errno) {
          old_errno = errno;
          pam_syslog (pamh, LOG_CRIT, "audit_log_acct_message() failed: %m");
      }
  }
  return rc;
}

static int
_pam_audit_open(pam_handle_t *pamh)
{
  int audit_fd;
  audit_fd = audit_open();
  if (audit_fd < 0) {
    /* You get these error codes only when the kernel doesn't have
     * audit compiled in. */
    if (errno == EINVAL || errno == EPROTONOSUPPORT ||
        errno == EAFNOSUPPORT)
        return -2;

    /* this should only fail in case of extreme resource shortage,
     * need to prevent login in that case for CAPP compliance.
     */
    pam_syslog(pamh, LOG_CRIT, "audit_open() failed: %m");
    return -1;
  }

  return audit_fd;
}

int
_pam_auditlog(pam_handle_t *pamh, int action, int retval, int flags)
{
  const char *message;
  int type;
  int audit_fd;

  if ((audit_fd=_pam_audit_open(pamh)) == -1) {
    return PAM_SYSTEM_ERR;
  } else if (audit_fd == -2) {
    return retval;
  }

  switch (action) {
  case PAM_AUTHENTICATE:
    message = "authentication";
    type = AUDIT_USER_AUTH;
    break;
  case PAM_OPEN_SESSION:
    message = "session_open";
    type = AUDIT_USER_START;
    break;
  case PAM_CLOSE_SESSION:
    message = "session_close";
    type = AUDIT_USER_END;
    break;
  case PAM_ACCOUNT:
    message = "accounting";
    type = AUDIT_USER_ACCT;
    break;
  case PAM_CHAUTHTOK:
    message = "chauthtok";
    type = AUDIT_USER_CHAUTHTOK;
    break;
  case PAM_SETCRED:
    message = "setcred";
    if (flags & PAM_ESTABLISH_CRED)
	type = AUDIT_CRED_ACQ;
    else if ((flags & PAM_REINITIALIZE_CRED) || (flags & PAM_REFRESH_CRED))
	type = AUDIT_CRED_REFR;
    else if (flags & PAM_DELETE_CRED)
	type = AUDIT_CRED_DISP;
    else
        type = AUDIT_USER_ERR;
    break;
  case _PAM_ACTION_DONE:
    message = "bad_ident";
    type = AUDIT_USER_ERR;
    break;
  default:
    message = "UNKNOWN";
    type = AUDIT_USER_ERR;
    pam_syslog(pamh, LOG_CRIT, "_pam_auditlog() should never get here");
    retval = PAM_SYSTEM_ERR;
  }

  if (_pam_audit_writelog(pamh, audit_fd, type, message, retval) < 0)
    retval = PAM_SYSTEM_ERR;

  audit_close(audit_fd);
  return retval;
}

int
_pam_audit_end(pam_handle_t *pamh, int status UNUSED)
{
  if (! (pamh->audit_state & PAMAUDIT_LOGGED)) {
    /* PAM library is being shut down without any of the auditted
     * stacks having been run. Assume that this is sshd faking
     * things for an unknown user.
     */
    _pam_auditlog(pamh, _PAM_ACTION_DONE, PAM_USER_UNKNOWN, 0);
  }

  return 0;
}

int
pam_modutil_audit_write(pam_handle_t *pamh, int type,
    const char *message, int retval)
{
  int audit_fd;
  int rc;

  if ((audit_fd=_pam_audit_open(pamh)) == -1) {
    return PAM_SYSTEM_ERR;
  } else if (audit_fd == -2) {
    return retval;
  }

  rc = _pam_audit_writelog(pamh, audit_fd, type, message, retval);

  audit_close(audit_fd);

  return rc < 0 ? PAM_SYSTEM_ERR : PAM_SUCCESS;
}

#else
int pam_modutil_audit_write(pam_handle_t *pamh UNUSED, int type UNUSED,
    const char *message UNUSED, int retval UNUSED)
{
  return PAM_SUCCESS;
}
#endif /* HAVE_LIBAUDIT */
