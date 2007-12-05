/* Copyright © 2007 Red Hat, Inc. All rights reserved.
   Red Hat author: Miloslav Trmač <mitr@redhat.com>

   Redistribution and use in source and binary forms of Linux-PAM, with
   or without modification, are permitted provided that the following
   conditions are met:

   1. Redistributions of source code must retain any existing copyright
      notice, and this entire permission notice in its entirety,
      including the disclaimer of warranties.

   2. Redistributions in binary form must reproduce all prior and current
      copyright notices, this list of conditions, and the following
      disclaimer in the documentation and/or other materials provided
      with the distribution.

   3. The name of any author may not be used to endorse or promote
      products derived from this software without their specific prior
      written permission.

   ALTERNATIVELY, this product may be distributed under the terms of the
   GNU General Public License, in which case the provisions of the GNU
   GPL are required INSTEAD OF the above restrictions.  (This clause is
   necessary due to a potential conflict between the GNU GPL and the
   restrictions contained in a BSD-style copyright.)

   THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
   MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
   IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
   INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
   BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
   OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
   ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
   TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
   USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
   DAMAGE. */

#include <errno.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/socket.h>
#include <unistd.h>

#include <libaudit.h>
#include <linux/netlink.h>

#define PAM_SM_SESSION

#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <security/pam_modutil.h>

#define DATANAME "pam_tty_audit_last_state"

/* Open an audit netlink socket */
static int
nl_open (void)
{
  return socket (AF_NETLINK, SOCK_RAW, NETLINK_AUDIT);
}

static int
nl_send (int fd, unsigned type, unsigned flags, const void *data, size_t size)
{
  struct sockaddr_nl addr;
  struct msghdr msg;
  struct nlmsghdr nlm;
  struct iovec iov[2];
  ssize_t res;

  nlm.nlmsg_len = NLMSG_LENGTH (size);
  nlm.nlmsg_type = type;
  nlm.nlmsg_flags = NLM_F_REQUEST | flags;
  nlm.nlmsg_seq = 0;
  nlm.nlmsg_pid = 0;
  iov[0].iov_base = &nlm;
  iov[0].iov_len = sizeof (nlm);
  iov[1].iov_base = (void *)data;
  iov[1].iov_len = size;
  addr.nl_family = AF_NETLINK;
  addr.nl_pid = 0;
  addr.nl_groups = 0;
  msg.msg_name = &addr;
  msg.msg_namelen = sizeof (addr);
  msg.msg_iov = iov;
  msg.msg_iovlen = 2;
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_flags = 0;
  res = sendmsg (fd, &msg, 0);
  if (res == -1)
    return -1;
  if ((size_t)res != nlm.nlmsg_len)
    {
      errno = EIO;
      return -1;
    }
  return 0;
}

static int
nl_recv (int fd, unsigned type, void *buf, size_t size)
{
  struct sockaddr_nl addr;
  struct msghdr msg;
  struct nlmsghdr nlm;
  struct iovec iov[2];
  ssize_t res;

 again:
  iov[0].iov_base = &nlm;
  iov[0].iov_len = sizeof (nlm);
  msg.msg_name = &addr;
  msg.msg_namelen = sizeof (addr);
  msg.msg_iov = iov;
  msg.msg_iovlen = 1;
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  if (type != NLMSG_ERROR)
    {
      res = recvmsg (fd, &msg, MSG_PEEK);
      if (res == -1)
	return -1;
      if (res != NLMSG_LENGTH (0))
	{
	  errno = EIO;
	  return -1;
	}
      if (nlm.nlmsg_type == NLMSG_ERROR)
	{
	  struct nlmsgerr err;

	  iov[1].iov_base = &err;
	  iov[1].iov_len = sizeof (err);
	  msg.msg_iovlen = 2;
	  res = recvmsg (fd, &msg, 0);
	  if (res == -1)
	    return -1;
	  if ((size_t)res != NLMSG_LENGTH (sizeof (err))
	      || nlm.nlmsg_type != NLMSG_ERROR)
	    {
	      errno = EIO;
	      return -1;
	    }
	  if (err.error == 0)
	    goto again;
	  errno = -err.error;
	  return -1;
	}
    }
  if (size != 0)
    {
      iov[1].iov_base = buf;
      iov[1].iov_len = size;
      msg.msg_iovlen = 2;
    }
  res = recvmsg (fd, &msg, 0);
  if (res == -1)
    return -1;
  if ((size_t)res != NLMSG_LENGTH (size)
      || nlm.nlmsg_type != type)
    {
      errno = EIO;
      return -1;
    }
  return 0;
}

static int
nl_recv_ack (int fd)
{
  struct nlmsgerr err;

  if (nl_recv (fd, NLMSG_ERROR, &err, sizeof (err)) != 0)
    return -1;
  if (err.error != 0)
    {
      errno = -err.error;
      return -1;
    }
  return 0;
}

static void
cleanup_old_status (pam_handle_t *pamh, void *data, int error_status)
{
  (void)pamh;
  (void)error_status;
  free (data);
}

int
pam_sm_open_session (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  enum command { CMD_NONE, CMD_ENABLE, CMD_DISABLE };

  enum command command;
  struct audit_tty_status *old_status, new_status;
  const char *user;
  uid_t user_uid;
  struct passwd *pwd;
  int i, fd;

  (void)flags;

  if (pam_get_user (pamh, &user, NULL) != PAM_SUCCESS)
    {
      pam_syslog (pamh, LOG_ERR, "error determining target user's name");
      return PAM_SESSION_ERR;
    }
  pwd = pam_modutil_getpwnam (pamh, user);
  if (pwd == NULL)
    {
      pam_syslog (pamh, LOG_ERR, "error determining target user's UID: %m");
      return PAM_SESSION_ERR;
    }
  user_uid = pwd->pw_uid;

  command = CMD_NONE;
  for (i = 0; i < argc; i++)
    {
      if (strncmp (argv[i], "enable=", 7) == 0
	  || strncmp (argv[i], "disable=", 8) == 0)
	{
	  enum command this_command;
	  char *copy, *tok_data, *tok;

	  this_command = *argv[i] == 'e' ? CMD_ENABLE : CMD_DISABLE;
	  copy = strdup (strchr (argv[i], '=') + 1);
	  if (copy == NULL)
	    return PAM_SESSION_ERR;
	  for (tok = strtok_r (copy, ",", &tok_data); tok != NULL;
	       tok = strtok_r (NULL, ",", &tok_data))
	    {
	      pwd = pam_modutil_getpwnam (pamh, tok);
	      if (pwd == NULL)
		{
		  pam_syslog (pamh, LOG_WARNING, "unknown user %s", tok);
		  continue;
		}
	      if (pwd->pw_uid == user_uid)
		{
		  command = this_command;
		  break;
		}
	    }
	  free (copy);
	}
    }
  if (command == CMD_NONE)
    return PAM_SUCCESS;

  old_status = malloc (sizeof (*old_status));
  if (old_status == NULL)
    return PAM_SESSION_ERR;

  fd = nl_open ();
  if (fd == -1
      || nl_send (fd, AUDIT_TTY_GET, 0, NULL, 0) != 0
      || nl_recv (fd, AUDIT_TTY_GET, old_status, sizeof (*old_status)) != 0)
    {
      pam_syslog (pamh, LOG_ERR, "error reading current audit status: %m");
      if (fd != -1)
	close (fd);
      free (old_status);
      return PAM_SESSION_ERR;
    }

  if (old_status->enabled == (command == CMD_ENABLE ? 1 : 0))
    {
      free (old_status);
      goto ok_fd;
    }

  if (pam_set_data (pamh, DATANAME, old_status, cleanup_old_status)
      != PAM_SUCCESS)
    {
      pam_syslog (pamh, LOG_ERR, "error saving old audit status");
      close (fd);
      free (old_status);
      return PAM_SESSION_ERR;
    }

  new_status.enabled = (command == CMD_ENABLE ? 1 : 0);
  if (nl_send (fd, AUDIT_TTY_SET, NLM_F_ACK, &new_status,
	       sizeof (new_status)) != 0
      || nl_recv_ack (fd) != 0)
    {
      pam_syslog (pamh, LOG_ERR, "error setting current audit status: %m");
      close (fd);
      return PAM_SESSION_ERR;
    }
  /* Fall through */
 ok_fd:
  close (fd);
  pam_syslog (pamh, LOG_DEBUG, "changed status from %d to %d",
	      old_status->enabled, new_status.enabled);
  return PAM_SUCCESS;
}

int
pam_sm_close_session (pam_handle_t *pamh, int flags, int argc,
		      const char **argv)
{
  const void *status_;

  (void)flags;
  (void)argc;
  (void)argv;
  if (pam_get_data (pamh, DATANAME, &status_) == PAM_SUCCESS)
    {
      const struct audit_tty_status *status;
      int fd;

      status = status_;

      fd = nl_open ();
      if (fd == -1
	  || nl_send (fd, AUDIT_TTY_SET, NLM_F_ACK, status,
		      sizeof (*status)) != 0
	  || nl_recv_ack (fd) != 0)
	{
	  pam_syslog (pamh, LOG_ERR, "error restoring audit status: %m");
	  if (fd != -1)
	    close (fd);
	  return PAM_SESSION_ERR;
	}
      close (fd);
      pam_syslog (pamh, LOG_ERR, "restored status to %d", status->enabled);
    }
  return PAM_SUCCESS;
}

/* static module data */
#ifdef PAM_STATIC
struct pam_module _pam_tty_audit_modstruct = {
  "pam_tty_audit",
  NULL,
  NULL,
  NULL,
  pam_sm_open_session,
  pam_sm_close_session,
  NULL
};
#endif
