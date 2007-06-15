/******************************************************************************
 * A module for Linux-PAM that will set the default security context after login
 * via PAM.
 *
 * Copyright (c) 2003 Red Hat, Inc.
 * Written by Dan Walsh <dwalsh@redhat.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "config.h"

#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>

#define PAM_SM_AUTH
#define PAM_SM_SESSION

#include <security/pam_modules.h>
#include <security/_pam_macros.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>

#include <selinux/selinux.h>
#include <selinux/get_context_list.h>
#include <selinux/flask.h>
#include <selinux/av_permissions.h>
#include <selinux/selinux.h>
#include <selinux/context.h>
#include <selinux/get_default_type.h>

#ifdef HAVE_LIBAUDIT
#include <libaudit.h>
#include <sys/select.h>
#include <errno.h>
#endif

/* Send audit message */
static

int send_audit_message(pam_handle_t *pamh, int success, security_context_t default_context,
		       security_context_t selected_context)
{
	int rc=0;
#ifdef HAVE_LIBAUDIT
	char *msg = NULL;
	int audit_fd = audit_open();
	security_context_t default_raw=NULL;
	security_context_t selected_raw=NULL;
	rc = -1;
	if (audit_fd < 0) {
		if (errno == EINVAL || errno == EPROTONOSUPPORT ||
                                        errno == EAFNOSUPPORT)
                        return 0; /* No audit support in kernel */
		pam_syslog(pamh, LOG_ERR, _("Error connecting to audit system."));
		return rc;
	}
	if (selinux_trans_to_raw_context(default_context, &default_raw) < 0) {
		pam_syslog(pamh, LOG_ERR, _("Error translating default context."));
		default_raw = NULL;
	}
	if (selinux_trans_to_raw_context(selected_context, &selected_raw) < 0) {
		pam_syslog(pamh, LOG_ERR, _("Error translating selected context."));
		selected_raw = NULL;
	}
	if (asprintf(&msg, "pam: default-context=%s selected-context=%s",
		     default_raw ? default_raw : (default_context ? default_context : "?"),
		     selected_raw ? selected_raw : (selected_context ? selected_context : "?")) < 0) {
		pam_syslog(pamh, LOG_ERR, ("Error allocating memory."));
		goto out;
	}
	if (audit_log_user_message(audit_fd, AUDIT_USER_ROLE_CHANGE,
				   msg, NULL, NULL, NULL, success) <= 0) {
		pam_syslog(pamh, LOG_ERR, _("Error sending audit message."));
		goto out;
	}
	rc = 0;
      out:
	free(msg);
	freecon(default_raw);
	freecon(selected_raw);
	close(audit_fd);
#else
	pam_syslog(pamh, LOG_NOTICE, "pam: default-context=%s selected-context=%s success %d", default_context, selected_context, success);
#endif
	return rc;
}
static int
send_text (pam_handle_t *pamh, const char *text, int debug)
{
  if (debug)
    pam_syslog(pamh, LOG_NOTICE, "%s", text);
  return pam_info (pamh, "%s", text);
}

/*
 * This function sends a message to the user and gets the response. The caller
 * is responsible for freeing the responses.
 */
static int
query_response (pam_handle_t *pamh, const char *text, const char *def,
		char **responses, int debug)
{
  int rc;
  if (def) 
    rc = pam_prompt (pamh, PAM_PROMPT_ECHO_ON, responses, "%s [%s] ", text, def);
  else
    rc = pam_prompt (pamh, PAM_PROMPT_ECHO_ON, responses, "%s ", text);
  if (debug)
    pam_syslog(pamh, LOG_NOTICE, "%s %s", text, responses[0]);
  return rc;
}

static security_context_t
manual_context (pam_handle_t *pamh, const char *user, int debug)
{
  security_context_t newcon=NULL;
  context_t new_context;
  int mls_enabled = is_selinux_mls_enabled();
  char *type=NULL;
  char *responses=NULL;

  while (1) {
    query_response(pamh,
		   _("Would you like to enter a security context? [N] "), NULL, 
		   &responses,debug);
    if ((responses[0] == 'y') || (responses[0] == 'Y'))
      {
	if (mls_enabled)
	  new_context = context_new ("user:role:type:level");
	else
	  new_context = context_new ("user:role:type");

	if (!new_context)
              goto fail_set;

	if (context_user_set (new_context, user))
              goto fail_set;

	_pam_drop(responses);
	/* Allow the user to enter each field of the context individually */
	query_response(pamh,_("role:"), NULL, &responses,debug);
	if (responses[0] != '\0') {
	   if (context_role_set (new_context, responses)) 
              goto fail_set;
	   if (get_default_type(responses, &type)) 
              goto fail_set;
	   if (context_type_set (new_context, type)) 
              goto fail_set;
	}
	_pam_drop(responses);
	if (mls_enabled)
	  {
	    query_response(pamh,_("level:"), NULL, &responses,debug);
	    if (responses[0] != '\0') {
	      if (context_range_set (new_context, responses))
		goto fail_set;
	    }
	  }
	/* Get the string value of the context and see if it is valid. */
	if (!security_check_context(context_str(new_context))) {
	  newcon = strdup(context_str(new_context));
	  context_free (new_context);
	  return newcon;
	}
	else
	  send_text(pamh,_("Not a valid security context"),debug);
	context_free (new_context);
      }
    else {
      _pam_drop(responses);
      return NULL;
    }
  } /* end while */
 fail_set:
  free(type);
  _pam_drop(responses);
  context_free (new_context);
  return NULL;
}

static int mls_range_allowed(pam_handle_t *pamh, security_context_t src, security_context_t dst, int debug)
{
  struct av_decision avd;
  int retval;
  unsigned int bit = CONTEXT__CONTAINS;
  context_t src_context = context_new (src);
  context_t dst_context = context_new (dst);
  context_range_set(dst_context, context_range_get(src_context));
  if (debug)
    pam_syslog(pamh, LOG_NOTICE, "Checking if %s mls range valid for  %s", dst, context_str(dst_context));

  retval = security_compute_av(context_str(dst_context), dst, SECCLASS_CONTEXT, bit, &avd);
  context_free(src_context);
  context_free(dst_context);
  if (retval || ((bit & avd.allowed) != bit))
    return 0;
  
  return 1;
}

static security_context_t
config_context (pam_handle_t *pamh, security_context_t puser_context, int debug)
{
  security_context_t newcon=NULL;
  context_t new_context;
  int mls_enabled = is_selinux_mls_enabled();
  char *responses=NULL;
  char *type=NULL;
  char resp_val = 0;

  pam_prompt (pamh, PAM_TEXT_INFO, NULL, _("Default Security Context %s\n"), puser_context);

  while (1) {
    query_response(pamh,
		   _("Would you like to enter a different role or level?"), "n", 
		   &responses,debug);

    resp_val = responses[0];
    _pam_drop(responses);
    if ((resp_val == 'y') || (resp_val == 'Y'))
      {
        new_context = context_new(puser_context);
        
	/* Allow the user to enter role and level individually */
	query_response(pamh,_("role:"), context_role_get(new_context), 
		       &responses, debug);
	if (responses[0]) {
	  if (get_default_type(responses, &type)) {
	    pam_prompt (pamh, PAM_ERROR_MSG, NULL, _("No default type for role %s\n"), responses);
	    _pam_drop(responses);
	    continue;
	  } else {
	    if (context_role_set(new_context, responses)) 
	      goto fail_set;
	    if (context_type_set (new_context, type))
	      goto fail_set;
	  } 
	}
	_pam_drop(responses);
	if (mls_enabled)
	  {
	    query_response(pamh,_("level:"), context_range_get(new_context), 
			   &responses, debug);
	    if (responses[0]) {
	      if (context_range_set(new_context, responses))
		goto fail_set;
	    } 
	    _pam_drop(responses);
	  }
	if (debug)
	  pam_syslog(pamh, LOG_NOTICE, "Selected Security Context %s", context_str(new_context));

        /* Get the string value of the context and see if it is valid. */
        if (!security_check_context(context_str(new_context))) {
	  newcon = strdup(context_str(new_context));
	  context_free (new_context);

          /* we have to check that this user is allowed to go into the
             range they have specified ... role is tied to an seuser, so that'll
             be checked at setexeccon time */
          if (mls_enabled && !mls_range_allowed(pamh, puser_context, newcon, debug)) {
	    pam_syslog(pamh, LOG_NOTICE, "Security context %s is not allowed for %s", puser_context, newcon);

    	    send_audit_message(pamh, 0, puser_context, newcon);

	    free(newcon);
            goto fail_range;
	  }
	  return newcon;
	}
	else {
	  send_audit_message(pamh, 0, puser_context, context_str(new_context));
	  send_text(pamh,_("Not a valid security context"),debug);
	}
        context_free(new_context); /* next time around allocates another */
      }
    else
      return strdup(puser_context);
  } /* end while */

  return NULL;

 fail_set:
  free(type);
  _pam_drop(responses);
  context_free (new_context);
  send_audit_message(pamh, 0, puser_context, NULL);
 fail_range:
  return NULL;  
}

static void
security_restorelabel_tty(const pam_handle_t *pamh,
			  const char *tty, security_context_t context)
{
  char ttybuf[PATH_MAX];
  const char *ptr;

  if (context==NULL)
    return;

  if(strncmp("/dev/", tty, 5)) {
    snprintf(ttybuf,sizeof(ttybuf),"/dev/%s",tty);
    ptr = ttybuf;
  }
  else
    ptr = tty;

  if (setfilecon(ptr, context) && errno != ENOENT)
  {
    pam_syslog(pamh, LOG_NOTICE,
	       "Warning!  Could not relabel %s with %s, not relabeling: %m",
	       ptr, context);
  }
}

static security_context_t
security_label_tty(pam_handle_t *pamh, char *tty,
		   security_context_t usercon)
{
  char ttybuf[PATH_MAX];
  int status=0;
  security_context_t newdev_context=NULL; /* The new context of a device */
  security_context_t prev_context=NULL; /* The new context of a device */
  const char *ptr;

  if(strncmp("/dev/", tty, 5))
  {
    snprintf(ttybuf,sizeof(ttybuf),"/dev/%s",tty);
    ptr = ttybuf;
  }
  else
    ptr = tty;

  if (getfilecon(ptr, &prev_context) < 0)
  {
    if(errno != ENOENT)
      pam_syslog(pamh, LOG_NOTICE,
	     "Warning!  Could not get current context for %s, not relabeling: %m",
	     ptr);
    return NULL;
  }
  if( security_compute_relabel(usercon,prev_context,SECCLASS_CHR_FILE,
                               &newdev_context)!=0)
  {
    pam_syslog(pamh, LOG_NOTICE,
           "Warning!  Could not get new context for %s, not relabeling: %m",
           ptr);
    pam_syslog(pamh, LOG_NOTICE,
	       "usercon=%s, prev_context=%s", usercon, prev_context);
    freecon(prev_context);
    return NULL;
  }
  status=setfilecon(ptr,newdev_context);
  if (status)
  {
      pam_syslog(pamh, LOG_NOTICE,
		 "Warning!  Could not relabel %s with %s, not relabeling: %m",
		 ptr,newdev_context);
      freecon(prev_context);
      prev_context=NULL;
  }
  freecon(newdev_context);
  return prev_context;
}

static security_context_t user_context=NULL;
static security_context_t prev_user_context=NULL;
static security_context_t ttyn_context=NULL;  /* The current context of ttyn device */
static int selinux_enabled=0;
static char *ttyn=NULL;

/* Tell the user that access has been granted. */
static void
verbose_message(pam_handle_t *pamh, char *msg, int debug)
{
  if (debug)
    pam_syslog(pamh, LOG_NOTICE, msg);

  pam_info (pamh, "%s", msg);
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh UNUSED, int flags UNUSED,
		    int argc UNUSED, const char **argv UNUSED)
{
	/* Fail by default. */
	return PAM_AUTH_ERR;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh UNUSED, int flags UNUSED,
	       int argc UNUSED, const char **argv UNUSED)
{
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags UNUSED,
		    int argc, const char **argv)
{
  int i, debug = 0, ttys=1, has_tty=isatty(0);
  int verbose=0, close_session=0;
  int select_context = 0;
  int use_current_range = 0;
  int ret = 0;
  security_context_t* contextlist = NULL;
  int num_contexts = 0;
  const char *username = NULL;
  const void *tty = NULL;
  char *seuser=NULL;
  char *level=NULL;
  security_context_t default_user_context=NULL;

  /* Parse arguments. */
  for (i = 0; i < argc; i++) {
    if (strcmp(argv[i], "debug") == 0) {
      debug = 1;
    }
    if (strcmp(argv[i], "nottys") == 0) {
      ttys = 0;
    }
    if (strcmp(argv[i], "verbose") == 0) {
      verbose = 1;
    }
    if (strcmp(argv[i], "close") == 0) {
      close_session = 1;
    }
    if (strcmp(argv[i], "select_context") == 0) {
      select_context = 1;
    }
    if (strcmp(argv[i], "use_current_range") == 0) {
      use_current_range = 1;
    }
  }
  
  if (debug)
    pam_syslog(pamh, LOG_NOTICE, "Open Session");

  if (select_context && use_current_range) {
    pam_syslog(pamh, LOG_ERR, "select_context cannot be used with use_current_range");
    select_context = 0;
  }

  /* this module is only supposed to execute close_session */
  if (close_session)
      return PAM_SUCCESS;

  if (!(selinux_enabled = is_selinux_enabled()>0) )
      return PAM_SUCCESS;

  if (pam_get_item(pamh, PAM_USER, (void *) &username) != PAM_SUCCESS ||
                   username == NULL) {
    return PAM_USER_UNKNOWN;
  }

  if (getseuserbyname(username, &seuser, &level)==0) {
	  num_contexts = get_ordered_context_list_with_level(seuser, 
							     level,
							     NULL, 
							     &contextlist);
	  if (debug)
		  pam_syslog(pamh, LOG_DEBUG, "Username= %s SELinux User = %s Level= %s",
                             username, seuser, level);
	  free(seuser);
	  free(level);
  }
  if (num_contexts > 0) {
    default_user_context=strdup(contextlist[0]);
    freeconary(contextlist);
    if (default_user_context == NULL) {
	  pam_syslog(pamh, LOG_ERR, _("Out of memory"));
          return PAM_AUTH_ERR;
    }
    user_context = default_user_context;
    if (select_context && has_tty) {
      user_context = config_context(pamh, default_user_context, debug);
      if (user_context == NULL) {
	freecon(default_user_context);
	pam_syslog(pamh, LOG_ERR, _("Unable to get valid context for %s"),
		    username);
	pam_prompt (pamh, PAM_ERROR_MSG, NULL,  _("Unable to get valid context for %s"), username);
        if (security_getenforce() == 1)
          return PAM_AUTH_ERR;
        else
          return PAM_SUCCESS;
      }
    } 
  }
  else { 
    if (has_tty) {
      user_context = manual_context(pamh,seuser,debug);
      if (user_context == NULL) {
	pam_syslog (pamh, LOG_ERR, "Unable to get valid context for %s",
		    username);
        if (security_getenforce() == 1)
          return PAM_AUTH_ERR;
        else
          return PAM_SUCCESS;
      }
    } else {
        pam_syslog (pamh, LOG_ERR,
		    "Unable to get valid context for %s, No valid tty",
		    username);
        if (security_getenforce() == 1)
          return PAM_AUTH_ERR;
        else
          return PAM_SUCCESS;
    }
  }

  if (use_current_range && is_selinux_mls_enabled()) {
    security_context_t process_context=NULL;    
    if (getcon(&process_context) == 0) {
      context_t pcon, ucon;
      char *process_level=NULL;
      security_context_t orig_context;
      
      if (user_context)
        orig_context = user_context;
      else
        orig_context = default_user_context;

      pcon = context_new(process_context);
      freecon(process_context);
      process_level = strdup(context_range_get(pcon));
      context_free(pcon);

      if (debug)
        pam_syslog (pamh, LOG_DEBUG, "process level=%s", process_level);

      ucon = context_new(orig_context);

      context_range_set(ucon, process_level);
      free(process_level);

      if (!mls_range_allowed(pamh, orig_context, context_str(ucon), debug)) {
	send_text(pamh, _("Requested MLS level not in permitted range"), debug);
	/* even if default_user_context is NULL audit that anyway */
	send_audit_message(pamh, 0, default_user_context, context_str(ucon));
	context_free(ucon);
	return PAM_AUTH_ERR;
      }

      if (debug)
        pam_syslog (pamh, LOG_DEBUG, "adjusted context=%s", context_str(ucon));

      /* replace the user context with the level adjusted one */
      freecon(user_context);
      user_context = strdup(context_str(ucon));

      context_free(ucon);
    }
  }

  if (getexeccon(&prev_user_context)<0) {
    prev_user_context=NULL;
  }
  if (ttys) {
    /* Get the name of the terminal. */
    if (pam_get_item(pamh, PAM_TTY, &tty) != PAM_SUCCESS) {
      tty = NULL;
    }

    if ((tty == NULL) || (strlen(tty) == 0) ||
	strcmp(tty, "ssh") == 0 || strncmp(tty, "NODEV", 5) == 0) {
      tty = ttyname(STDIN_FILENO);
      if ((tty == NULL) || (strlen(tty) == 0)) {
	tty = ttyname(STDOUT_FILENO);
      }
      if ((tty == NULL) || (strlen(tty) == 0)) {
	tty = ttyname(STDERR_FILENO);
      }
    }
  }
  if(ttys && tty ) {
    ttyn=strdup(tty);
    ttyn_context=security_label_tty(pamh,ttyn,user_context);
  }
  send_audit_message(pamh, 1, default_user_context, user_context);
  if (default_user_context != user_context) {
    freecon(default_user_context);
  }
  ret = setexeccon(user_context);
  if (ret==0 && verbose) {
    char msg[PATH_MAX];
    snprintf(msg, sizeof(msg),
	     _("Security Context %s Assigned"), user_context);
    verbose_message(pamh, msg, debug);
  }
  if (ret) {
    pam_syslog(pamh, LOG_ERR,
	       "Error!  Unable to set %s executable context %s.",
	       username, user_context);
    if (security_getenforce() == 1) {
       freecon(user_context);
       return PAM_AUTH_ERR;
    }
  } else {
    if (debug)
      pam_syslog(pamh, LOG_NOTICE, "set %s security context to %s",
		 username, user_context);
  }
#ifdef HAVE_SETKEYCREATECON
  ret = setkeycreatecon(user_context);
  if (ret==0 && verbose) {
    char msg[PATH_MAX];
    snprintf(msg, sizeof(msg),
	     _("Key Creation Context %s Assigned"), user_context);
    verbose_message(pamh, msg, debug);
  }
  if (ret) {
    pam_syslog(pamh, LOG_ERR,
	       "Error!  Unable to set %s key creation context %s.",
	       username, user_context);
    if (security_getenforce() == 1) {
       freecon(user_context);
       return PAM_AUTH_ERR;
    }
  } else {
    if (debug)
      pam_syslog(pamh, LOG_NOTICE, "set %s key creation context to %s",
		 username, user_context);
  }
#endif
  freecon(user_context);

  return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags UNUSED,
		     int argc, const char **argv)
{
  int i, debug = 0,status=0, open_session=0;
  if (! (selinux_enabled ))
      return PAM_SUCCESS;

  /* Parse arguments. */
  for (i = 0; i < argc; i++) {
    if (strcmp(argv[i], "debug") == 0) {
      debug = 1;
    }
    if (strcmp(argv[i], "open") == 0) {
      open_session = 1;
    }
  }

  if (debug)
    pam_syslog(pamh, LOG_NOTICE, "Close Session");

  if (open_session)
    return PAM_SUCCESS;

  if (ttyn) {
    if (debug)
      pam_syslog(pamh, LOG_NOTICE, "Restore tty  %s -> %s",
		 ttyn,ttyn_context);

    security_restorelabel_tty(pamh,ttyn,ttyn_context);
    freecon(ttyn_context);
    free(ttyn);
    ttyn=NULL;
  }
  status=setexeccon(prev_user_context);
  freecon(prev_user_context);
  if (status) {
    pam_syslog(pamh, LOG_ERR, "Error!  Unable to set executable context %s.",
	       prev_user_context);
    if (security_getenforce() == 1)
       return PAM_AUTH_ERR;
    else
       return PAM_SUCCESS;
  }

  if (debug)
    pam_syslog(pamh, LOG_NOTICE, "setcontext back to orginal");

  return PAM_SUCCESS;
}
