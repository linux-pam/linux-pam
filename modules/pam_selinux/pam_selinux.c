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
#include <selinux/selinux.h>
#include <selinux/context.h>

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
query_response (pam_handle_t *pamh, const char *text,
		char **responses, int debug)
{
  if (debug)
    pam_syslog(pamh, LOG_NOTICE, "%s", text);

  return pam_prompt (pamh, PAM_PROMPT_ECHO_ON, responses, "%s", text);
}

static security_context_t
select_context (pam_handle_t *pamh, security_context_t* contextlist,
		int debug)
{
  char *responses;
  char *text=calloc(PATH_MAX,1);

  if (text == NULL)
    return (security_context_t) strdup(contextlist[0]);

  snprintf(text, PATH_MAX,
	   _("Your default context is %s. \n"), contextlist[0]);
  send_text(pamh,text,debug);
  free(text);
  query_response(pamh,_("Do you want to choose a different one? [n]"),
		 &responses,debug);
  if (responses && ((responses[0] == 'y') ||
		    (responses[0] == 'Y')))
    {
      int choice=0;
      int i;
      const char *prompt=_("Enter number of choice: ");
      int len=strlen(prompt);
      char buf[PATH_MAX];

      _pam_drop(responses);
      for (i = 0; contextlist[i]; i++) {
	len+=strlen(contextlist[i]) + 10;
      }
      text=calloc(len,1);
      for (i = 0; contextlist[i]; i++) {
	snprintf(buf, PATH_MAX,
		 "[%d] %s\n", i+1, contextlist[i]);
	strncat(text,buf,len);
      }
      strcat(text,prompt);
      while ((choice < 1) || (choice > i)) {
	query_response(pamh,text,&responses,debug);
	choice = strtol (responses, NULL, 10);
	_pam_drop(responses);
      }
      free(text);
      return (security_context_t) strdup(contextlist[choice-1]);
    }
  else if (responses)
    _pam_drop(responses);

  return (security_context_t) strdup(contextlist[0]);
}

static security_context_t
manual_context (pam_handle_t *pamh, const char *user, int debug)
{
  security_context_t newcon;
  context_t new_context;
  int mls_enabled = is_selinux_mls_enabled();

  char *responses;

  while (1) {
    query_response(pamh,
		   _("Would you like to enter a security context? [y] "),
		   &responses,debug);
    if ((responses[0] == 'y') || (responses[0] == 'Y') ||
	(responses[0] == '\0') )
      {
	if (mls_enabled)
	  new_context = context_new ("user:role:type:level");
	else
	  new_context = context_new ("user:role:type");
	_pam_drop(responses);

	/* Allow the user to enter each field of the context individually */
	if (context_user_set (new_context, user))
	  {
	    context_free (new_context);
	    return NULL;
	  }
	query_response(pamh,_("role: "),&responses,debug);
	if (context_role_set (new_context, responses))
	  {
	    _pam_drop(responses);
	    context_free (new_context);
	    return NULL;
	  }
	_pam_drop(responses);
	query_response(pamh,_("type: "),&responses,debug);
	if (context_type_set (new_context, responses))
	  {
	    _pam_drop(responses);
	    context_free (new_context);
	    return NULL;
	  }
	_pam_drop(responses);
	if (mls_enabled)
	  {
	    query_response(pamh,_("level: "),&responses,debug);
	    if (context_range_set (new_context, responses))
	      {
		_pam_drop(responses);
		context_free (new_context);
		return NULL;
	      }
	    _pam_drop(responses);
	  }
	/* Get the string value of the context and see if it is valid. */
	if (!security_check_context(context_str(new_context))) {
	  newcon = strdup(context_str(new_context));
	  context_free (new_context);
	  return newcon;
	}
	else
	  send_text(pamh,_("Not a valid security context"),debug);
      }
    else {
      _pam_drop(responses);
      return NULL;
    }
  } /* end while */

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
  int verbose=0, multiple=0, close_session=0;
  int ret = 0;
  security_context_t* contextlist = NULL;
  int num_contexts = 0;
  const void *username = NULL;
  const void *tty = NULL;

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
    if (strcmp(argv[i], "multiple") == 0) {
      multiple = 1;
    }
    if (strcmp(argv[i], "close") == 0) {
      close_session = 1;
    }
  }

  if (debug)
    pam_syslog(pamh, LOG_NOTICE, "Open Session");

  /* this module is only supposed to execute close_session */
  if (close_session)
      return PAM_SUCCESS;

  if (!(selinux_enabled = is_selinux_enabled()>0) )
      return PAM_SUCCESS;

  if (pam_get_item(pamh, PAM_USER, &username) != PAM_SUCCESS ||
                   username == NULL) {
    return PAM_AUTH_ERR;
  }
  num_contexts = get_ordered_context_list(username, 0, &contextlist);
  if (num_contexts > 0) {
    if (multiple && (num_contexts > 1) && has_tty) {
      user_context = select_context(pamh,contextlist, debug);
      freeconary(contextlist);
    } else {
      user_context = (security_context_t) strdup(contextlist[0]);
      freeconary(contextlist);
    }
  } else {
    if (has_tty) {
      user_context = manual_context(pamh,username,debug);
      if (user_context == NULL) {
	pam_syslog (pamh, LOG_ERR, "Unable to get valid context for %s",
		    (const char *)username);
	return PAM_AUTH_ERR;
      }
    } else {
        pam_syslog (pamh, LOG_ERR,
		    "Unable to get valid context for %s, No valid tty",
		    (const char *)username);
	return PAM_AUTH_ERR;
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
	       (const char *)username, user_context);
    freecon(user_context);
    return PAM_AUTH_ERR;
  } else {
    if (debug)
      pam_syslog(pamh, LOG_NOTICE, "set %s security context to %s",
		 (const char *)username, user_context);
  }
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
    return PAM_AUTH_ERR;
  }

  if (debug)
    pam_syslog(pamh, LOG_NOTICE, "setcontext back to orginal");

  return PAM_SUCCESS;
}
