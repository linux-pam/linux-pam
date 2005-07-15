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

#include "../../_pam_aconf.h"

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
#include <linux/limits.h>

#define PAM_SM_AUTH
#define PAM_SM_SESSION

#include <security/pam_modules.h>
#include <security/_pam_macros.h>
#include <security/_pam_modutil.h>

#include <libintl.h>
#define _(x) gettext(x)

#ifndef PAM_SELINUX_MAIN
#define MODULE "pam_selinux"

#include <selinux/selinux.h>
#include <selinux/get_context_list.h>
#include <selinux/flask.h>
#include <selinux/selinux.h>
#include <selinux/context.h>

static int
send_text (const struct pam_conv *conv, const char *text, int debug)
{
  struct pam_message message;
  const struct pam_message *messages[] = {&message};
  struct pam_response *responses;
  int retval;

  memset(&message, 0, sizeof(message));
  message.msg_style = PAM_TEXT_INFO;
  message.msg = text;
  if (debug)
    syslog(LOG_NOTICE, MODULE ": %s", message.msg);
  retval = conv->conv(1, messages, &responses, conv->appdata_ptr);
  if (responses)
    _pam_drop_reply(responses, 1);
  return retval;
}

/*
 * This function sends a message to the user and gets the response. The caller
 * is responsible for freeing the responses.
 */
static int
query_response (const struct pam_conv *conv, const char *text,
		struct pam_response **responses, int debug)
{
  struct pam_message message;
  const struct pam_message *messages[] = {&message};

  memset(&message, 0, sizeof(message));
  message.msg_style = PAM_PROMPT_ECHO_ON;
  message.msg = text;

  if (debug)
    syslog(LOG_NOTICE, MODULE ": %s", message.msg);

  return conv->conv(1, messages, responses, conv->appdata_ptr);
}

static security_context_t
select_context (pam_handle_t *pamh, security_context_t* contextlist,
		int debug)
{
  const void *void_conv;
  const struct pam_conv *conv;

  if (pam_get_item(pamh, PAM_CONV, &void_conv) == PAM_SUCCESS &&
      void_conv) {
    conv = void_conv;
    if (conv->conv != NULL) {
      struct pam_response *responses;
      char *text=calloc(PATH_MAX,1);

      if (text == NULL)
	return (security_context_t) strdup(contextlist[0]);

      snprintf(text, PATH_MAX,
	       _("Your default context is %s. \n"), contextlist[0]);
      send_text(conv,text,debug);
      free(text);
      query_response(conv,_("Do you want to choose a different one? [n]"),
		&responses,debug);
      if (responses && ((responses[0].resp[0] == 'y') ||
			(responses[0].resp[0] == 'Y')))
      {
	  int choice=0;
	  int i;
	  char *prompt=_("Enter number of choice: ");
	  int len=strlen(prompt);
	  char buf[PATH_MAX];

	  _pam_drop_reply(responses, 1);
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
	    query_response(conv,text,&responses,debug);
	    choice = strtol (responses[0].resp, NULL, 10);
            _pam_drop_reply(responses, 1);
	  }
	  free(text);
	  return (security_context_t) strdup(contextlist[choice-1]);
      }
      else if (responses)
        _pam_drop_reply(responses, 1);
    } else {
      if (debug)
	syslog(LOG_NOTICE, _("%s: bogus conversation function"),MODULE);
    }
  } else {
    if (debug)
      syslog(LOG_NOTICE, _("%s: no conversation function"),MODULE);
  }
  return (security_context_t) strdup(contextlist[0]);
}

static security_context_t
manual_context (pam_handle_t *pamh, const char *user, int debug)
{
  const void *void_conv;
  const struct pam_conv *conv;
  security_context_t newcon;
  context_t new_context;
  int mls_enabled = is_selinux_mls_enabled();

  if (pam_get_item(pamh, PAM_CONV, &void_conv) == PAM_SUCCESS) {
    conv = void_conv;
    if (conv && conv->conv != NULL) {
      struct pam_response *responses;

      while (1) {
	query_response(conv,
                       _("Would you like to enter a security context? [y] "),
                       &responses,debug);
	if ((responses[0].resp[0] == 'y') || (responses[0].resp[0] == 'Y') ||
            (responses[0].resp[0] == '\0') )
	{
 	  if (mls_enabled)
 	    new_context = context_new ("user:role:type:level");
 	  else
 	    new_context = context_new ("user:role:type");
          _pam_drop_reply(responses, 1);

	  /* Allow the user to enter each field of the context individually */
	  if (context_user_set (new_context, user))
	  {
	      context_free (new_context);
	      return NULL;
	  }
	  query_response(conv,_("role: "),&responses,debug);
	  if (context_role_set (new_context, responses[0].resp))
	  {
              _pam_drop_reply(responses, 1);
	      context_free (new_context);
	      return NULL;
	  }
          _pam_drop_reply(responses, 1);
	  query_response(conv,_("type: "),&responses,debug);
	  if (context_type_set (new_context, responses[0].resp))
	  {
              _pam_drop_reply(responses, 1);
	      context_free (new_context);
	      return NULL;
	  }
          _pam_drop_reply(responses, 1);
 	  if (mls_enabled)
 	    {
 	      query_response(conv,_("level: "),&responses,debug);
 	      if (context_range_set (new_context, responses[0].resp))
 	        {
 	          context_free (new_context);
 	          return NULL;
 	        }
 	    }
	  /* Get the string value of the context and see if it is valid. */
	  if (!security_check_context(context_str(new_context))) {
	    newcon = strdup(context_str(new_context));
	    context_free (new_context);
	    return newcon;
	  }
	  else
	    send_text(conv,_("Not a valid security context"),debug);
	}
	else {
          _pam_drop_reply(responses, 1);
	  return NULL;
	}
      } /* end while */
    } else {
      if (debug)
	syslog(LOG_NOTICE, _("%s: bogus conversation function"),MODULE);
    }
  } else {
    if (debug)
      syslog(LOG_NOTICE, _("%s: no conversation function"),MODULE);
  }
  return NULL;
}

static void security_restorelabel_tty(const char *tty,
                                      security_context_t context) {
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
      syslog(LOG_NOTICE,
             _("Warning!  Could not relabel %s with %s, not relabeling.\n"),
             ptr, context);
  }
}

static security_context_t security_label_tty(char *tty,
                                             security_context_t usercon) {
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
      syslog(LOG_NOTICE,
           _("Warning!  Could not get current context for %s, not relabeling."),           ptr);
      return NULL;
  }
  if( security_compute_relabel(usercon,prev_context,SECCLASS_CHR_FILE,
                               &newdev_context)!=0)
  {
    syslog(LOG_NOTICE,
           _("Warning!  Could not get new context for %s, not relabeling."),
           ptr);
    syslog(LOG_NOTICE, "usercon=%s, prev_context=%s\n", usercon, prev_context);
    freecon(prev_context);
    return NULL;
  }
  status=setfilecon(ptr,newdev_context);
  if (status)
  {
      syslog(LOG_NOTICE,
             _("Warning!  Could not relabel %s with %s, not relabeling.%s"),
             ptr,newdev_context,strerror(errno));
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
  const void *void_conv;
  const struct pam_conv *conv;
  struct pam_message message;
  const struct pam_message *messages[] = {&message};
  struct pam_response *responses;
  if (pam_get_item(pamh, PAM_CONV, &void_conv) == PAM_SUCCESS) {
    conv = void_conv;
    if (conv && conv->conv != NULL) {
      char text[PATH_MAX];

      memset(&message, 0, sizeof(message));
      message.msg_style = PAM_TEXT_INFO;
      snprintf(text, sizeof(text), msg);

      message.msg = text;
      if (debug)
	syslog(LOG_NOTICE, MODULE ": %s", message.msg);
      conv->conv(1, messages, &responses, conv->appdata_ptr);
      if (responses)
        _pam_drop_reply(responses, 1);
    } else {
      if (debug)
	syslog(LOG_NOTICE, _("%s: bogus conversation function"),MODULE);
    }
  } else {
    if (debug)
      syslog(LOG_NOTICE,_("%s: no conversation function"),MODULE);
  }
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	/* Fail by default. */
	return PAM_AUTH_ERR;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  int i, debug = 0, ttys=1, has_tty=isatty(0), verbose=0, multiple=0, close_session=0;
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
    syslog(LOG_NOTICE, MODULE ": %s", "Open Session");

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
	syslog (LOG_ERR, _("Unable to get valid context for %s"),
		(const char *)username);
	return PAM_AUTH_ERR;
      }
    } else {
	syslog (LOG_ERR,
		_("Unable to get valid context for %s, No valid tty"),
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
    ttyn_context=security_label_tty(ttyn,user_context);
  }
  ret = setexeccon(user_context);
  if (ret==0 && verbose) {
    char msg[PATH_MAX];
    snprintf(msg, sizeof(msg),
	     _("Security Context %s Assigned"), user_context);
    verbose_message(pamh, msg, debug);
  }
  if (ret) {
    syslog(LOG_ERR, _("Error!  Unable to set %s executable context %s."),
           (const char *)username, user_context);
    freecon(user_context);
    return PAM_AUTH_ERR;
  } else {
    if (debug)
      syslog(LOG_NOTICE, _("%s: set %s security context to %s"),MODULE,
             (const char *)username, user_context);
  }
  freecon(user_context);

  return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
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
    syslog(LOG_NOTICE, MODULE ": %s", "Close Session");

  if (open_session)
    return PAM_SUCCESS;

  if (ttyn) {
    if (debug)
      syslog(LOG_NOTICE, MODULE ":Restore tty  %s -> %s", ttyn,ttyn_context);

    security_restorelabel_tty(ttyn,ttyn_context);
    freecon(ttyn_context);
    free(ttyn);
    ttyn=NULL;
  }
  status=setexeccon(prev_user_context);
  freecon(prev_user_context);
  if (status) {
    syslog(LOG_ERR, _("Error!  Unable to set executable context %s."),
           prev_user_context);
    return PAM_AUTH_ERR;
  }

  if (debug)
    syslog(LOG_NOTICE, _("%s: setcontext back to orginal"),MODULE);

  return PAM_SUCCESS;
}

#else /* PAM_SELINUX_MAIN */

/************************************************************************
 *
 * All PAM code goes in this section.
 *
 ************************************************************************/

#include <unistd.h>               /* for getuid(), exit(), getopt() */
#include <signal.h>
#include <sys/wait.h>		  /* for wait() */

#include <security/pam_appl.h>    /* for PAM functions */
#include <security/pam_misc.h>    /* for misc_conv PAM utility function */

#define SERVICE_NAME "pam_selinux_check"   /* the name of this program for PAM */
				  /* The file containing the context to run
				   * the scripts under.                     */
int authenticate_via_pam( const char *user ,   pam_handle_t **pamh);

/* authenticate_via_pam()
 *
 * in:     user
 * out:    nothing
 * return: value   condition
 *         -----   ---------
 *           1     pam thinks that the user authenticated themselves properly
 *           0     otherwise
 *
 * this function uses pam to authenticate the user running this
 * program.  this is the only function in this program that makes pam
 * calls.
 *
 */

int authenticate_via_pam( const char *user ,   pam_handle_t **pamh) {

  struct pam_conv *conv;
  int result = 0;    /* our result, set to 0 (not authenticated) by default */

  /* this is a jump table of functions for pam to use when it wants to *
   * communicate with the user.  we'll be using misc_conv(), which is  *
   * provided for us via pam_misc.h.                                   */
  struct pam_conv pam_conversation = {
    misc_conv,
    NULL
  };
  conv = &pam_conversation;


  /* make `p_pam_handle' a valid pam handle so we can use it when *
   * calling pam functions.                                       */
  if( PAM_SUCCESS != pam_start( SERVICE_NAME,
				user,
				conv,
				pamh ) ) {
    fprintf( stderr, _("failed to initialize PAM\n") );
    exit( -1 );
  }

  if( PAM_SUCCESS != pam_set_item(*pamh, PAM_RUSER, user))
  {
      fprintf( stderr, _("failed to pam_set_item()\n") );
      exit( -1 );
  }

  /* Ask PAM to authenticate the user running this program */
  if( PAM_SUCCESS == pam_authenticate(*pamh,0) ) {
    if ( PAM_SUCCESS == pam_open_session(*pamh, 0) )
      result = 1;  /* user authenticated OK! */
  }
  return( result );

} /* authenticate_via_pam() */

int main(int argc, char **argv) {
  pam_handle_t *pamh;
  int childPid;

  if (!authenticate_via_pam(argv[1],&pamh))
    exit(-1);

  childPid = fork();
  if (childPid < 0) {
    int errsv = errno;

    /* error in fork() */
    fprintf(stderr, _("login: failure forking: %s"), strerror(errsv));
    pam_close_session(pamh, 0);
    /* We're done with PAM.  Free `pam_handle'. */
    pam_end( pamh, PAM_SUCCESS );
    exit(0);
  }
  if (childPid) {
    close(0); close(1); close(2);
    struct sigaction sa;
    memset(&sa,0,sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    while(wait(NULL) == -1 && errno == EINTR) /**/ ;
    openlog("login", LOG_ODELAY, LOG_AUTHPRIV);
    pam_close_session(pamh, 0);
    /* We're done with PAM.  Free `pam_handle'. */
    pam_end( pamh, PAM_SUCCESS );
    exit(0);
  }
  argv[0]="/bin/sh";
  argv[1]=NULL;

  /* NOTE: The environment has not been sanitized. LD_PRELOAD and other fun
   * things could be set. */
  execv("/bin/sh",argv);
  fprintf(stderr,"Failure\n");
  return 0;
}
#endif
