/* pam_start.c */

/* Creator Marc Ewing
 * Maintained by AGM
 *
 * $Id$
 *
 */

#include "pam_private.h"

#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>

int pam_start (
    const char *service_name,
    const char *user,
    const struct pam_conv *pam_conversation,
    pam_handle_t **pamh)
{
    D(("called pam_start: [%s] [%s] [%p] [%p]"
       ,service_name, user, pam_conversation, pamh));

    if (pamh == NULL) {
	pam_syslog(NULL, LOG_CRIT,
		   "pam_start: invalid argument: pamh == NULL");
	return (PAM_SYSTEM_ERR);
    }

    if (service_name == NULL) {
	pam_syslog(NULL, LOG_CRIT,
		   "pam_start: invalid argument: service == NULL");
	return (PAM_SYSTEM_ERR);
    }

    if (pam_conversation == NULL) {
	pam_syslog(NULL, LOG_CRIT,
		   "pam_start: invalid argument: conv == NULL");
	return (PAM_SYSTEM_ERR);
    }

    if ((*pamh = calloc(1, sizeof(**pamh))) == NULL) {
	pam_syslog(NULL, LOG_CRIT, "pam_start: calloc failed for *pamh");
	return (PAM_BUF_ERR);
    }

    /* All service names should be files below /etc/pam.d and nothing
       else. Forbid paths. */
    if (strrchr(service_name, '/') != NULL)
	service_name = strrchr(service_name, '/') + 1;

    /* Mark the caller as the application - permission to do certain
       things is limited to a module or an application */

    __PAM_TO_APP(*pamh);

    if (((*pamh)->service_name = _pam_strdup(service_name)) == NULL) {
	pam_syslog(*pamh, LOG_CRIT,
		   "pam_start: _pam_strdup failed for service name");
	_pam_drop(*pamh);
	return (PAM_BUF_ERR);
    } else {
	char *tmp;

	for (tmp=(*pamh)->service_name; *tmp; ++tmp)
	    *tmp = tolower(*tmp);                   /* require lower case */
    }

    if (user) {
	if (((*pamh)->user = _pam_strdup(user)) == NULL) {
	    pam_syslog(*pamh, LOG_CRIT,
		       "pam_start: _pam_strdup failed for user");
	    _pam_drop((*pamh)->service_name);
	    _pam_drop(*pamh);
	    return (PAM_BUF_ERR);
	}
    } else
	(*pamh)->user = NULL;

    (*pamh)->tty = NULL;
    (*pamh)->prompt = NULL;              /* prompt for pam_get_user() */
    (*pamh)->ruser = NULL;
    (*pamh)->rhost = NULL;
    (*pamh)->authtok = NULL;
    (*pamh)->oldauthtok = NULL;
    (*pamh)->fail_delay.delay_fn_ptr = NULL;
    (*pamh)->former.choice = PAM_NOT_STACKED;
    (*pamh)->former.substates = NULL;
#ifdef HAVE_LIBAUDIT
    (*pamh)->audit_state = 0;
#endif
    (*pamh)->xdisplay = NULL;
    (*pamh)->authtok_type = NULL;
    memset (&((*pamh)->xauth), 0, sizeof ((*pamh)->xauth));

    if (((*pamh)->pam_conversation = (struct pam_conv *)
	  malloc(sizeof(struct pam_conv))) == NULL) {
	pam_syslog(*pamh, LOG_CRIT, "pam_start: malloc failed for pam_conv");
	_pam_drop((*pamh)->service_name);
	_pam_drop((*pamh)->user);
	_pam_drop(*pamh);
	return (PAM_BUF_ERR);
    } else {
	memcpy((*pamh)->pam_conversation, pam_conversation,
	       sizeof(struct pam_conv));
    }

    (*pamh)->data = NULL;
    if ( _pam_make_env(*pamh) != PAM_SUCCESS ) {
	pam_syslog(*pamh,LOG_ERR,"pam_start: failed to initialize environment");
	_pam_drop((*pamh)->pam_conversation);
	_pam_drop((*pamh)->service_name);
	_pam_drop((*pamh)->user);
	_pam_drop(*pamh);
	return PAM_ABORT;
    }

    _pam_reset_timer(*pamh);         /* initialize timer support */

    _pam_start_handlers(*pamh);                   /* cannot fail */

    /* According to the SunOS man pages, loading modules and resolving
     * symbols happens on the first call from the application. */

    if ( _pam_init_handlers(*pamh) != PAM_SUCCESS ) {
	pam_syslog(*pamh, LOG_ERR, "pam_start: failed to initialize handlers");
	_pam_drop_env(*pamh);                 /* purge the environment */
	_pam_drop((*pamh)->pam_conversation);
	_pam_drop((*pamh)->service_name);
	_pam_drop((*pamh)->user);
	_pam_drop(*pamh);
	return PAM_ABORT;
    }

    D(("exiting pam_start successfully"));

    return PAM_SUCCESS;
}
