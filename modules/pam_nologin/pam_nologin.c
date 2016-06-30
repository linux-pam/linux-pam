/* pam_nologin module */

/*
 * $Id$
 *
 * Written by Michael K. Johnson <johnsonm@redhat.com> 1996/10/24
 *
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <pwd.h>

#include <security/_pam_macros.h>
/*
 * here, we make a definition for the externally accessible function
 * in this file (this definition is required for static a module
 * but strongly encouraged generally) it is used to instruct the
 * modules include file to define the function prototypes.
 */

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT

#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>

#define DEFAULT_NOLOGIN_PATH "/var/run/nologin"
#define COMPAT_NOLOGIN_PATH "/etc/nologin"

/*
 * parse some command line options
 */
struct opt_s {
    int retval_when_nofile;
    const char *nologin_file;
};

static void
parse_args(pam_handle_t *pamh, int argc, const char **argv, struct opt_s *opts)
{
    int i;

    memset(opts, 0, sizeof(*opts));

    opts->retval_when_nofile = PAM_IGNORE;

    for (i=0; i<argc; ++i) {
	if (!strcmp("successok", argv[i])) {
	    opts->retval_when_nofile = PAM_SUCCESS;
	} else if (!strncmp("file=", argv[i], 5)) {
	    opts->nologin_file = argv[i] + 5;
	} else {
	    pam_syslog(pamh, LOG_ERR, "unknown option: %s", argv[i]);
	}
    }
}

/*
 * do the meat of the work for this module
 */

static int perform_check(pam_handle_t *pamh, struct opt_s *opts)
{
    const char *username;
    int retval = opts->retval_when_nofile;
    int fd = -1;

    if ((pam_get_user(pamh, &username, NULL) != PAM_SUCCESS) || !username) {
	pam_syslog(pamh, LOG_ERR, "cannot determine username");
	return PAM_USER_UNKNOWN;
    }

    if (opts->nologin_file == NULL) {
	if ((fd = open(DEFAULT_NOLOGIN_PATH, O_RDONLY, 0)) < 0) {
		fd = open(COMPAT_NOLOGIN_PATH, O_RDONLY, 0);
	}
    } else {
	fd = open(opts->nologin_file, O_RDONLY, 0);
    }

    if (fd >= 0) {

	char *mtmp=NULL;
	int msg_style = PAM_TEXT_INFO;
	struct passwd *user_pwd;
	struct stat st;

	user_pwd = pam_modutil_getpwnam(pamh, username);
	if (user_pwd == NULL) {
	    retval = PAM_USER_UNKNOWN;
	    msg_style = PAM_ERROR_MSG;
	} else if (user_pwd->pw_uid) {
	    retval = PAM_AUTH_ERR;
	    msg_style = PAM_ERROR_MSG;
	}

	/* fill in message buffer with contents of /etc/nologin */
	if (fstat(fd, &st) < 0)  {
	    /* give up trying to display message */
	    goto clean_up_fd;
	}

	mtmp = malloc(st.st_size+1);
	if (!mtmp) {
	    pam_syslog(pamh, LOG_CRIT, "out of memory");
	    retval = PAM_BUF_ERR;
	    goto clean_up_fd;
	}

	if (pam_modutil_read(fd, mtmp, st.st_size) == st.st_size) {
		mtmp[st.st_size] = '\0';
		(void) pam_prompt (pamh, msg_style, NULL, "%s", mtmp);
	}
	else
	    retval = PAM_SYSTEM_ERR;

	free(mtmp);

    clean_up_fd:

	close(fd);
    }

    return retval;
}

/* --- authentication management functions --- */

int
pam_sm_authenticate (pam_handle_t *pamh, int flags UNUSED,
		     int argc, const char **argv)
{
    struct opt_s opts;

    parse_args(pamh, argc, argv, &opts);

    return perform_check(pamh, &opts);
}

int
pam_sm_setcred (pam_handle_t *pamh UNUSED, int flags UNUSED,
		int argc, const char **argv)
{
    struct opt_s opts;

    parse_args(pamh, argc, argv, &opts);

    return opts.retval_when_nofile;
}

/* --- account management function --- */

int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags UNUSED,
		 int argc, const char **argv)
{
    struct opt_s opts;

    parse_args(pamh, argc, argv, &opts);

    return perform_check(pamh, &opts);
}

/* end of module definition */
