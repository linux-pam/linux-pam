/* pam_nologin module */

/*
 * $Id$
 *
 * Written by Michael K. Johnson <johnsonm@redhat.com> 1996/10/24
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
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

#include <security/_pam_modutil.h>

/*
 * parse some command line options
 */
struct opt_s {
    int retval_when_nofile;
    const char *nologin_file;
};

static void parse_args(pam_handle_t *pamh, int argc, const char **argv,
		       struct opt_s *opts)
{
    int i;

    memset(opts, 0, sizeof(*opts));

    opts->retval_when_nofile = PAM_IGNORE;
    opts->nologin_file = "/etc/nologin";

    for (i=0; i<argc; ++i) {
	if (!strcmp("successok", argv[i])) {
	    opts->retval_when_nofile = PAM_SUCCESS;
	} else if (!memcmp("file=", argv[i], 5)) {
	    opts->nologin_file = argv[i] + 5;
	} else {
	    /* XXX - ignore for now. Later, we'll use the logging
               function in pammodutils */
	}
    }
}

/*
 * do the meat of the work for this module
 */

static int perform_check(pam_handle_t *pamh, struct opt_s *opts)
{
    const char *username;
    int retval = PAM_SUCCESS;
    int fd;

    retval = opts->retval_when_nofile;

    if ((pam_get_user(pamh, &username, NULL) != PAM_SUCCESS) || !username) {
	return PAM_USER_UNKNOWN;
    }

    if ((fd = open(opts->nologin_file, O_RDONLY, 0)) >= 0) {

	char *mtmp=NULL;
	struct passwd *user_pwd;
	struct pam_conv *conversation;
	struct pam_message message;
	struct pam_message *pmessage = &message;
	struct pam_response *resp = NULL;
	struct stat st;

	user_pwd = _pammodutil_getpwnam(pamh, username);
	if (user_pwd == NULL) {

	    retval = PAM_USER_UNKNOWN;
	    message.msg_style = PAM_ERROR_MSG;

	} else if (user_pwd->pw_uid) {

	    retval = PAM_AUTH_ERR;
	    message.msg_style = PAM_ERROR_MSG;

	} else {

	    /* root can still log in; lusers cannot */
	    message.msg_style = PAM_TEXT_INFO;

	}

	/* fill in message buffer with contents of /etc/nologin */
	if (fstat(fd, &st) < 0)  {
	    /* give up trying to display message */
	    goto clean_up_fd;
	}

	message.msg = mtmp = malloc(st.st_size+1);
	if (!message.msg) {
	    /* if malloc failed... */
	    retval = PAM_BUF_ERR;
	    goto clean_up_fd;
	}

	if (_pammodutil_read(fd, mtmp, st.st_size) == st.st_size) {
		mtmp[st.st_size] = '\000';

		/*
		 * Use conversation function to give user contents 
		 * of /etc/nologin
		 */

		retval = pam_get_item(pamh, PAM_CONV, 
				(const void **)&conversation);
		if ((retval == PAM_SUCCESS) && (conversation)) {
			(void) conversation->conv(1, 
				(const struct pam_message **)&pmessage,
				&resp, conversation->appdata_ptr);

			if (resp) {
			    _pam_drop_reply(resp, 1);
			}
		}
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

PAM_EXTERN
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                        const char **argv)
{
    struct opt_s opts;

    parse_args(pamh, argc, argv, &opts);

    return perform_check(pamh, &opts);
}

PAM_EXTERN
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
                   const char **argv)
{
    struct opt_s opts;

    parse_args(pamh, argc, argv, &opts);

    return opts.retval_when_nofile;
}

/* --- account management function --- */

PAM_EXTERN
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc,
		     const char **argv)
{
    struct opt_s opts;

    parse_args(pamh, argc, argv, &opts);

    return perform_check(pamh, &opts);
}


#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_nologin_modstruct = {
     "pam_nologin",
     pam_sm_authenticate,
     pam_sm_setcred,
     pam_sm_acct_mgmt,
     NULL,
     NULL,
     NULL,
};

#endif /* PAM_STATIC */

/* end of module definition */
