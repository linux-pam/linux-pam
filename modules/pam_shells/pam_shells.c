/* pam_shells module */

/*
 * by Erik Troan <ewt@redhat.com>, Red Hat Software.
 * August 5, 1996.
 * This code shamelessly ripped from the pam_securetty module.
 */

#include "config.h"

#include <pwd.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>
#include <errno.h>

/*
 * here, we make a definition for the externally accessible function
 * in this file (this definition is required for static a module
 * but strongly encouraged generally) it is used to instruct the
 * modules include file to define the function prototypes.
 */

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define SHELL_FILE_DEFAULT "/etc/shells"
#define PWFILE_DEFAULT     "/etc/passwd"

#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>

struct pam_shells_options
{
    int         debug;
    const char *shellfile;
    const char *pwfile;
};

static int
pam_shells_parse_options(pam_handle_t               *pamh,
                         int                         argc,
                         const char                **argv,
                         struct pam_shells_options  *opt)
{
    int         i;

    if (pamh == NULL)
    {
        return(PAM_SERVICE_ERR);
    }

    if (opt == NULL)
    {
        pam_syslog(pamh, LOG_ERR, "Options are invalid");
        return(PAM_SERVICE_ERR);
    }

    /*
     *  Initialize the options.
     */
    opt->debug     = 0;
    opt->shellfile = SHELL_FILE_DEFAULT;
    opt->pwfile    = PWFILE_DEFAULT;

    /* process arguments */
    for (i = 0; i < argc; i++)
    {
        if (strcmp("debug", argv[i]) == 0)
        {
            opt->debug = 1;
        }
    }

    for (i = 0; i < argc; i++)
    {
        if (strncmp("pwfile=", argv[i], 7) == 0)
        {
            opt->pwfile = argv[i] + 7;
            if (opt->debug)
            {
                pam_syslog(pamh, LOG_DEBUG, "set pwfile to \"%s\"", opt->pwfile);
            }
        }
        else if (strncmp("shellfile=", argv[i], 10) == 0)
        {
            opt->shellfile = argv[i] + 10;
            if (opt->debug)
            {
                pam_syslog(pamh, LOG_DEBUG, "set shellfile to \"%s\"", opt->shellfile);
            }
        }
    }

    return(PAM_SUCCESS);
}

static struct passwd *
pam_shells_getpwnam(pam_handle_t               *pamh,
                    struct pam_shells_options  *opt,
                    const char                 *username)
{
    FILE          *fp;
    struct passwd *pw;


    if (pamh == NULL)
    {
        return(NULL);
    }

    if (opt == NULL
            ||
        opt->pwfile == NULL
            ||
        username == NULL)
    {
        pam_syslog(pamh, LOG_ERR, "Arguments to pam_shells_getpwnam invalid");
        return(NULL);
    }


    /*
     *  Open the password file.
     */
    errno = 0;
    fp = fopen(opt->pwfile, "r");
    if (fp == NULL)
    {
        pam_syslog(pamh, LOG_ERR, "Failed to open passwd file %s", opt->pwfile);
        return(NULL);
    }


    pw = fgetpwent(fp);
    while (pw != NULL)
    {
        if (strcmp(username, pw->pw_name) == 0)
        {
            if (opt->debug)
            {
                pam_syslog(pamh, LOG_DEBUG, "User %s found in passwd file %s", username, opt->pwfile);
            }

            break;
        }

        pw = fgetpwent(fp);
    }

    fclose(fp);
    return(pw);
}

static int perform_check(pam_handle_t               *pamh,
                         struct pam_shells_options  *opt)
{
    int retval = PAM_AUTH_ERR;
    const char *userName;
    char *userShell;
    char shellFileLine[256];
    struct stat sb;
    struct passwd * pw;
    FILE * shellFile;

    retval = pam_get_user(pamh, &userName, NULL);
    if (retval != PAM_SUCCESS)
    {
        pam_syslog(pamh, LOG_ERR, "pam_get_user(1) failed. rc: %d", retval);
        return PAM_SERVICE_ERR;
    }

    if (!userName || (userName[0] == '\0'))
    {

        /* Don't let them use a NULL username... */
        retval = pam_get_user(pamh,&userName,NULL);
        if (retval != PAM_SUCCESS)
        {
            pam_syslog(pamh, LOG_ERR, "pam_get_user(2) failed. rc: %d", retval);
            return PAM_SERVICE_ERR;
        }

        /* It could still be NULL the second time. */
        if (!userName || (userName[0] == '\0'))
        {
            pam_syslog(pamh, LOG_ERR, "Username is not set");
            return PAM_SERVICE_ERR;
        }
    }

    pw = pam_shells_getpwnam(pamh, opt, userName);
    if (!pw)
    {
        pam_syslog(pamh, LOG_ERR, "User %s not in %s", userName, opt->pwfile);
        return PAM_AUTH_ERR;		/* user doesn't exist */
    }
    userShell = pw->pw_shell;

    if (stat(opt->shellfile,&sb))
    {
        pam_syslog(pamh, LOG_ERR, "Cannot stat %s: %m", opt->shellfile);
        return PAM_AUTH_ERR;		/* must have /etc/shells */
    }

    if ((sb.st_mode & S_IWOTH) || !S_ISREG(sb.st_mode))
    {
        pam_syslog(pamh, LOG_ERR,
                   "%s is either world writable or not a normal file",
                   opt->shellfile);
        return PAM_AUTH_ERR;
    }

    /* Check that we opened it successfully */
    shellFile = fopen(opt->shellfile,"r");
    if (shellFile == NULL)
    {
        pam_syslog(pamh, LOG_ERR, "Error opening %s: %m", opt->shellfile);
        return PAM_SERVICE_ERR;
    }

    retval = 1;
    while(retval && (fgets(shellFileLine, 255, shellFile) != NULL))
    {
        /*
         *
         *  Ignore lines that begin with a '#'
         *
         */
        if (shellFileLine[strlen(shellFileLine) - 1] == '\n')
        {
            shellFileLine[strlen(shellFileLine) - 1] = '\0';
        }

        retval = strcmp(shellFileLine, userShell);
    }
    fclose(shellFile);

    if (retval)
    {
        pam_syslog(pamh, LOG_ERR, "User shell is invalid %s", userShell);
        return PAM_AUTH_ERR;
    }
    else
    {
        return PAM_SUCCESS;
    }
}

/* --- authentication management functions (only) --- */

int pam_sm_authenticate(pam_handle_t  *pamh,
                        int            flags UNUSED,
                        int            argc,
                        const char   **argv)
{
    struct pam_shells_options  opt;
    int                        rc;

    rc = pam_shells_parse_options(pamh,
                                  argc,
                                  argv,
                                  &opt);
    if (rc != PAM_SUCCESS)
    {
        return(rc);
    }

    return( perform_check(pamh,
                          &opt) );
}

int pam_sm_setcred(pam_handle_t  *pamh  UNUSED,
                   int            flags UNUSED,
                   int            argc  UNUSED,
                   const char   **argv  UNUSED)
{
     return PAM_SUCCESS;
}

/* --- account management functions (only) --- */

int pam_sm_acct_mgmt(pam_handle_t  *pamh,
                     int            flags UNUSED,
                     int            argc,
                     const char   **argv)
{
    struct pam_shells_options  opt;
    int                        rc;

    rc = pam_shells_parse_options(pamh,
                                  argc,
                                  argv,
                                  &opt);
    if (rc != PAM_SUCCESS)
    {
        return(rc);
    }

    return( perform_check(pamh,
                          &opt) );
}

/* end of module definition */
