/*
 * pam_limit_ssh module
 *
 * Written by Paul Schou <github.com/pschou> 2022/12/8
 */

#include "config.h"
#include <syslog.h>
#include <glob.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

/* SSHD processes from globbed exe links. */
#define PROC_GLOB            "/proc/[0-9]*/cmdline"
#define PROC_CMDLINE         "cmdline"
#define PROC_CMDLINE_PREFIX  "sshd: "
#define PROC_CMDLINE_SUFFIX  "@"

/* --- authentication management functions --- */

int
pam_sm_authenticate(pam_handle_t *pamh, int flags UNUSED,
        int argc, const char **argv)
{
    const char* user;
    // parse the user
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_NOTICE, "cannot determine user name");
        return PAM_SESSION_ERR;
    }

    glob_t globbuf;
    int glob_rv = glob(PROC_GLOB, GLOB_ERR | GLOB_NOSORT, NULL, &globbuf);
    char buf[2048];
    ssize_t buf_len, buf_pos;
    FILE *cmdfile;
    //const char *sshd_path;

    unsigned int i, ssh_count, ssh_max;
    ssh_max = 10;
    //sshd_path = "/usr/sbin/sshd";

    // parse the args to find max and sshd process
    for (; argc-- > 0; ++argv) {
        if (strncmp(*argv, "max=", 4) == 0) {
            i = atoi(*argv+4);
            if (i > 0)
                ssh_max = i;
    //    } else if (strncmp(*argv, "sshd=", 4) == 0) {
    //        sshd_path = *argv + 5;
        }
    }

    ssh_count = 0;
    if (glob_rv == 0) {
        for (i = 0; i < globbuf.gl_pathc; i++) {
            // step through the /proc/#/cmdline list

            // open the file and read it in
            cmdfile = fopen(globbuf.gl_pathv[i], "r");
            if(cmdfile == NULL) // continue if file is not readable
                continue;
            buf_len = fread(buf, sizeof(char), sizeof(buf), cmdfile);
            fclose(cmdfile);

            // compare the content with the PREFIX, USER, SUFFIX
            buf_pos = strlen(PROC_CMDLINE_PREFIX);
            if (buf_pos > buf_len-2 || strncmp(buf, PROC_CMDLINE_PREFIX, buf_pos) != 0)
                continue;
            if (buf_pos + (int)strlen(user) >  buf_len-2 || strncmp(buf+buf_pos, user, strlen(user)) != 0)
                continue;
            buf_pos = buf_pos + strlen(user);
            if (strncmp(buf+buf_pos, PROC_CMDLINE_SUFFIX, strlen(PROC_CMDLINE_SUFFIX)) != 0)
                continue;
            buf_pos = buf_pos + strlen(PROC_CMDLINE_SUFFIX);

            // count the session
            ssh_count++;

            // count any additional sub sessions
            for (; buf_pos < buf_len; buf_pos++)
                if (buf[buf_pos] == ',')
                     ssh_count++;
        }
        pam_syslog(pamh, LOG_NOTICE, "user %s, current %d, max %d", user, ssh_count, ssh_max);

        globfree(&globbuf);
        if (ssh_count >= ssh_max) {
            return PAM_AUTH_ERR;
        }
    } else {
        pam_syslog(pamh, LOG_NOTICE, "unable to list /proc/*/cmdline for sshd processes");
        return PAM_AUTH_ERR;
    }
    return PAM_SUCCESS;
}

int
pam_sm_setcred(pam_handle_t *pamh, int flags,
         int argc, const char **argv)
{
    if (pam_sm_authenticate(pamh, flags, argc, argv) == PAM_SUCCESS)
        return PAM_SUCCESS;
    return PAM_CRED_ERR;
}

/* --- account management functions --- */

int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
     int argc, const char **argv)
{
    if (pam_sm_authenticate(pamh, flags, argc, argv) == PAM_SUCCESS)
        return PAM_SUCCESS;
    return PAM_AUTH_ERR;
}

/* --- password management --- */

int
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
     int argc, const char **argv)
{
    if (pam_sm_authenticate(pamh, flags, argc, argv) == PAM_SUCCESS)
        return PAM_SUCCESS;
    return PAM_AUTHTOK_ERR;
}

/* --- session management --- */

int
pam_sm_open_session(pam_handle_t *pamh, int flags,
        int argc, const char **argv)
{
    if (pam_sm_authenticate(pamh, flags, argc, argv) == PAM_SUCCESS)
        return PAM_SUCCESS;
    return PAM_SESSION_ERR;
}

int
pam_sm_close_session(pam_handle_t *pamh UNUSED, int flags UNUSED,
         int argc UNUSED, const char **argv UNUSED)
{
    return PAM_SUCCESS;
}

/* end of module definition */
