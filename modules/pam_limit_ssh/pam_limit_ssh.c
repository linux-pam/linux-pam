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
#define PROC_GLOB            "/proc/*/exe"
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
    ssize_t buf_len;
    FILE *cmdfile;
    const char *sshd_path;

    unsigned int i, ssh_count, ssh_max;
    ssh_max = 10;
    sshd_path = "/usr/sbin/sshd";

    // parse the args to find max and sshd process
    for (; argc-- > 0; ++argv) {
        if (strncmp(*argv, "max=", 4) == 0) {
            i = atoi(*argv+4);
            if (i > 0)
                ssh_max = i;
        } else if (strncmp(*argv, "sshd=", 4) == 0) {
            sshd_path = *argv + 5;
        }
    }

    ssh_count = 0;
    if (glob_rv == 0) {
        for (i = 0; i < globbuf.gl_pathc; i++) {
            // step through the /proc/#/exe list
            buf_len = readlink(globbuf.gl_pathv[i], buf, sizeof(buf)-1);
            if (buf_len == -1) { continue; }

            buf[buf_len] = '\0';
            if (strcmp(buf, sshd_path) == 0) {
                // build /proc/#/cmdline filename from the /proc/#/exe path
                for (buf_len = 0; buf_len < (int)(sizeof(buf))-10 && globbuf.gl_pathv[i][buf_len] != 0; buf_len++) {
                    buf[buf_len] = globbuf.gl_pathv[i][buf_len];
                }
                strncpy(buf+buf_len-3, PROC_CMDLINE, 8);
                
                // open the file and read it in
                cmdfile = fopen(buf, "r");
                if(cmdfile == NULL) // continue if file is not readable
                    continue;
                fread(buf, sizeof(char), sizeof(buf), cmdfile);
                fclose(cmdfile);

                // compare the content with the PREFIX, USER, SUFFIX
                buf_len = strlen(PROC_CMDLINE_PREFIX);
                if (buf_len > (int)(sizeof(buf))-2 || strncmp(buf, PROC_CMDLINE_PREFIX, buf_len) != 0)
                    continue;
                if (buf_len + strlen(user) >  sizeof(buf)-2 || strncmp(buf+buf_len, user, strlen(user)) != 0)
                    continue;
                buf_len = buf_len + strlen(user);
                if (strncmp(buf+buf_len, PROC_CMDLINE_SUFFIX, strlen(PROC_CMDLINE_SUFFIX)) != 0)
                    continue;

                // count the session
                ssh_count++;
            }
        }
        pam_syslog(pamh, LOG_NOTICE, "user %s, current %d, max %d", user, ssh_count, ssh_max);

        globfree(&globbuf);
        if (ssh_count >= ssh_max) {
            return PAM_AUTH_ERR;
        }
    } else {
        pam_syslog(pamh, LOG_NOTICE, "unable to list /proc/*/exe for sshd processes");
        return PAM_SESSION_ERR;
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
