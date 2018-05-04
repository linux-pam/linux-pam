/* pam_motd module */

/*
 * Modified for pam_motd by Ben Collins <bcollins@debian.org>
 *
 * Based off of:
 * $Id$
 *
 * Written by Michael K. Johnson <johnsonm@redhat.com> 1996/10/24
 *
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <syslog.h>

#include <security/_pam_macros.h>
#include <security/pam_ext.h>
/*
 * here, we make a definition for the externally accessible function
 * in this file (this definition is required for static a module
 * but strongly encouraged generally) it is used to instruct the
 * modules include file to define the function prototypes.
 */

#define PAM_SM_SESSION
#define DEFAULT_MOTD	"/etc/motd"
#define DEFAULT_MOTD_D	"/etc/motd.d"

#include <security/pam_modules.h>
#include <security/pam_modutil.h>

/* --- session management functions (only) --- */

int
pam_sm_close_session (pam_handle_t *pamh UNUSED, int flags UNUSED,
		      int argc UNUSED, const char **argv UNUSED)
{
     return PAM_IGNORE;
}

static char default_motd[] = DEFAULT_MOTD;
static char default_motd_dir[] = DEFAULT_MOTD_D;

static void try_to_display_fd(pam_handle_t *pamh, int fd)
{
    struct stat st;
    char *mtmp = NULL;

    /* fill in message buffer with contents of motd */
    if ((fstat(fd, &st) < 0) || !st.st_size || st.st_size > 0x10000)
	return;

    if (!(mtmp = malloc(st.st_size+1)))
	return;

    if (pam_modutil_read(fd, mtmp, st.st_size) == st.st_size) {
	if (mtmp[st.st_size-1] == '\n')
	    mtmp[st.st_size-1] = '\0';
	else
	    mtmp[st.st_size] = '\0';

	pam_info (pamh, "%s", mtmp);
    }

    _pam_drop(mtmp);
}

static void try_to_display_directory(pam_handle_t *pamh, const char *dirname)
{
    DIR *dirp;

    dirp = opendir(dirname);

    if (dirp != NULL) {
	struct dirent *entry;

	while ((entry = readdir(dirp))) {
	    int fd = openat(dirfd(dirp), entry->d_name, O_RDONLY);

	    if (fd >= 0) {
		try_to_display_fd(pamh, fd);
		close(fd);
	    }
	}

	closedir(dirp);
    }
}

int pam_sm_open_session(pam_handle_t *pamh, int flags,
			int argc, const char **argv)
{
    int retval = PAM_IGNORE;
    const char *motd_path = NULL;
    const char *motd_dir_path = NULL;

    if (flags & PAM_SILENT) {
	return retval;
    }

    for (; argc-- > 0; ++argv) {
        if (!strncmp(*argv,"motd=",5)) {

            motd_path = 5 + *argv;
            if (*motd_path != '\0') {
                D(("set motd path: %s", motd_path));
	    } else {
		motd_path = NULL;
		pam_syslog(pamh, LOG_ERR,
			   "motd= specification missing argument - ignored");
	    }
	}
	else if (!strncmp(*argv,"motd_dir=",9)) {

            motd_dir_path = 9 + *argv;
            if (*motd_dir_path != '\0') {
                D(("set motd.d path: %s", motd_dir_path));
	    } else {
		motd_dir_path = NULL;
		pam_syslog(pamh, LOG_ERR,
			   "motd_dir= specification missing argument - ignored");
	    }
	}
	else
	    pam_syslog(pamh, LOG_ERR, "unknown option: %s", *argv);
    }

    if (motd_path == NULL && motd_dir_path == NULL) {
	motd_path = default_motd;
	motd_dir_path = default_motd_dir;
    }

    if (motd_path != NULL) {
	int fd = open(motd_path, O_RDONLY, 0);

	if (fd >= 0) {
	    try_to_display_fd(pamh, fd);
	    close(fd);
	}
    }

    if (motd_dir_path != NULL)
	try_to_display_directory(pamh, motd_dir_path);

    return retval;
}

/* end of module definition */
