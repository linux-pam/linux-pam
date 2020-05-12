/*
 * This file implements the following functions:
 *   pam_modutil_sanitize_helper_fds:
 *     redirects standard descriptors, closes all other descriptors.
 */

#include "pam_modutil_private.h"
#include <security/pam_ext.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <sys/resource.h>
#include <dirent.h>
#ifdef HAVE_SYS_VFS_H
#include <sys/vfs.h>
#endif
#ifdef HAVE_LINUX_MAGIC_H
#include <linux/magic.h>
#endif

/*
 * Creates a pipe, closes its write end, redirects fd to its read end.
 * Returns fd on success, -1 otherwise.
 */
static int
redirect_in_pipe(pam_handle_t *pamh, int fd, const char *name)
{
	int in[2];

	if (pipe(in) < 0) {
		pam_syslog(pamh, LOG_ERR, "Could not create pipe: %m");
		return -1;
	}

	close(in[1]);

	if (in[0] == fd)
		return fd;

	if (dup2(in[0], fd) != fd) {
		pam_syslog(pamh, LOG_ERR, "dup2 of %s failed: %m", name);
		fd = -1;
	}

	close(in[0]);
	return fd;
}

/*
 * Opens /dev/null for writing, redirects fd there.
 * Returns fd on success, -1 otherwise.
 */
static int
redirect_out_null(pam_handle_t *pamh, int fd, const char *name)
{
	int null = open("/dev/null", O_WRONLY);

	if (null < 0) {
		pam_syslog(pamh, LOG_ERR, "open of %s failed: %m", "/dev/null");
		return -1;
	}

	if (null == fd)
		return fd;

	if (dup2(null, fd) != fd) {
		pam_syslog(pamh, LOG_ERR, "dup2 of %s failed: %m", name);
		fd = -1;
	}

	close(null);
	return fd;
}

static int
redirect_out(pam_handle_t *pamh, enum pam_modutil_redirect_fd mode,
	     int fd, const char *name)
{
	switch (mode) {
		case PAM_MODUTIL_PIPE_FD:
			if (redirect_in_pipe(pamh, fd, name) < 0)
				return -1;
			break;
		case PAM_MODUTIL_NULL_FD:
			if (redirect_out_null(pamh, fd, name) < 0)
				return -1;
			break;
		case PAM_MODUTIL_IGNORE_FD:
			break;
	}
	return fd;
}

/* Check if path is in a procfs. */
static int
is_in_procfs(int fd)
{
#if defined HAVE_SYS_VFS_H && defined PROC_SUPER_MAGIC
	struct statfs stfs;

	if (fstatfs(fd, &stfs) == 0) {
		if (stfs.f_type == PROC_SUPER_MAGIC)
			return 1;
	} else {
		return 0;
	}
#endif /* HAVE_SYS_VFS_H && PROC_SUPER_MAGIC */

	return -1;
}

/* Closes all descriptors after stderr. */
static void
close_fds(void)
{
	DIR *dir = NULL;
	struct dirent *dent;
	int dfd = -1;
	int fd;
	struct rlimit rlim;

	/*
	 * An arbitrary upper limit for the maximum file descriptor number
	 * returned by RLIMIT_NOFILE.
	 */
	const unsigned int MAX_FD_NO = 65535;

	/* The lower limit is the same as for _POSIX_OPEN_MAX. */
	const unsigned int MIN_FD_NO = 20;

	/* If /proc is mounted, we can optimize which fd can be closed. */
	if ((dir = opendir("/proc/self/fd")) != NULL) {
		if ((dfd = dirfd(dir)) >= 0 && is_in_procfs(dfd) > 0) {
			while ((dent = readdir(dir)) != NULL) {
				fd = atoi(dent->d_name);
				if (fd > STDERR_FILENO && fd != dfd)
					close(fd);
			}
		} else {
			dfd = -1;
		}
		closedir(dir);
	}

	/* If /proc isn't available, fallback to the previous behavior. */
	if (dfd < 0) {
		if (getrlimit(RLIMIT_NOFILE, &rlim) || rlim.rlim_max > MAX_FD_NO)
			fd = MAX_FD_NO;
		else if (rlim.rlim_max < MIN_FD_NO)
			fd = MIN_FD_NO;
		else
			fd = rlim.rlim_max - 1;

		for (; fd > STDERR_FILENO; --fd)
			close(fd);
	}
}

int
pam_modutil_sanitize_helper_fds(pam_handle_t *pamh,
				enum pam_modutil_redirect_fd stdin_mode,
				enum pam_modutil_redirect_fd stdout_mode,
				enum pam_modutil_redirect_fd stderr_mode)
{
	if (stdin_mode != PAM_MODUTIL_IGNORE_FD &&
	    redirect_in_pipe(pamh, STDIN_FILENO, "stdin") < 0) {
		return -1;
	}

	if (redirect_out(pamh, stdout_mode, STDOUT_FILENO, "stdout") < 0)
		return -1;

	/*
	 * If stderr should not be ignored and
	 * redirect mode for stdout and stderr are the same,
	 * optimize by redirecting stderr to stdout.
	 */
	if (stderr_mode != PAM_MODUTIL_IGNORE_FD &&
	    stdout_mode == stderr_mode) {
		if (dup2(STDOUT_FILENO, STDERR_FILENO) != STDERR_FILENO) {
			pam_syslog(pamh, LOG_ERR,
				   "dup2 of %s failed: %m", "stderr");
			return -1;
		}
	} else {
		if (redirect_out(pamh, stderr_mode, STDERR_FILENO, "stderr") < 0)
			return -1;
	}

	close_fds();
	return 0;
}
