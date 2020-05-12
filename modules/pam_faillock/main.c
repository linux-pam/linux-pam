/*
 * Copyright (c) 2010 Tomas Mraz <tmraz@redhat.com>
 * Copyright (c) 2010 Red Hat, Inc.
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
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <pwd.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef HAVE_LIBAUDIT
#include <libaudit.h>

#define AUDIT_NO_ID     ((unsigned int) -1)
#endif

#include "faillock.h"

struct options {
	unsigned int reset;
	const char *dir;
	const char *user;
	const char *progname;
};

static int
args_parse(int argc, char **argv, struct options *opts)
{
	int i;
	memset(opts, 0, sizeof(*opts));

	opts->dir = FAILLOCK_DEFAULT_TALLYDIR;
	opts->progname = argv[0];

	for (i = 1; i < argc; ++i) {

		if (strcmp(argv[i], "--dir") == 0) {
			++i;
			if (i >= argc || strlen(argv[i]) == 0) {
				fprintf(stderr, "%s: No directory supplied.\n", argv[0]);
				return -1;
			}
		        opts->dir = argv[i];
		}
		else if (strcmp(argv[i], "--user") == 0) {
			++i;
			if (i >= argc || strlen(argv[i]) == 0) {
				fprintf(stderr, "%s: No user name supplied.\n", argv[0]);
				return -1;
			}
		        opts->user = argv[i];
		}
		else if (strcmp(argv[i], "--reset") == 0) {
			opts->reset = 1;
		}
		else {
			fprintf(stderr, "%s: Unknown option: %s\n", argv[0], argv[i]);
			return -1;
		}
	}
	return 0;
}

static void
usage(const char *progname)
{
	fprintf(stderr, _("Usage: %s [--dir /path/to/tally-directory] [--user username] [--reset]\n"),
		progname);
}

static int
do_user(struct options *opts, const char *user)
{
	int fd;
	int rv;
	struct tally_data tallies;
	struct passwd *pwd;

	pwd = getpwnam(user);

	fd = open_tally(opts->dir, user, pwd != NULL ? pwd->pw_uid : 0, 0);

	if (fd == -1) {
		if (errno == ENOENT) {
			return 0;
		}
		else {
			fprintf(stderr, "%s: Error opening the tally file for %s:",
				opts->progname, user);
			perror(NULL);
			return 3;
		}
	}
	if (opts->reset) {
#ifdef HAVE_LIBAUDIT
		int audit_fd;
#endif

		while ((rv=ftruncate(fd, 0)) == -1 && errno == EINTR);
		if (rv == -1) {
			fprintf(stderr, "%s: Error clearing the tally file for %s:",
				opts->progname, user);
			perror(NULL);
#ifdef HAVE_LIBAUDIT
		}
		if ((audit_fd=audit_open()) >= 0) {
			audit_log_acct_message(audit_fd, AUDIT_USER_MGMT, NULL,
				"faillock-reset", user,
				pwd != NULL ? pwd->pw_uid : AUDIT_NO_ID,
				NULL, NULL, NULL, rv == 0);
			close(audit_fd);
		}
		if (rv == -1) {
#endif
			close(fd);
			return 4;
		}
	}
	else {
		unsigned int i;

		memset(&tallies, 0, sizeof(tallies));
		if ((rv=read_tally(fd, &tallies)) == -1) {
			fprintf(stderr, "%s: Error reading the tally file for %s:",
				opts->progname, user);
			perror(NULL);
			close(fd);
			return 5;
		}

		printf("%s:\n", user);
		printf("%-19s %-5s %-48s %-5s\n", "When", "Type", "Source", "Valid");

		for (i = 0; i < tallies.count; i++) {
			struct tm *tm;
			char timebuf[80];
			uint16_t status = tallies.records[i].status;
			time_t when = tallies.records[i].time;

			tm = localtime(&when);
			strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm);
			printf("%-19s %-5s %-52.52s %s\n", timebuf,
				status & TALLY_STATUS_RHOST ? "RHOST" : (status & TALLY_STATUS_TTY ? "TTY" : "SVC"),
				tallies.records[i].source, status & TALLY_STATUS_VALID ? "V":"I");
		}
		free(tallies.records);
	}
	close(fd);
	return 0;
}

static int
do_allusers(struct options *opts)
{
	struct dirent **userlist;
	int rv, i;

	rv = scandir(opts->dir, &userlist, NULL, alphasort);
	if (rv < 0) {
		fprintf(stderr, "%s: Error reading tally directory: %m\n", opts->progname);
		return 2;
	}

	for (i = 0; i < rv; i++) {
		if (userlist[i]->d_name[0] == '.') {
			if ((userlist[i]->d_name[1] == '.' && userlist[i]->d_name[2] == '\0') ||
			    userlist[i]->d_name[1] == '\0')
				continue;
		}
		do_user(opts, userlist[i]->d_name);
		free(userlist[i]);
	}
	free(userlist);

	return 0;
}


/*-----------------------------------------------------------------------*/
int
main (int argc, char *argv[])
{
	struct options opts;

	if (args_parse(argc, argv, &opts)) {
		usage(argv[0]);
		return 1;
	}

	if (opts.user == NULL) {
		return do_allusers(&opts);
	}

	return do_user(&opts, opts.user);
}
