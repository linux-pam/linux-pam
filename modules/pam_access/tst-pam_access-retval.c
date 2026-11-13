/*
 * Check pam_access return values, in particular correct handling of the
 * last line of the access file when it is not terminated by a newline.
 *
 * Copyright (c) 2026 Thorsten Kukuk <kukuk@suse.com>
 */

#include "test_assert.h"

#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <security/pam_appl.h>

#define MODULE_NAME "pam_access"
#define TEST_NAME "tst-" MODULE_NAME "-retval"

static const char service_file[] = TEST_NAME ".service";
static const char access_file[] = TEST_NAME ".access";
static struct pam_conv conv;

static void
write_access_file(const char *data, size_t len)
{
	FILE *fp;

	ASSERT_NE(NULL, fp = fopen(access_file, "w"));
	ASSERT_EQ(len, fwrite(data, 1, len, fp));
	ASSERT_EQ(0, fclose(fp));
}

static void
write_service_file(const char *cwd)
{
	FILE *fp;

	ASSERT_NE(NULL, fp = fopen(service_file, "w"));
	ASSERT_LT(0, fprintf(fp, "#%%PAM-1.0\n"
			     "auth required %s/" LTDIR "%s.so accessfile=%s\n"
			     "account required %s/" LTDIR "%s.so accessfile=%s\n"
			     "password required %s/" LTDIR "%s.so accessfile=%s\n"
			     "session required %s/" LTDIR "%s.so accessfile=%s\n",
			     cwd, MODULE_NAME, access_file,
			     cwd, MODULE_NAME, access_file,
			     cwd, MODULE_NAME, access_file,
			     cwd, MODULE_NAME, access_file));
	ASSERT_EQ(0, fclose(fp));
}

static void
check(const char *user, int expected)
{
	pam_handle_t *pamh = NULL;

	ASSERT_EQ(PAM_SUCCESS,
		  pam_start_confdir(service_file, user, &conv, ".", &pamh));
	ASSERT_NE(NULL, pamh);
	ASSERT_EQ(expected, pam_authenticate(pamh, 0));
	ASSERT_EQ(PAM_PERM_DENIED, pam_setcred(pamh, 0));
	ASSERT_EQ(expected, pam_acct_mgmt(pamh, 0));
	ASSERT_EQ(expected, pam_chauthtok(pamh, 0));
	ASSERT_EQ(expected, pam_open_session(pamh, 0));
	ASSERT_EQ(expected, pam_close_session(pamh, 0));
	ASSERT_EQ(PAM_SUCCESS, pam_end(pamh, 0));
}

int
main(void)
{
	char cwd[PATH_MAX];
	ASSERT_NE(NULL, getcwd(cwd, sizeof(cwd)));

	struct passwd *pw;
	ASSERT_NE(NULL, (pw = getpwuid(geteuid())));

	write_service_file(cwd);

	/*
	 * Regression test: a sole deny rule on the last line of the access
	 * file must be honored even without a trailing newline.  Before the
	 * fix, getline() returning the final line without '\n' caused the
	 * rule to be skipped entirely, so no rule matched and access was
	 * granted instead of denied.
	 */
	char rule[LINE_MAX];
	int len = snprintf(rule, sizeof(rule), "-:%s:ALL", pw->pw_name);
	ASSERT_LT(0, len);
	write_access_file(rule, (size_t) len);
	check(pw->pw_name, PAM_PERM_DENIED);

	/* Control: same rule, but with a trailing newline. */
	rule[len] = '\n';
	write_access_file(rule, (size_t) len + 1);
	check(pw->pw_name, PAM_PERM_DENIED);

	/*
	 * A deny rule on the last, newline-less line must still be found
	 * when it is not the only line in the file.
	 */
	char multi[LINE_MAX];
	int mlen = snprintf(multi, sizeof(multi),
			     "+:no-such-user:ALL\n-:%s:ALL", pw->pw_name);
	ASSERT_LT(0, mlen);
	write_access_file(multi, (size_t) mlen);
	check(pw->pw_name, PAM_PERM_DENIED);

	/* An allow rule on the last, newline-less line must still match. */
	int alen = snprintf(multi, sizeof(multi),
			     "+:%s:ALL", pw->pw_name);
	ASSERT_LT(0, alen);
	write_access_file(multi, (size_t) alen);
	check(pw->pw_name, PAM_SUCCESS);

	/*
	 * A malformed last line without a trailing newline must still be
	 * rejected for having the wrong field count, not accidentally
	 * accepted now that the newline requirement is gone.
	 */
	int blen = snprintf(multi, sizeof(multi),
			     "+:no-such-user:ALL\nbadline-with-no-colons");
	ASSERT_LT(0, blen);
	write_access_file(multi, (size_t) blen);
	check(pw->pw_name, PAM_SUCCESS);

	/* A comment as the last, newline-less line must still be ignored. */
	int clen = snprintf(multi, sizeof(multi),
			     "+:no-such-user:ALL\n# trailing comment");
	ASSERT_LT(0, clen);
	write_access_file(multi, (size_t) clen);
	check(pw->pw_name, PAM_SUCCESS);

	/* A blank last line without a trailing newline must be skipped. */
	int wlen = snprintf(multi, sizeof(multi),
			     "+:no-such-user:ALL\n   ");
	ASSERT_LT(0, wlen);
	write_access_file(multi, (size_t) wlen);
	check(pw->pw_name, PAM_SUCCESS);

	ASSERT_EQ(0, unlink(access_file));
	ASSERT_EQ(0, unlink(service_file));

	return 0;
}
