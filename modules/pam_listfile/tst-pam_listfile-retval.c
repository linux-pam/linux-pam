/*
 * Check pam_listfile return values.
 *
 * Copyright (c) 2023 Dmitry V. Levin <ldv@strace.io>
 */

#include "test_assert.h"
#include "pam_inline.h"

#include <errno.h>
#include <limits.h>
#include <pwd.h>
#include <grp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <security/pam_appl.h>

#define MODULE_NAME "pam_listfile"
#define TEST_NAME "tst-" MODULE_NAME "-retval"
#define LIST_FILE TEST_NAME ".list"

static const char service_file[] = TEST_NAME ".service";
static const char list_file[] = LIST_FILE;
static struct pam_conv conv;

static void
check_pam_ruser(const char *user, const char *ruser,
		int auth_ret, int cred_ret, int other_ret)
{
	pam_handle_t *pamh = NULL;

	ASSERT_EQ(PAM_SUCCESS,
		  pam_start_confdir(service_file, user, &conv, ".", &pamh));
	ASSERT_NE(NULL, pamh);
	if (ruser != NULL)
		ASSERT_EQ(PAM_SUCCESS, pam_set_item(pamh, PAM_RUSER, ruser));
	ASSERT_EQ(auth_ret, pam_authenticate(pamh, 0));
	ASSERT_EQ(cred_ret, pam_setcred(pamh, 0));
	ASSERT_EQ(other_ret, pam_acct_mgmt(pamh, 0));
	ASSERT_EQ(other_ret, pam_chauthtok(pamh, 0));
	ASSERT_EQ(other_ret, pam_open_session(pamh, 0));
	ASSERT_EQ(other_ret, pam_close_session(pamh, 0));
	ASSERT_EQ(PAM_SUCCESS, pam_end(pamh, 0));
}

static void
check_pam(const char *user, int auth_ret, int cred_ret, int other_ret)
{
	check_pam_ruser(user, NULL, auth_ret, cred_ret, other_ret);
}

static void
write_service(const char *cwd, const char *auth, const char *account,
	      const char *password, const char *session)
{
	FILE *fp;

	ASSERT_NE(NULL, fp = fopen(service_file, "w"));
	ASSERT_LT(0, fprintf(fp, "#%%PAM-1.0\n"
			     "auth required %s/" LTDIR MODULE_NAME ".so %s\n"
			     "account required %s/" LTDIR MODULE_NAME ".so %s\n"
			     "password required %s/" LTDIR MODULE_NAME ".so %s\n"
			     "session required %s/" LTDIR MODULE_NAME ".so %s\n",
			     cwd, auth, cwd, account,
			     cwd, password, cwd, session));
	ASSERT_EQ(0, fclose(fp));
}

static void PAM_FORMAT((printf, 2, 3))
write_service_all(const char *cwd, const char *format, ...)
{
	va_list args;
	char *options;

	va_start(args, format);
	ASSERT_LE(0, vasprintf(&options, format, args));
	va_end(args);
	write_service(cwd, options, options, options, options);
	free(options);
}

static void PAM_FORMAT((printf, 1, 2))
write_list(const char *format, ...)
{
	va_list args;
	FILE *fp;

	ASSERT_NE(NULL, fp = fopen(list_file, "w"));
	va_start(args, format);
	ASSERT_LE(0, vfprintf(fp, format, args));
	va_end(args);
	ASSERT_EQ(0, fclose(fp));
}

struct match_case {
	const char *entries;
	const char *value;
	int matched;
};

/* Exercise real PAM configuration parsing with synthetic remote users. */
static void
check_match(const char *entries, const char *value, int matched, int inline_list)
{
	char cwd[PATH_MAX];
	char *list = NULL;

	ASSERT_NE(NULL, getcwd(cwd, sizeof(cwd)));
	if (inline_list) {
		ASSERT_NE(NULL, list = strdup(entries));
		for (char *p = list; *p; ++p)
			if (*p == '\n')
				*p = ',';
	} else {
		write_list("%s\n", entries);
	}

	for (int deny = 0; deny <= 1; ++deny) {
		int result = matched != deny ? PAM_SUCCESS : PAM_AUTH_ERR;

		write_service_all(cwd, "item=ruser %s=%s sense=%s onerr=fail",
				  inline_list ? "list" : "file",
				  inline_list ? list : list_file,
				  deny ? "deny" : "allow");
		check_pam_ruser("", value, result,
				result == PAM_SUCCESS ? PAM_SUCCESS : PAM_PERM_DENIED,
				result);
	}
	free(list);
}

static void
check_matches(const struct match_case *cases, size_t count, int inline_list)
{
	for (size_t i = 0; i < count; ++i)
		check_match(cases[i].entries, cases[i].value, cases[i].matched, inline_list);
}

static void
check_patterns(int inline_list)
{
	static const struct match_case cases[] = {
		{ "DOMAIN\\alice", "DOMAIN\\alice", 1 },
		{ "DOMAIN\\alice", "DOMAINalice", 0 },
		{ "DOMAIN\\*", "DOMAIN\\alice", 1 },
		{ "DOMAIN\\*", "DOMAINalice", 0 },
		{ "DOMAIN\\*", "DOMAIN*", 0 },
		{ "trailing\\", "trailing\\", 1 },
		{ "trailing\\", "trailing", 0 },
		{ "[*]", "*", 1 },
		{ "[?]", "?", 1 },
		{ "[[]", "[", 1 },
		{ "/home/*", "/home/a/b", 1 },
		{ "*", ".hidden", 1 },
		{ "alice", "malice", 0 },
		{ "alice", "alices", 0 },
	};

	check_matches(cases, PAM_ARRAY_SIZE(cases), inline_list);
}

static void
check_negation(int inline_list)
{
	static const struct match_case cases[] = {
		/* Exact matches outrank globs in either order. */
		{ "ftp*\n!ftpadmin", "ftpadmin", 0 },
		{ "!ftpadmin\nftp*", "ftpadmin", 0 },
		{ "!ftp*\nftpadmin", "ftpadmin", 1 },
		{ "ftpadmin\n!ftp*", "ftpadmin", 1 },
		/* Within each priority level, the first match wins. */
		{ "ftpadmin\n!ftpadmin", "ftpadmin", 1 },
		{ "!ftpadmin\nftpadmin", "ftpadmin", 0 },
		{ "ftp*\n!ftp?*", "ftpadmin", 1 },
		{ "!ftp?*\nftp*", "ftpadmin", 0 },
		{ "!ftp?*\nftp*\nftpadmin", "ftpadmin", 1 },
		{ "ftp*\n!ftp?*\n!ftpadmin", "ftpadmin", 0 },
		{ "ftp*\n!ftpadmin\nftpadmin", "ftpadmin", 0 },
		{ "!ftp*\nftpadmin\n!ftpadmin", "ftpadmin", 1 },
		/* Bracket expressions remain globs, even for a single literal. */
		{ "ftp*\n![f]tpadmin", "ftpadmin", 1 },
		{ "![f]tpadmin\nftp*", "ftpadmin", 0 },
		{ "![f]tpadmin\nftpadmin", "ftpadmin", 1 },
		{ "[f]tpadmin\n!ftpadmin", "ftpadmin", 0 },
		{ "ftp*\n!ftpadmin", "ftpuser", 1 },
		{ "!ftpadmin", "ftpuser", 0 },
		{ "ftp*\n!ftpadmin", "other", 0 },
		{ "ftp*\n!other", "ftpadmin", 1 },
		{ "ftp*\n!ftp*", "ftpuser", 1 },
		{ "DOMAIN\\*\n!DOMAIN\\admin", "DOMAIN\\admin", 0 },
		{ "!DOMAIN\\admin\nDOMAIN\\*", "DOMAIN\\admin", 0 },
		{ "DOMAIN\\*\n!DOMAIN\\admin", "DOMAIN\\alice", 1 },
		{ "!DOMAIN\\*\nDOMAIN\\admin", "DOMAIN\\admin", 1 },
		{ "*\n!DOMAIN\\admin", "DOMAINadmin", 1 },
	};

	check_matches(cases, PAM_ARRAY_SIZE(cases), inline_list);
}

int
main(void)
{
	FILE *fp;

	char cwd[PATH_MAX];
	ASSERT_NE(NULL, getcwd(cwd, sizeof(cwd)));

	struct passwd *pw;
	ASSERT_NE(NULL, (pw = getpwuid(geteuid())));

	struct group *gr;
	ASSERT_NE(NULL, (gr = getgrgid(getegid())));

	/* invalid onerr= specified */
	write_service(cwd, "onerr", "onerr=", "onerr=0", "onerr=1");
	check_pam("", PAM_SERVICE_ERR, PAM_PERM_DENIED, PAM_SERVICE_ERR);

	/* unknown option, implicit onerr=fail */
	write_service(cwd, "one=1", "two=2", "three=3", "four=4");
	check_pam("", PAM_SERVICE_ERR, PAM_PERM_DENIED, PAM_SERVICE_ERR);

	/* unknown option, onerr=succeed after unknown option */
	write_service(cwd, "one=1 onerr=succeed",
		      "two=2 onerr=succeed",
		      "three=3 onerr=succeed",
		      "four=4 onerr=succeed");
	check_pam("", PAM_SERVICE_ERR, PAM_PERM_DENIED, PAM_SERVICE_ERR);

	/* unknown option, onerr=succeed before unknown option */
	write_service(cwd, "onerr=succeed one=1",
		      "onerr=succeed two=2",
		      "onerr=succeed three=3",
		      "onerr=succeed four=4");
	check_pam("", PAM_SUCCESS, PAM_SUCCESS, PAM_SUCCESS);

	/* no item= or invalid item= specified, implicit onerr=fail */
	write_service(cwd, "", "item", "item=", "item=bad");
	check_pam("", PAM_SERVICE_ERR, PAM_PERM_DENIED, PAM_SERVICE_ERR);

	/* no item= or invalid item= specified, explicit onerr=fail */
	write_service(cwd, "onerr=fail",
		      "onerr=fail item",
		      "onerr=fail item=",
		      "onerr=fail item=bad");
	check_pam("", PAM_SERVICE_ERR, PAM_PERM_DENIED, PAM_SERVICE_ERR);

	/* no item= or invalid item= specified, onerr=succeed */
	write_service(cwd, "onerr=succeed",
		      "onerr=succeed item",
		      "onerr=succeed item=",
		      "onerr=succeed item=bad");
	check_pam("", PAM_SUCCESS, PAM_SUCCESS, PAM_SUCCESS);

	/* no file= specified, implicit onerr=fail */
	write_service(cwd, "item=user", "item=group", "item=ruser", "item=rhost");
	check_pam("", PAM_SERVICE_ERR, PAM_PERM_DENIED, PAM_SERVICE_ERR);

	/* no file= specified, onerr=succeed */
	write_service(cwd, "onerr=succeed item=user",
		      "onerr=succeed item=group",
		      "onerr=succeed item=ruser",
		      "onerr=succeed item=rhost");
	check_pam("", PAM_SUCCESS, PAM_SUCCESS, PAM_SUCCESS);

	/* no sense= or invalid sense= specified, implicit onerr=fail */
	write_service(cwd, "item=user file=.",
		      "item=group file=. sense",
		      "item=shell file=. sense=",
		      "item=tty file=. sense=bad");
	check_pam("", PAM_SERVICE_ERR, PAM_PERM_DENIED, PAM_SERVICE_ERR);

	/* no sense= or invalid sense= specified, onerr=succeed */
	write_service(cwd, "onerr=succeed item=user file=.",
		      "onerr=succeed item=group file=. sense",
		      "onerr=succeed item=shell file=. sense=",
		      "onerr=succeed item=tty file=. sense=bad");
	check_pam("", PAM_SUCCESS, PAM_SUCCESS, PAM_SUCCESS);

	/* invalid apply= specified, implicit onerr=fail */
	write_service(cwd, "item=ruser file=. sense=allow apply=",
		      "item=rhost file=. sense=allow apply=",
		      "item=tty file=. sense=allow apply=@",
		      "item=tty file=. sense=allow apply=");
	check_pam("", PAM_SERVICE_ERR, PAM_PERM_DENIED, PAM_SERVICE_ERR);

	/* invalid apply= specified, onerr=succeed */
	write_service(cwd, "onerr=succeed item=ruser file=. sense=allow apply=",
		      "onerr=succeed item=rhost file=. sense=allow apply=",
		      "onerr=succeed item=tty file=. sense=allow apply=@",
		      "onerr=succeed item=tty file=. sense=allow apply=");
	check_pam("", PAM_SUCCESS, PAM_SUCCESS, PAM_SUCCESS);

	/* PAM_IGNORE -> PAM_PERM_DENIED */
	write_service(cwd, "item=rhost file=. sense=allow apply=:",
		      "item=tty file=. sense=allow apply=@:",
		      "item=rhost file=. sense=allow apply=:",
		      "item=tty file=. sense=allow apply=@:");
	check_pam(pw->pw_name, PAM_PERM_DENIED, PAM_PERM_DENIED, PAM_PERM_DENIED);

	/* item not set, sense=allow */
	ASSERT_NE(NULL, fp = fopen(service_file, "w"));
	ASSERT_LT(0, fprintf(fp, "#%%PAM-1.0\n"
			     "auth required %s/" LTDIR "%s.so item=rhost file=. sense=allow apply=%s\n"
			     "account required %s/" LTDIR "%s.so item=tty file=. sense=allow apply=%s\n"
			     "password required %s/" LTDIR "%s.so item=rhost file=. sense=allow apply=@%s\n"
			     "session required %s/" LTDIR "%s.so item=tty file=. sense=allow apply=@%s\n",
			     cwd, MODULE_NAME, pw->pw_name,
			     cwd, MODULE_NAME, pw->pw_name,
			     cwd, MODULE_NAME, gr->gr_name,
			     cwd, MODULE_NAME, gr->gr_name));
	ASSERT_EQ(0, fclose(fp));
	check_pam(pw->pw_name, PAM_AUTH_ERR, PAM_PERM_DENIED, PAM_AUTH_ERR);

	/* item not set, sense=deny */
	write_service(cwd, "item=ruser file=. sense=deny",
		      "item=rhost file=. sense=deny",
		      "item=tty file=. sense=deny",
		      "item=ruser file=. sense=deny");
	check_pam(pw->pw_name, PAM_SUCCESS, PAM_SUCCESS, PAM_SUCCESS);

	/* file does not exist, not a regular file, or world writable */
	write_service(cwd, "item=user file= sense=allow",
		      "item=user file=. sense=allow onerr=succeed",
		      "item=user file=/ sense=allow onerr=succeed",
		      "item=user file=/dev/null sense=allow onerr=succeed");
	check_pam(pw->pw_name, PAM_SERVICE_ERR, PAM_PERM_DENIED, PAM_AUTH_ERR);

	/* item is listed, sense=allow */
	write_service_all(cwd, "item=user file=" LIST_FILE " sense=allow");
	write_list("%s\n", pw->pw_name);
	check_pam(pw->pw_name, PAM_SUCCESS, PAM_SUCCESS, PAM_SUCCESS);

	/* item is listed, sense=deny */
	write_service_all(cwd, "item=user file=" LIST_FILE " sense=deny");
	write_list("%s\n", pw->pw_name);
	check_pam(pw->pw_name, PAM_AUTH_ERR, PAM_PERM_DENIED, PAM_AUTH_ERR);

	/* item is listed with whitespace and comments, sense=allow */
	write_service_all(cwd, "item=user file=" LIST_FILE " sense=allow");
	write_list("# This is a comment\n"
		   "\t # Indented comment\n"
		   "  %s\t \n", pw->pw_name);
	check_pam(pw->pw_name, PAM_SUCCESS, PAM_SUCCESS, PAM_SUCCESS);

	/* item is commented out, sense=allow */
	write_service_all(cwd, "item=user file=" LIST_FILE " sense=allow");
	write_list("# %s\n\t # %s\n", pw->pw_name, pw->pw_name);
	check_pam(pw->pw_name, PAM_AUTH_ERR, PAM_PERM_DENIED, PAM_AUTH_ERR);

	/* item=home is listed, sense=allow */
	write_service_all(cwd, "item=home file=" LIST_FILE " sense=allow");
	write_list("%s\n", pw->pw_dir);
	check_pam(pw->pw_name, PAM_SUCCESS, PAM_SUCCESS, PAM_SUCCESS);

	/* item=home is listed, sense=deny */
	write_service_all(cwd, "item=home file=" LIST_FILE " sense=deny");
	write_list("%s\n", pw->pw_dir);
	check_pam(pw->pw_name, PAM_AUTH_ERR, PAM_PERM_DENIED, PAM_AUTH_ERR);

	/* item matches glob pattern, sense=allow */
	write_service_all(cwd, "item=user file=" LIST_FILE " sense=allow");
	write_list("%c*\n", pw->pw_name[0]);
	check_pam(pw->pw_name, PAM_SUCCESS, PAM_SUCCESS, PAM_SUCCESS);

	/* item does not match glob pattern, sense=allow */
	write_service_all(cwd, "item=user file=" LIST_FILE " sense=allow");
	write_list("%s*%s\n", pw->pw_name, pw->pw_name);
	check_pam(pw->pw_name, PAM_AUTH_ERR, PAM_PERM_DENIED, PAM_AUTH_ERR);

	check_patterns(0);

	/* negated item match, sense=deny: negation means not listed */
	write_service_all(cwd, "item=user file=" LIST_FILE " sense=deny");
	write_list("!%s\n", pw->pw_name);
	check_pam(pw->pw_name, PAM_SUCCESS, PAM_SUCCESS, PAM_SUCCESS);

	/* negated non-matching entry does not affect result */
	write_service_all(cwd, "item=user file=" LIST_FILE " sense=allow");
	write_list("!%s%s\n%s\n", pw->pw_name, pw->pw_name, pw->pw_name);
	check_pam(pw->pw_name, PAM_SUCCESS, PAM_SUCCESS, PAM_SUCCESS);

	check_negation(0);

	/* inline list match, sense=allow */
	write_service_all(cwd, "item=user list=%s sense=allow", pw->pw_name);
	check_pam(pw->pw_name, PAM_SUCCESS, PAM_SUCCESS, PAM_SUCCESS);

	/* inline list non-match, sense=allow */
	write_service_all(cwd, "item=user list=: sense=allow");
	check_pam(pw->pw_name, PAM_AUTH_ERR, PAM_PERM_DENIED, PAM_AUTH_ERR);

	/* inline list with negation, sense=deny */
	write_service_all(cwd, "item=user list=!%s sense=deny", pw->pw_name);
	check_pam(pw->pw_name, PAM_SUCCESS, PAM_SUCCESS, PAM_SUCCESS);

	/* inline list with glob pattern, sense=allow */
	write_service_all(cwd, "item=user list=%c* sense=allow", pw->pw_name[0]);
	check_pam(pw->pw_name, PAM_SUCCESS, PAM_SUCCESS, PAM_SUCCESS);

	check_patterns(1);
	check_negation(1);

	/* item is not listed, sense=allow */
	write_service_all(cwd, "item=user file=" LIST_FILE " sense=allow");
	write_list(":\n");
	check_pam(pw->pw_name, PAM_AUTH_ERR, PAM_PERM_DENIED, PAM_AUTH_ERR);

	/* item is not listed, sense=deny */
	write_service_all(cwd, "item=user file=" LIST_FILE " sense=deny");
	write_list(":\n");
	check_pam(pw->pw_name, PAM_SUCCESS, PAM_SUCCESS, PAM_SUCCESS);

	/* Perform a test dedicated to configuration file parsing. */
	ASSERT_NE(NULL, fp = fopen(service_file, "w"));
	ASSERT_LT(0, fprintf(fp, "#%%PAM-1.0\n"
			     "# support line continuations, ignore escaped newlines in comments \\\n"
			     "auth required \\\n"
			     "     %s/" LTDIR "%s.so \\  \n"
			     "     item=user \\\t\t\n"
			     "     file=%s \\ \t \t\n"
			     "     sense=deny\n"
			     "\t \t # allow unneeded whitespace, ignore escaped newlines in comments \\ \n"
			     "   account\t required  %s/" LTDIR "%s.so item=user file=%s sense=deny%c\\\n"
			     "line after NUL byte continues up to here\n"
			     "# trim trailing comments, ignore escaped newlines in comments \\\t\n"
			     "password required %s/" LTDIR "%s.so item=user file=%s sense=deny # foo=bar\n"
			     "# support %*s long lines\n"
			     "session required %*s/" LTDIR "%s.so item=user file=%s sense=deny",
			     cwd, MODULE_NAME, list_file,
			     cwd, MODULE_NAME, list_file, '\0',
			     cwd, MODULE_NAME, list_file,
			     8192, " ",
			     65536, cwd, MODULE_NAME, list_file));
	ASSERT_EQ(0, fclose(fp));
	check_pam(pw->pw_name, PAM_SUCCESS, PAM_SUCCESS, PAM_SUCCESS);

	/* group glob pattern match */
	write_service_all(cwd, "item=group file=" LIST_FILE " sense=allow onerr=fail");
	write_list("%c*\n", gr->gr_name[0]);
	check_pam(pw->pw_name, PAM_SUCCESS, PAM_SUCCESS, PAM_SUCCESS);

	ASSERT_EQ(0, unlink(list_file));
	ASSERT_EQ(0, unlink(service_file));

	return 0;
}
