/*
 * Check pam_env return values.
 *
 * Copyright (c) 2020-2022 Dmitry V. Levin <ldv@altlinux.org>
 * Copyright (c) 2022 Stefan Schubert <schubi@suse.de>
 */

#include "test_assert.h"

#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <security/pam_appl.h>

#define MODULE_NAME "pam_env"
#define TEST_NAME "tst-" MODULE_NAME "-retval"
#define TEST_NAME_DIR TEST_NAME ".dir"

static const char service_file[] = TEST_NAME ".service";
static const char missing_file[] = TEST_NAME ".missing";
static const char my_conf[] = TEST_NAME ".conf";
static const char my_env[] = TEST_NAME ".env";
static const char bad_conf[] = TEST_NAME ".bad.conf";
static const char envd_reg_root[] = TEST_NAME_DIR "/envd-regression";
static const char envd_reg_env[] = TEST_NAME_DIR "/envd-regression"
				   SYSCONFDIR "/environment";
static const char envd_reg_dir[] = TEST_NAME_DIR "/envd-regression"
				   SYSCONFDIR "/environment.d";
static const char envd_reg_file[] = TEST_NAME_DIR "/envd-regression"
				    SYSCONFDIR "/environment.d/10-defaults.conf";
static const char envd_reg_missing[] = TEST_NAME_DIR "/envd-regression"
				       SYSCONFDIR "/environment.d/00-missing.conf";
#ifdef VENDORDIR
static const char dir_usr_etc_security[] = TEST_NAME_DIR VENDOR_SCONFIG_DIR;
static const char usr_env[] = TEST_NAME_DIR VENDORDIR "/environment";
static const char usr_conf[] = TEST_NAME_DIR VENDOR_SCONFIG_DIR "/pam_env.conf";
static const char envd_root[] = TEST_NAME_DIR "/envd";
static const char envd_usr_dir[] = TEST_NAME_DIR "/envd" VENDORDIR "/environment.d";
static const char envd_etc_dir[] = TEST_NAME_DIR "/envd" SYSCONFDIR "/environment.d";
static const char envd_usr_env[] = TEST_NAME_DIR "/envd" VENDORDIR "/environment";
static const char envd_usr_10[] = TEST_NAME_DIR "/envd" VENDORDIR "/environment.d/10-example.conf";
static const char envd_usr_20[] = TEST_NAME_DIR "/envd" VENDORDIR "/environment.d/20-example.conf";
static const char envd_usr_30[] = TEST_NAME_DIR "/envd" VENDORDIR "/environment.d/30-chain.conf";
static const char envd_usr_40[] = TEST_NAME_DIR "/envd" VENDORDIR "/environment.d/40-chain.conf";
static const char envd_etc_20[] = TEST_NAME_DIR "/envd" SYSCONFDIR "/environment.d/20-example.conf";
static const char envd_etc_50[] = TEST_NAME_DIR "/envd" SYSCONFDIR "/environment.d/50-chain.conf";
#endif

static struct pam_conv conv;

static void
mkdir_p(const char *pathname, mode_t mode)
{
	if (mkdir(pathname, mode) == 0 || errno == EEXIST)
		return;
	ASSERT_EQ(errno, ENOENT);

	char *buf;
	ASSERT_NE(NULL, buf = strdup(pathname));
	mkdir_p(dirname(buf), mode);
	free(buf);

	ASSERT_EQ(0, mkdir(pathname, mode));
}

static void
rmdir_p(const char *pathname)
{
	if (rmdir(pathname) != 0)
		return;

	char *buf;
	ASSERT_NE(NULL, buf = strdup(pathname));
	rmdir_p(dirname(buf));
	free(buf);
}

static void
setup(void)
{
	FILE *fp;

	ASSERT_NE(NULL, fp = fopen(my_conf, "w"));
	ASSERT_LT(0, fprintf(fp,
			     "EDITOR\tDEFAULT=vi DEFAULT= DEFAULT=vim\n"
			     "PAGER\tDEFAULT=more\n"
			     "# ignore escaped newlines in comments \\\n"
			     "NAME\tDEFAULT=@{PAM_\\ \t\n"
			     "USER}\\\\name\n"));
	ASSERT_EQ(0, fclose(fp));

	ASSERT_NE(NULL, fp = fopen(bad_conf, "w"));
	ASSERT_LT(0, fprintf(fp,
			     "GOOD_VAR\tDEFAULT=good\n"
			     "BAD_VAR\tBADOPTION=bad\n"));
	ASSERT_EQ(0, fclose(fp));

	ASSERT_NE(NULL, fp = fopen(my_env, "w"));
	ASSERT_LT(0, fprintf(fp,
			     "test_value=foo\n"
			     "test2_value=bar\n"));
	ASSERT_EQ(0, fclose(fp));

	mkdir_p(envd_reg_dir, 0755);

	ASSERT_NE(NULL, fp = fopen(envd_reg_env, "w"));
	ASSERT_EQ(0, fclose(fp));

	ASSERT_NE(NULL, fp = fopen(envd_reg_file, "w"));
	ASSERT_LT(0, fprintf(fp,
			     "BASE=present\n"
			     "RESULT_SET=${BASE:-fallback}\n"
			     "RESULT_SET_DEFAULT=${BASE-fallback}\n"
			     "RESULT_UNSET=${UNSET:-fallback}\n"
			     "RESULT_UNSET_DEFAULT=${UNSET-fallback}\n"
			     "URL=${SUNSET:-https://example.test/{name}/file}\n"
			     "NESTED=${UNSET:-${ALSO_UNSET:-fallback}}\n"
			     "ESCAPED_SPACE=foo\\ \n"
			     "EVEN_BACKSLASHES=foo\\\\ \n"
			     "TRAILING_SPACE=foo \t\r\n"
			     "EMPTY=\n"
			     "RESULT_EMPTY=${EMPTY:-fallback}\n"
			     "RESULT_EMPTY_DEFAULT=${EMPTY-fallback}\n"
			     "TOO_DEEP=original\n"
			     "TOO_DEEP=${A:-${B:-${C:-${D:-${E:-${F:-${G:-${H:-${I:-${J:-${K:-${L:-${M:-${N:-${O:-${P:-${Q:-too deep}}}}}}}}}}}}}}}}}\n"
			     "AFTER_TOO_DEEP=present\n"
			     "# Example: VALUE=\"\n"
			     "RESULT_AFTER_QUOTE_COMMENT=present\n"
			     "; Example: VALUE=\"\n"
			     "RESULT_AFTER_SEMICOLON_QUOTE_COMMENT=present\n"
			     "# Example: VALUE=\\\n"
			     "RESULT_AFTER_BACKSLASH_COMMENT=present\n"
			     "; Example: VALUE=\\\n"
			     "RESULT_AFTER_SEMICOLON_BACKSLASH_COMMENT=present\n"
			     "CONTINUED=first\\\n"
			     "second\n"));
	ASSERT_EQ(0, fclose(fp));
	ASSERT_EQ(0, symlink("missing-target.conf", envd_reg_missing));

#ifdef VENDORDIR
	mkdir_p(dir_usr_etc_security, 0755);

	ASSERT_NE(NULL, fp = fopen(usr_env, "w"));
	ASSERT_LT(0, fprintf(fp,
			     "usr_etc_test=foo\n"
			     "usr_etc_test2=bar\n"));
	ASSERT_EQ(0, fclose(fp));

	ASSERT_NE(NULL, fp = fopen(usr_conf, "w"));
	ASSERT_LT(0, fprintf(fp,
			     "PAGER		DEFAULT=emacs\n"
			     "MANPAGER		DEFAULT=less\n"));
	ASSERT_EQ(0, fclose(fp));
#endif

#ifdef VENDORDIR
	mkdir_p(envd_usr_dir, 0755);
	mkdir_p(envd_etc_dir, 0755);

	ASSERT_NE(NULL, fp = fopen(envd_usr_env, "w"));
	ASSERT_LT(0, fprintf(fp, "PATH=/usr/bin\n"));
	ASSERT_EQ(0, fclose(fp));

	ASSERT_NE(NULL, fp = fopen(envd_usr_10, "w"));
	ASSERT_LT(0, fprintf(fp,
			     "TEST=\"example var\"\n"
			     "PATH=\"/my/custom/path:${PATH}\"\n"
			     "LITERAL=\"$$TEST\"\n"
			     "FALLBACK_DEFAULT=\"${UNSET:-default}\"\n"
			     "BASE=present\n"
			     "FALLBACK_SET=\"${BASE:-fallback}\"\n"
			     "EMPTY=\n"
			     "FALLBACK_EMPTY=\"${EMPTY:-fallback}\"\n"
			     "CONTINUED=first\\\n"
			     "second\n"));
	ASSERT_EQ(0, fclose(fp));

	ASSERT_NE(NULL, fp = fopen(envd_usr_20, "w"));
	ASSERT_LT(0, fprintf(fp, "TEST=\"vendor $TEST\"\n"));
	ASSERT_EQ(0, fclose(fp));

	ASSERT_NE(NULL, fp = fopen(envd_etc_20, "w"));
	ASSERT_LT(0, fprintf(fp,
			     "TEST=\"system $TEST\"\n"
			     "QUOTED='# $TEST'\n"
			     "SPACED=' value '\n"
			     "FALLBACK=\"${UNSET:+unused}${TEST:+-configured}\"\n"));
	ASSERT_EQ(0, fclose(fp));

	ASSERT_NE(NULL, fp = fopen(envd_usr_30, "w"));
	ASSERT_LT(0, fprintf(fp, "CHAIN=first\n"));
	ASSERT_EQ(0, fclose(fp));

	ASSERT_NE(NULL, fp = fopen(envd_usr_40, "w"));
	ASSERT_LT(0, fprintf(fp, "CHAIN=\"$CHAIN second\"\n"));
	ASSERT_EQ(0, fclose(fp));

	ASSERT_NE(NULL, fp = fopen(envd_etc_50, "w"));
	ASSERT_LT(0, fprintf(fp, "CHAIN=\"${CHAIN:+$CHAIN third}\"\n"));
	ASSERT_EQ(0, fclose(fp));
#endif
}

static void
cleanup(void)
{
	ASSERT_EQ(0, unlink(my_conf));
	ASSERT_EQ(0, unlink(bad_conf));
	ASSERT_EQ(0, unlink(my_env));
	ASSERT_EQ(0, unlink(envd_reg_env));
	ASSERT_EQ(0, unlink(envd_reg_file));
	ASSERT_EQ(0, unlink(envd_reg_missing));
	rmdir_p(envd_reg_dir);
#ifdef VENDORDIR
	ASSERT_EQ(0, unlink(usr_env));
	ASSERT_EQ(0, unlink(usr_conf));
	rmdir_p(dir_usr_etc_security);
#endif

#ifdef VENDORDIR
	ASSERT_EQ(0, unlink(envd_usr_env));
	ASSERT_EQ(0, unlink(envd_usr_10));
	ASSERT_EQ(0, unlink(envd_usr_20));
	ASSERT_EQ(0, unlink(envd_usr_30));
	ASSERT_EQ(0, unlink(envd_usr_40));
	ASSERT_EQ(0, unlink(envd_etc_20));
	ASSERT_EQ(0, unlink(envd_etc_50));
	rmdir_p(envd_usr_dir);
	rmdir_p(envd_etc_dir);
	rmdir_p(envd_root);
#endif
}

static void
check_array(const char **array1, char **array2)
{
	for (const char **a1 = array1; *a1 != NULL; ++a1) {
		char **a2;
		for (a2 = array2; *a2 != NULL; ++a2) {
			if (strcmp(*a1, *a2) == 0)
				break;
		}
		ASSERT_NE(NULL, *a2);
	}
}

static void
check_env(const char **list)
{
	pam_handle_t *pamh = NULL;

	ASSERT_EQ(PAM_SUCCESS,
		  pam_start_confdir(service_file, "user", &conv, ".", &pamh));
	ASSERT_NE(NULL, pamh);

	ASSERT_EQ(PAM_SUCCESS, pam_open_session(pamh, 0));

	char **env_list = pam_getenvlist(pamh);
	ASSERT_NE(NULL, env_list);

	check_array(list, env_list);

	for (char **e = env_list; *e != NULL; ++e)
		free(*e);
	free(env_list);

	ASSERT_EQ(PAM_SUCCESS, pam_close_session(pamh, 0));
	ASSERT_EQ(PAM_SUCCESS, pam_end(pamh, 0));
}

int
main(void)
{
	pam_handle_t *pamh = NULL;
	FILE *fp;
	char cwd[PATH_MAX];

	ASSERT_NE(NULL, getcwd(cwd, sizeof(cwd)));

	setup();

	/*
	 * When conffile= specifies a missing file, all methods except
	 * pam_sm_acct_mgmt and pam_sm_chauthtok return PAM_IGNORE.
	 * The return code of the stack where every module returns PAM_IGNORE
	 * is PAM_PERM_DENIED.
	 */
	ASSERT_NE(NULL, fp = fopen(service_file, "w"));
	ASSERT_LT(0, fprintf(fp, "#%%PAM-1.0\n"
			     "auth required %s/" LTDIR "%s.so conffile=%s/%s\n"
			     "account required %s/" LTDIR "%s.so conffile=%s/%s\n"
			     "password required %s/" LTDIR "%s.so conffile=%s/%s\n"
			     "session required %s/" LTDIR "%s.so conffile=%s/%s\n",
			     cwd, MODULE_NAME, cwd, missing_file,
			     cwd, MODULE_NAME, cwd, missing_file,
			     cwd, MODULE_NAME, cwd, missing_file,
			     cwd, MODULE_NAME, cwd, missing_file));
	ASSERT_EQ(0, fclose(fp));

	ASSERT_EQ(PAM_SUCCESS,
		  pam_start_confdir(service_file, "", &conv, ".", &pamh));
	ASSERT_NE(NULL, pamh);
	ASSERT_EQ(PAM_PERM_DENIED, pam_authenticate(pamh, 0));
	ASSERT_EQ(PAM_PERM_DENIED, pam_setcred(pamh, 0));
	ASSERT_EQ(PAM_SERVICE_ERR, pam_acct_mgmt(pamh, 0));
	ASSERT_EQ(PAM_SERVICE_ERR, pam_chauthtok(pamh, 0));
	ASSERT_EQ(PAM_PERM_DENIED, pam_open_session(pamh, 0));
	ASSERT_EQ(PAM_PERM_DENIED, pam_close_session(pamh, 0));
	ASSERT_EQ(PAM_SUCCESS, pam_end(pamh, 0));
	pamh = NULL;

	/*
	 * When conffile= specifies a missing file, all methods except
	 * pam_sm_acct_mgmt and pam_sm_chauthtok return PAM_IGNORE.
	 * pam_permit is added after pam_env to convert PAM_IGNORE to PAM_SUCCESS.
	 */
	ASSERT_NE(NULL, fp = fopen(service_file, "w"));
	ASSERT_LT(0, fprintf(fp, "#%%PAM-1.0\n"
			     "auth required %s/" LTDIR "%s.so conffile=%s/%s\n"
			     "auth required %s/../pam_permit/" LTDIR "pam_permit.so\n"
			     "account required %s/" LTDIR "%s.so conffile=%s/%s\n"
			     "account required %s/../pam_permit/" LTDIR "pam_permit.so\n"
			     "password required %s/" LTDIR "%s.so conffile=%s/%s\n"
			     "password required %s/../pam_permit/" LTDIR "pam_permit.so\n"
			     "session required %s/" LTDIR "%s.so conffile=%s/%s\n"
			     "session required %s/../pam_permit/" LTDIR "pam_permit.so\n",
			     cwd, MODULE_NAME, cwd, missing_file, cwd,
			     cwd, MODULE_NAME, cwd, missing_file, cwd,
			     cwd, MODULE_NAME, cwd, missing_file, cwd,
			     cwd, MODULE_NAME, cwd, missing_file, cwd));
	ASSERT_EQ(0, fclose(fp));

	ASSERT_EQ(PAM_SUCCESS,
		  pam_start_confdir(service_file, "", &conv, ".", &pamh));
	ASSERT_NE(NULL, pamh);
	ASSERT_EQ(PAM_SUCCESS, pam_authenticate(pamh, 0));
	ASSERT_EQ(PAM_SUCCESS, pam_setcred(pamh, 0));
	ASSERT_EQ(PAM_SERVICE_ERR, pam_acct_mgmt(pamh, 0));
	ASSERT_EQ(PAM_SERVICE_ERR, pam_chauthtok(pamh, 0));
	ASSERT_EQ(PAM_SUCCESS, pam_open_session(pamh, 0));
	ASSERT_EQ(PAM_SUCCESS, pam_close_session(pamh, 0));
	ASSERT_EQ(PAM_SUCCESS, pam_end(pamh, 0));
	pamh = NULL;

	/*
	 * conffile= specifies an existing file,
	 * envfile= specifies an empty file.
	 */
	ASSERT_NE(NULL, fp = fopen(service_file, "w"));
	ASSERT_LT(0, fprintf(fp, "#%%PAM-1.0\n"
			     "session required %s/" LTDIR "%s.so"
			     " conffile=%s/%s envfile=%s\n",
			     cwd, MODULE_NAME,
			     cwd, my_conf, "/dev/null"));
	ASSERT_EQ(0, fclose(fp));

	const char *env1[] = { "EDITOR=vim", "PAGER=more", "NAME=user\\name", NULL };
	check_env(env1);

	/*
	 * conffile= specifies an empty file,
	 * envfile= specifies an existing file.
	 */
	ASSERT_NE(NULL, fp = fopen(service_file, "w"));
	ASSERT_LT(0, fprintf(fp, "#%%PAM-1.0\n"
			     "session required %s/" LTDIR "%s.so"
			     " conffile=%s envfile=%s/%s\n",
			     cwd, MODULE_NAME,
			     "/dev/null", cwd, my_env));
	ASSERT_EQ(0, fclose(fp));

	const char *env2[] = { "test_value=foo", "test2_value=bar", NULL };
	check_env(env2);

	/*
	 * conffile= specifies a file whose last line is malformed,
	 * preceded by a valid line.  This must not cause PAM_ABORT.
	 */
	ASSERT_NE(NULL, fp = fopen(service_file, "w"));
	ASSERT_LT(0, fprintf(fp, "#%%PAM-1.0\n"
			     "session required %s/" LTDIR "%s.so"
			     " conffile=%s/%s envfile=%s\n",
			     cwd, MODULE_NAME,
			     cwd, bad_conf, "/dev/null"));
	ASSERT_EQ(0, fclose(fp));

	const char *env3a[] = { "GOOD_VAR=good", NULL };
	check_env(env3a);

	ASSERT_NE(NULL, fp = fopen(service_file, "w"));
	ASSERT_LT(0, fprintf(fp, "#%%PAM-1.0\n"
			     "session required %s/" LTDIR "%s.so"
			     " conffile=/dev/null envfile=%s/%s\n",
			     cwd, MODULE_NAME, cwd, envd_reg_root));
	ASSERT_EQ(0, fclose(fp));

	const char *env_defaults[] = {
		"BASE=present",
		"RESULT_SET=present",
		"RESULT_SET_DEFAULT=present",
		"RESULT_UNSET=fallback",
		"RESULT_UNSET_DEFAULT=fallback",
		"URL=https://example.test/{name}/file",
		"NESTED=fallback",
		"ESCAPED_SPACE=foo ",
		"EVEN_BACKSLASHES=foo\\",
		"TRAILING_SPACE=foo",
		"EMPTY=",
		"RESULT_EMPTY=fallback",
		"RESULT_EMPTY_DEFAULT=",
		"TOO_DEEP=original",
		"AFTER_TOO_DEEP=present",
		"RESULT_AFTER_QUOTE_COMMENT=present",
		"RESULT_AFTER_SEMICOLON_QUOTE_COMMENT=present",
		"RESULT_AFTER_BACKSLASH_COMMENT=present",
		"RESULT_AFTER_SEMICOLON_BACKSLASH_COMMENT=present",
		"CONTINUED=firstsecond",
		NULL
	};
	check_env(env_defaults);

#if defined (USE_ECONF) && defined (VENDORDIR)

	/* envfile is a directory. So values will be read from {TEST_NAME_DIR}/usr/etc and {TEST_NAME_DIR}/etc */
	ASSERT_NE(NULL, fp = fopen(service_file, "w"));
	ASSERT_LT(0, fprintf(fp, "#%%PAM-1.0\n"
			     "session required %s/" LTDIR "%s.so"
			     " conffile=%s envfile=%s/%s/\n",
			     cwd, MODULE_NAME,
			     "/dev/null",
			     cwd, TEST_NAME_DIR));
	ASSERT_EQ(0, fclose(fp));

	const char *env3[] = {"usr_etc_test=foo", "usr_etc_test2=bar", NULL};
	check_env(env3);

	/* conffile is a directory. So values will be read from {TEST_NAME_DIR}/usr/etc and {TEST_NAME_DIR}/etc */
	ASSERT_NE(NULL, fp = fopen(service_file, "w"));
	ASSERT_LT(0, fprintf(fp, "#%%PAM-1.0\n"
			     "session required %s/" LTDIR "%s.so"
			     " conffile=%s/%s/ envfile=%s\n",
			     cwd, MODULE_NAME,
			     cwd, TEST_NAME_DIR,
			     "/dev/null"));
	ASSERT_EQ(0, fclose(fp));

	const char *env4[] = {"PAGER=emacs", "MANPAGER=less", NULL};
	check_env(env4);

#endif

#ifdef VENDORDIR
	/* Verify environment.d expansion, ordering, quoting, and file precedence. */
	ASSERT_NE(NULL, fp = fopen(service_file, "w"));
	ASSERT_LT(0, fprintf(fp, "#%%PAM-1.0\n"
			     "session required %s/" LTDIR "%s.so"
			     " conffile=/dev/null envfile=%s/%s\n",
			     cwd, MODULE_NAME, cwd, envd_root));
	ASSERT_EQ(0, fclose(fp));

	const char *env5[] = {
		"PATH=/my/custom/path:/usr/bin",
		"TEST=system example var",
		"LITERAL=$TEST",
		"FALLBACK=-configured",
		"FALLBACK_DEFAULT=default",
		"FALLBACK_SET=present",
		"FALLBACK_EMPTY=fallback",
		"CONTINUED=firstsecond",
		"QUOTED=# system example var",
		"SPACED= value ",
		"CHAIN=first second third",
		NULL
	};
	check_env(env5);
#endif

	/* cleanup */
	cleanup();
	ASSERT_EQ(0, unlink(service_file));

	return 0;
}
