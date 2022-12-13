/*
 * Check pam_env return values.
 *
 * Copyright (c) 2020-2022 Dmitry V. Levin <ldv@altlinux.org>
 * Copyright (c) 2022 Stefan Schubert <schubi@suse.de>
 */

#include "test_assert.h"

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
static const char dir[] = TEST_NAME_DIR;
static const char dir_usr[] = TEST_NAME_DIR "/usr";
static const char dir_usr_etc[] = TEST_NAME_DIR "/usr/etc";
static const char dir_usr_etc_security[] = TEST_NAME_DIR "/usr/etc/security";
static const char my_conf[] = TEST_NAME ".conf";
static const char my_env[] = TEST_NAME ".env";
static const char usr_env[] = TEST_NAME_DIR "/usr/etc/environment";
static const char usr_conf[] = TEST_NAME_DIR "/usr/etc/security/pam_env.conf";

static struct pam_conv conv;

static void
setup(void)
{
	FILE *fp;

	ASSERT_EQ(0, mkdir(dir, 0755));
	ASSERT_EQ(0, mkdir(dir_usr, 0755));
	ASSERT_EQ(0, mkdir(dir_usr_etc, 0755));
	ASSERT_EQ(0, mkdir(dir_usr_etc_security, 0755));

	ASSERT_NE(NULL, fp = fopen(my_conf, "w"));
	ASSERT_LT(0, fprintf(fp,
			     "EDITOR\tDEFAULT=vim\n"
			     "PAGER\tDEFAULT=more\n"));
	ASSERT_EQ(0, fclose(fp));

	ASSERT_NE(NULL, fp = fopen(my_env, "w"));
	ASSERT_LT(0, fprintf(fp,
			     "test_value=foo\n"
			     "test2_value=bar\n"));
	ASSERT_EQ(0, fclose(fp));

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
}

static void
cleanup(void)
{
	ASSERT_EQ(0, unlink(my_conf));
	ASSERT_EQ(0, unlink(my_env));
	ASSERT_EQ(0, unlink(usr_env));
	ASSERT_EQ(0, unlink(usr_conf));
	ASSERT_EQ(0, rmdir(dir_usr_etc_security));
	ASSERT_EQ(0, rmdir(dir_usr_etc));
	ASSERT_EQ(0, rmdir(dir_usr));
	ASSERT_EQ(0, rmdir(dir));
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
		  pam_start_confdir(service_file, "", &conv, ".", &pamh));
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
			     "auth required %s/.libs/%s.so conffile=%s/%s\n"
			     "account required %s/.libs/%s.so conffile=%s/%s\n"
			     "password required %s/.libs/%s.so conffile=%s/%s\n"
			     "session required %s/.libs/%s.so conffile=%s/%s\n",
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
			     "auth required %s/.libs/%s.so conffile=%s/%s\n"
			     "auth required %s/../pam_permit/.libs/pam_permit.so\n"
			     "account required %s/.libs/%s.so conffile=%s/%s\n"
			     "account required %s/../pam_permit/.libs/pam_permit.so\n"
			     "password required %s/.libs/%s.so conffile=%s/%s\n"
			     "password required %s/../pam_permit/.libs/pam_permit.so\n"
			     "session required %s/.libs/%s.so conffile=%s/%s\n"
			     "session required %s/../pam_permit/.libs/pam_permit.so\n",
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
			     "session required %s/.libs/%s.so"
			     " conffile=%s/%s envfile=%s\n",
			     cwd, MODULE_NAME,
			     cwd, my_conf, "/dev/null"));
	ASSERT_EQ(0, fclose(fp));

	const char *env1[] = { "EDITOR=vim", "PAGER=more", NULL };
	check_env(env1);

	/*
	 * conffile= specifies an empty file,
	 * envfile= specifies an existing file.
	 */
	ASSERT_NE(NULL, fp = fopen(service_file, "w"));
	ASSERT_LT(0, fprintf(fp, "#%%PAM-1.0\n"
			     "session required %s/.libs/%s.so"
			     " conffile=%s envfile=%s/%s\n",
			     cwd, MODULE_NAME,
			     "/dev/null", cwd, my_env));
	ASSERT_EQ(0, fclose(fp));

	const char *env2[] = { "test_value=foo", "test2_value=bar", NULL };
	check_env(env2);

#if defined (USE_ECONF)	&& defined (VENDORDIR)

	/* envfile is a directory. So values will be read from {TEST_NAME_DIR}/usr/etc and {TEST_NAME_DIR}/etc */
	ASSERT_NE(NULL, fp = fopen(service_file, "w"));
	ASSERT_LT(0, fprintf(fp, "#%%PAM-1.0\n"
			     "session required %s/.libs/%s.so"
			     " conffile=%s envfile=%s/%s/\n",
			     cwd, MODULE_NAME,
			     "/dev/null",
			     cwd, dir));
	ASSERT_EQ(0, fclose(fp));

	const char *env3[] = {"usr_etc_test=foo", "usr_etc_test2=bar", NULL};
	check_env(env3);

	/* conffile is a directory. So values will be read from {TEST_NAME_DIR}/usr/etc and {TEST_NAME_DIR}/etc */
	ASSERT_NE(NULL, fp = fopen(service_file, "w"));
	ASSERT_LT(0, fprintf(fp, "#%%PAM-1.0\n"
			     "session required %s/.libs/%s.so"
			     " conffile=%s/%s/ envfile=%s\n",
			     cwd, MODULE_NAME,
			     cwd, dir,
			     "/dev/null"));
	ASSERT_EQ(0, fclose(fp));

	const char *env4[] = {"PAGER=emacs", "MANPAGER=less", NULL};
	check_env(env4);

#endif

	/* cleanup */
	cleanup();
	ASSERT_EQ(0, unlink(service_file));

	return 0;
}
