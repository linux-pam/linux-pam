/*
 * Check pam_succeed_if return values.
 *
 * Copyright (c) 2020 Dmitry V. Levin <ldv@altlinux.org>
 * Copyright (c) 2024 Tobias Stoeckmann <tobias@stoeckmann.org>
 */

#include "test_assert.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <security/pam_appl.h>

#define MODULE_NAME "pam_succeed_if"
#define TEST_NAME "tst-" MODULE_NAME "-retval"

static const char service_file[] = TEST_NAME ".service";
static const char user_name[] = "name";
static struct pam_conv conv;

int
main(void)
{
	pam_handle_t *pamh = NULL;
	FILE *fp;
	char cwd[PATH_MAX];

	ASSERT_NE(NULL, getcwd(cwd, sizeof(cwd)));

	ASSERT_NE(NULL, fp = fopen(service_file, "w"));
	ASSERT_LT(0, fprintf(fp, "#%%PAM-1.0\n"
			     "auth required %s/.libs/%s.so user = name\n"
			     "auth required %s/.libs/%s.so env:some-unset-env-variable is unset\n"
			     "auth required %s/.libs/%s.so env:some-set-env-variable is set\n"
			     "auth required %s/.libs/%s.so env:some-set-env-variable = 0\n"
			     "auth [auth_err=ignore] %s/.libs/%s.so env:some-set-env-variable != 0\n"
			     "auth required %s/.libs/%s.so env:some-set-env-variable lt 1\n"
			     "auth required %s/.libs/%s.so env:some-set-env-variable gt -1\n"
			     "auth [service_err=ignore] %s/.libs/%s.so env is unset\n"
			     "auth [service_err=ignore] %s/.libs/%s.so env: is unset\n"
			     "auth required %s/.libs/%s.so env:some-set-env-variable is 0\n"
			     "auth [auth_err=ignore] %s/.libs/%s.so env:some-set-env-variable is 1\n"
			     "account required %s/.libs/%s.so user notin a:b\n"
			     "password required %s/.libs/%s.so user in x:name\n"
			     "session required %s/.libs/%s.so rhost eq 0\n",
			     cwd, MODULE_NAME,
			     cwd, MODULE_NAME,
			     cwd, MODULE_NAME,
			     cwd, MODULE_NAME,
			     cwd, MODULE_NAME,
			     cwd, MODULE_NAME,
			     cwd, MODULE_NAME,
			     cwd, MODULE_NAME,
			     cwd, MODULE_NAME,
			     cwd, MODULE_NAME,
			     cwd, MODULE_NAME,
			     cwd, MODULE_NAME,
			     cwd, MODULE_NAME,
			     cwd, MODULE_NAME));
	ASSERT_EQ(0, fclose(fp));

	ASSERT_EQ(PAM_SUCCESS,
		  pam_start_confdir(service_file, user_name, &conv, ".", &pamh));
	ASSERT_NE(NULL, pamh);
	ASSERT_EQ(PAM_SUCCESS, pam_set_item(pamh, PAM_RHOST, "0"));
	ASSERT_EQ(PAM_SUCCESS, pam_putenv(pamh, "some-set-env-variable=0"));

	ASSERT_EQ(PAM_SUCCESS, pam_authenticate(pamh, 0));
	ASSERT_EQ(PAM_SUCCESS, pam_acct_mgmt(pamh, 0));
	ASSERT_EQ(PAM_SUCCESS, pam_chauthtok(pamh, 0));
	ASSERT_EQ(PAM_SUCCESS, pam_open_session(pamh, 0));
	ASSERT_EQ(PAM_SUCCESS, pam_close_session(pamh, 0));
	ASSERT_EQ(PAM_SUCCESS, pam_end(pamh, 0));
	pamh = NULL;

	ASSERT_EQ(0, unlink(service_file));

	/* test some illegal conditions */
	ASSERT_NE(NULL, fp = fopen(service_file, "w"));
	ASSERT_LT(0, fprintf(fp, "#%%PAM-1.0\n"
			     "auth required %s/.libs/%s.so user eq name\n"
			     "account required %s/.libs/%s.so user in a:b\n"
			     "password required %s/.libs/%s.so user notin x:name\n"
			     "session required %s/.libs/%s.so rhost eq []\n",
			     cwd, MODULE_NAME,
			     cwd, MODULE_NAME,
			     cwd, MODULE_NAME,
			     cwd, MODULE_NAME));
	ASSERT_EQ(0, fclose(fp));

	ASSERT_EQ(PAM_SUCCESS,
		  pam_start_confdir(service_file, user_name, &conv, ".", &pamh));
	ASSERT_NE(NULL, pamh);

	ASSERT_EQ(PAM_SERVICE_ERR, pam_authenticate(pamh, 0));
	ASSERT_EQ(PAM_AUTH_ERR, pam_acct_mgmt(pamh, 0));
	ASSERT_EQ(PAM_AUTH_ERR, pam_chauthtok(pamh, 0));
	ASSERT_EQ(PAM_SERVICE_ERR, pam_open_session(pamh, 0));
	ASSERT_EQ(PAM_SERVICE_ERR, pam_close_session(pamh, 0));
	ASSERT_EQ(PAM_SUCCESS, pam_end(pamh, 0));
	pamh = NULL;

	ASSERT_EQ(0, unlink(service_file));

	return 0;
}
