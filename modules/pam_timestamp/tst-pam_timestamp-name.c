/* Test timestamp path validation without accessing cache files. */
#define pam_modutil_getpwuid test_getpwuid
#define pam_syslog test_syslog
#include "pam_timestamp.c"
#include "test_assert.h"
#include <security/pam_appl.h>

static char diagnostic[128];
static int diagnostic_priority;

struct passwd *
test_getpwuid(pam_handle_t *pamh UNUSED, uid_t uid UNUSED)
{
	static char invalid_name[] = "bad/name";
	static struct passwd pwd = { .pw_name = invalid_name };

	return &pwd;
}

void
test_syslog(const pam_handle_t *pamh UNUSED, int priority, const char *fmt, ...)
{
	va_list ap;

	diagnostic_priority = priority;
	va_start(ap, fmt);
	vsnprintf(diagnostic, sizeof(diagnostic), fmt, ap);
	va_end(ap);
}

int
main(void)
{
	static const char *const invalid_names[] = { NULL, "", ".", "..", "bad/name" };
	const char *args[] = { "timestampdir=/" };
	const struct pam_conv conv = { .conv = NULL };
	pam_handle_t *pamh = NULL;
	char path[128];

	for (size_t i = 0; i < sizeof(invalid_names) / sizeof(invalid_names[0]); ++i) {
		ASSERT_EQ(false, is_valid_timestamp_name_component(invalid_names[i]));
	}

	ASSERT_EQ(PAM_SUCCESS, pam_start("pam_timestamp_name_test", "bad/name", &conv, &pamh));
	ASSERT_EQ(PAM_AUTH_ERR, get_timestamp_name(pamh, 1, args, path, sizeof(path)));
	ASSERT_EQ(0, strcmp(diagnostic, "invalid PAM_USER for timestamp path"));
	ASSERT_EQ(LOG_ERR, diagnostic_priority);

	ASSERT_EQ(PAM_SUCCESS, pam_set_item(pamh, PAM_USER, "alice.example"));
	ASSERT_EQ(PAM_SUCCESS, pam_set_item(pamh, PAM_RUSER, "bad/name"));
	ASSERT_EQ(PAM_AUTH_ERR, get_timestamp_name(pamh, 1, args, path, sizeof(path)));
	ASSERT_EQ(0, strcmp(diagnostic, "invalid PAM_RUSER for timestamp path"));
	ASSERT_EQ(LOG_NOTICE, diagnostic_priority);

	ASSERT_EQ(PAM_SUCCESS, pam_set_item(pamh, PAM_RUSER, NULL));
	ASSERT_EQ(PAM_AUTH_ERR, get_timestamp_name(pamh, 1, args, path, sizeof(path)));
	ASSERT_EQ(0, strcmp(diagnostic, "invalid username returned by real-UID lookup for timestamp path"));
	ASSERT_EQ(LOG_ERR, diagnostic_priority);

	ASSERT_EQ(PAM_SUCCESS, pam_set_item(pamh, PAM_TTY, "tty1"));
	ASSERT_EQ(PAM_SUCCESS, pam_set_item(pamh, PAM_RUSER, "alice.example"));
	ASSERT_EQ(PAM_SUCCESS, get_timestamp_name(pamh, 1, args, path, sizeof(path)));
	ASSERT_EQ(0, strcmp(path, "//alice.example/tty1"));
	ASSERT_EQ(PAM_SUCCESS, pam_set_item(pamh, PAM_USER, "bob.example"));
	ASSERT_EQ(PAM_SUCCESS, get_timestamp_name(pamh, 1, args, path, sizeof(path)));
	ASSERT_EQ(0, strcmp(path, "//alice.example/tty1:bob.example"));
	ASSERT_EQ(PAM_AUTH_ERR, get_timestamp_name(pamh, 1, args, path, 1));
	ASSERT_EQ(0, strcmp(diagnostic, "timestamp path too long"));
	ASSERT_EQ(LOG_ERR, diagnostic_priority);
	ASSERT_EQ(PAM_SUCCESS, pam_end(pamh, PAM_SUCCESS));
	return 0;
}
