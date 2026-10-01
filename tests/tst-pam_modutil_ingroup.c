/* Check group patterns without depending on the system account database. */

#define pam_modutil_getpwnam test_getpwnam
#define pam_modutil_getgrnam test_getgrnam
#define pam_modutil_getgrgid test_getgrgid
#define getgrouplist test_getgrouplist
#include "pam_modutil_ingroup.c"

#include "test_assert.h"

static char user_name[] = "test-user";
static struct passwd user = {
	.pw_name = user_name,
	.pw_gid = 100,
};
static char *members[] = { NULL };
static char group_names[2][32];
static struct group groups[] = {
	{ .gr_name = group_names[0], .gr_gid = 100, .gr_mem = members },
	{ .gr_name = group_names[1], .gr_gid = 101, .gr_mem = members },
};

struct passwd *
test_getpwnam(pam_handle_t *pamh UNUSED, const char *name)
{
	return strcmp(name, user.pw_name) == 0 ? &user : NULL;
}

struct group *
test_getgrnam(pam_handle_t *pamh UNUSED, const char *name)
{
	for (size_t i = 0; i < sizeof(groups) / sizeof(groups[0]); ++i)
		if (strcmp(name, groups[i].gr_name) == 0)
			return &groups[i];
	return NULL;
}

struct group *
test_getgrgid(pam_handle_t *pamh UNUSED, gid_t gid)
{
	for (size_t i = 0; i < sizeof(groups) / sizeof(groups[0]); ++i)
		if (gid == groups[i].gr_gid)
			return &groups[i];
	return NULL;
}

#ifdef HAVE_GETGROUPLIST
int
test_getgrouplist(const char *name, gid_t primary, gid_t *list, int *count)
{
	ASSERT_EQ(0, strcmp(name, user.pw_name));
	ASSERT_EQ(user.pw_gid, primary);
	ASSERT_LE(2, *count);
	list[0] = groups[0].gr_gid;
	list[1] = groups[1].gr_gid;
	*count = 2;
	return 2;
}
#endif

int
main(void)
{
	static const struct {
		const char *name;
		const char *pattern;
		int matched;
	} cases[] = {
		{ "DOMAIN\\admins", "DOMAIN\\admins", 1 },
		{ "DOMAIN\\admins", "DOMAIN\\*", 1 },
		{ "DOMAINadmins", "DOMAIN\\*", 0 },
		{ "DOMAIN*", "DOMAIN\\*", 0 },
		{ "DOMAIN\\admins", "DOMAINadmins", 0 },
		{ "admins", "adm?ns", 1 },
		{ "admins", "[a]dmins", 1 },
		{ "admins", "other*", 0 },
	};
	/* The controlled lookup functions do not dereference the PAM handle. */
	pam_handle_t *pamh = (pam_handle_t *) &user;

	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
		strcpy(group_names[0], cases[i].name);
		strcpy(group_names[1], "unrelated");
		ASSERT_EQ(cases[i].matched,
			  pam_modutil_user_in_group_nam_pat(pamh, user.pw_name,
							   cases[i].pattern));
#ifdef HAVE_GETGROUPLIST
		strcpy(group_names[0], "unrelated");
		strcpy(group_names[1], cases[i].name);
		ASSERT_EQ(cases[i].matched,
			  pam_modutil_user_in_group_nam_pat(pamh, user.pw_name,
								   cases[i].pattern));
#endif
	}
	return 0;
}
