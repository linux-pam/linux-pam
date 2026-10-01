/*
 * $Id$
 *
 * This function provides common methods for checking if a user is in a
 * specified group.
 */

#include "pam_modutil_private.h"

#include <fnmatch.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>

#ifdef HAVE_GETGROUPLIST

#define NGROUPS_MIN 100
#define NGROUPS_MAX 65536

static gid_t *
getgrouplist_alloc(const char *user, gid_t primary, int *ngroups_out)
{
	gid_t *grouplist = NULL;
	int ngroups, pgroups, i = -1;

	ngroups = NGROUPS_MIN;
	do {
		pgroups = ngroups;
		free(grouplist);
		grouplist = malloc(sizeof(gid_t) * ngroups);
		if (grouplist == NULL)
			return NULL;
		i = getgrouplist(user, primary, grouplist, &ngroups);
	} while (i < 0 && ngroups > 0 && ngroups != pgroups
		 && ngroups <= NGROUPS_MAX);

	if (i < 0) {
		free(grouplist);
		return NULL;
	}
	*ngroups_out = ngroups;
	return grouplist;
}

static int
checkgrouplist(const char *user, gid_t primary, gid_t target)
{
	gid_t *grouplist;
	int ngroups;
	int found = 0;

	grouplist = getgrouplist_alloc(user, primary, &ngroups);
	if (grouplist != NULL) {
		for (int i = 0; i < ngroups; i++) {
			if (grouplist[i] == target) {
				found = 1;
				break;
			}
		}
		free(grouplist);
	}

	return found;
}
#endif

static int
pam_modutil_user_in_group_common(pam_handle_t *pamh UNUSED,
				 struct passwd *pwd,
				 struct group *grp)
{
	int i;

	if (pwd == NULL) {
		return 0;
	}
	if (grp == NULL) {
		return 0;
	}

	if (pwd->pw_gid == grp->gr_gid) {
		return 1;
	}

	for (i = 0; (grp->gr_mem != NULL) && (grp->gr_mem[i] != NULL); i++) {
		if (strcmp(pwd->pw_name, grp->gr_mem[i]) == 0) {
			return 1;
		}
	}

#ifdef HAVE_GETGROUPLIST
	if (checkgrouplist(pwd->pw_name, pwd->pw_gid, grp->gr_gid)) {
		return 1;
	}
#endif

	return 0;
}

int
pam_modutil_user_in_group_nam_nam(pam_handle_t *pamh,
				 const char *user, const char *group)
{
	struct passwd *pwd;
	struct group *grp;

	pwd = pam_modutil_getpwnam(pamh, user);
	grp = pam_modutil_getgrnam(pamh, group);

	return pam_modutil_user_in_group_common(pamh, pwd, grp);
}

int
pam_modutil_user_in_group_nam_gid(pam_handle_t *pamh,
				  const char *user, gid_t group)
{
	struct passwd *pwd;
	struct group *grp;

	pwd = pam_modutil_getpwnam(pamh, user);
	grp = pam_modutil_getgrgid(pamh, group);

	return pam_modutil_user_in_group_common(pamh, pwd, grp);
}

int
pam_modutil_user_in_group_uid_nam(pam_handle_t *pamh,
				  uid_t user, const char *group)
{
	struct passwd *pwd;
	struct group *grp;

	pwd = pam_modutil_getpwuid(pamh, user);
	grp = pam_modutil_getgrnam(pamh, group);

	return pam_modutil_user_in_group_common(pamh, pwd, grp);
}

int
pam_modutil_user_in_group_uid_gid(pam_handle_t *pamh,
				  uid_t user, gid_t group)
{
	struct passwd *pwd;
	struct group *grp;

	pwd = pam_modutil_getpwuid(pamh, user);
	grp = pam_modutil_getgrgid(pamh, group);

	return pam_modutil_user_in_group_common(pamh, pwd, grp);
}

static int
checkgroupname(pam_handle_t *pamh, gid_t gid, const char *pattern)
{
	struct group *grp;

	grp = pam_modutil_getgrgid(pamh, gid);
	if (grp == NULL)
		return 0;
	return fnmatch(pattern, grp->gr_name, 0) == 0;
}

#ifdef HAVE_GETGROUPLIST
static int
checkgrouplist_pat(pam_handle_t *pamh, const char *user, gid_t primary,
		   const char *pattern)
{
	gid_t *grouplist;
	int ngroups;
	int found = 0;

	grouplist = getgrouplist_alloc(user, primary, &ngroups);
	if (grouplist != NULL) {
		for (int i = 0; i < ngroups; i++) {
			if (grouplist[i] == primary)
				continue;
			if (checkgroupname(pamh, grouplist[i], pattern)) {
				found = 1;
				break;
			}
		}
		free(grouplist);
	}

	return found;
}
#endif

int
pam_modutil_user_in_group_nam_pat(pam_handle_t *pamh,
				  const char *user, const char *pattern)
{
	struct passwd *pwd;

	if (strpbrk(pattern, "*?[") == NULL)
		return pam_modutil_user_in_group_nam_nam(pamh, user, pattern);

	pwd = pam_modutil_getpwnam(pamh, user);
	if (pwd == NULL)
		return 0;

	if (checkgroupname(pamh, pwd->pw_gid, pattern))
		return 1;

#ifdef HAVE_GETGROUPLIST
	return checkgrouplist_pat(pamh, pwd->pw_name, pwd->pw_gid, pattern);
#else
	return 0;
#endif
}
