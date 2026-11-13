/*
 * $Id$
 *
 * This function provides a common pam_set_data() friendly version of free().
 */

#include "pam_modutil_private.h"
#include "pam_inline.h"

#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <shadow.h>

void
pam_modutil_cleanup (pam_handle_t *pamh UNUSED, void *data,
		     int error_status UNUSED)
{
	/* junk it */
	free(data);
}

void
pam_modutil_cleanup_group (pam_handle_t *pamh UNUSED, void *data,
			   int error_status UNUSED)
{
	struct group *gr = data;

	if (gr && gr->gr_passwd)
		pam_overwrite_string(gr->gr_passwd);

	free(data);
}

void
pam_modutil_cleanup_passwd (pam_handle_t *pamh UNUSED, void *data,
			    int error_status UNUSED)
{
	struct passwd *pw = data;

	if (pw && pw->pw_passwd)
		pam_overwrite_string(pw->pw_passwd);

	free(data);
}

void
pam_modutil_cleanup_shadow (pam_handle_t *pamh UNUSED, void *data,
			    int error_status UNUSED)
{
	struct spwd *sp = data;

	if (sp && sp->sp_pwdp)
		pam_overwrite_string(sp->sp_pwdp);

	free(data);
}
