#include "config.h"

#ifdef PAM_STATIC

#define static extern
#define PAM_SM_ACCOUNT
#define PAM_SM_AUTH
#define PAM_SM_PASSWORD
#define PAM_SM_SESSION
#include "pam_unix_static.h"
#include <security/pam_modules.h>

struct pam_module _pam_unix_modstruct = {
	"pam_unix",
	pam_sm_authenticate,
	pam_sm_setcred,
	pam_sm_acct_mgmt,
	pam_sm_open_session,
	pam_sm_close_session,
	pam_sm_chauthtok,
};

#endif
