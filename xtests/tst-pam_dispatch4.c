
#include <stdio.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>

static struct pam_conv conv = {
    misc_conv,
    NULL
};


/* Check that errors of optional modules are ignored and that
   required modules after a sufficient one are not executed.  */

int
main(int argc, char *argv[])
{
  pam_handle_t *pamh=NULL;
  const char *user="nobody";
  int retval;
  int debug = 0;

  if (argc > 1 && strcmp (argv[1], "-d") == 0)
    debug = 1;

  retval = pam_start("tst-pam_dispatch4", user, &conv, &pamh);
  if (retval != PAM_SUCCESS)
    {
      if (debug)
	fprintf (stderr, "test4: pam_start returned %d\n", retval);
      return 1;
    }

  retval = pam_authenticate (pamh, 0);
  if (retval != PAM_SUCCESS)
    {
      if (debug)
	fprintf (stderr, "test4: pam_authenticate returned %d\n", retval);
      return 1;
    }

  retval = pam_acct_mgmt (pamh, 0);
  if (retval == PAM_SUCCESS)
    {
      if (debug)
	fprintf (stderr, "test4: pam_authenticate returned %d\n", retval);
      return 1;
    }

  retval = pam_end (pamh,retval);
  if (retval != PAM_SUCCESS)
    {
      if (debug)
	fprintf (stderr, "test4: pam_end returned %d\n", retval);
      return 1;
    }
  return 0;
}
