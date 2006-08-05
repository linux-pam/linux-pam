
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdio.h>

static struct pam_conv conv = {
    misc_conv,
    NULL
};

static int debug = 0;

/*
  https://bugzilla.redhat.com/bugzilla/show_bug.cgi?id=196859

  This stack should not return PAM_IGNORE to the application:
  auth [default=bad] pam_debug.so auth=ignore
*/
static int
test1 (void)
{
  pam_handle_t *pamh=NULL;
  const char *user="nobody";
  int retval;

  retval = pam_start("tst-pam_dispatch1", user, &conv, &pamh);
  if (retval != PAM_SUCCESS)
    {
      if (debug)
	fprintf (stderr, "test1: pam_start returned %d\n", retval);
      return 1;
    }

  retval = pam_authenticate(pamh, 0);
  if (retval != PAM_PERM_DENIED)
    {
      if (debug)
	fprintf (stderr, "test1: pam_authenticate returned %d\n", retval);
      return 1;
    }

  retval = pam_end(pamh,retval);
  if (retval != PAM_SUCCESS)
    {
      if (debug)
	fprintf (stderr, "test1: pam_end returned %d\n", retval);
      return 1;
    }
  return 0;
}


int main(int argc, char *argv[])
{
    if (argc > 1 && strcmp (argv[1], "-d") == 0)
      debug = 1;

    if (test1 ())
      return 1;

    return 0;
}
