
#include <stdio.h>
#include <strings.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>

static struct pam_conv conv = {
    misc_conv,
    NULL
};

static int debug = 0;

/*
  https://bugzilla.redhat.com/bugzilla/show_bug.cgi?id=196859

  This stack should not return PAM_IGNORE to the application:
  auth [default=die] pam_debug.so auth=ignore
*/
static int
test2 (void)
{
  pam_handle_t *pamh=NULL;
  const char *user="nobody";
  int retval;

  retval = pam_start("tst-pam_dispatch2", user, &conv, &pamh);
  if (retval != PAM_SUCCESS)
    {
      if (debug)
	fprintf (stderr, "test2: pam_start returned %d\n", retval);
      return 1;
    }

  retval = pam_authenticate(pamh, 0);
  if (retval != PAM_PERM_DENIED)
    {
      if (debug)
	fprintf (stderr, "test2: pam_authenticate returned %d\n", retval);
      return 1;
    }

  retval = pam_end(pamh,retval);
  if (retval != PAM_SUCCESS)
    {
      if (debug)
	fprintf (stderr, "test2: pam_end returned %d\n", retval);
      return 1;
    }
  return 0;
}

int main(int argc, char *argv[])
{
    if (argc > 1 && strcmp (argv[1], "-d") == 0)
      debug = 1;

    if (test2 ())
      return 1;

    return 0;
}
