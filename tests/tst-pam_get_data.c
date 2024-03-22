/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <pam_private.h>

static void
tst_str_data_cleanup (pam_handle_t *pamh UNUSED, void *data, int error_status)
{
  fprintf (stderr, "tst_cleanup was called: data=\"%s\", error_status=%d\n",
	   (char *)data, error_status);
  free (data);
}

int
main (void)
{
  const char *service = "dummy";
  const char *user = "root";
  struct pam_conv conv = { NULL, NULL };
  pam_handle_t *pamh;
  void *dataptr;
  const void *constdataptr;
  int retval;

  /* 1: Call with NULL as pam handle */
  retval = pam_get_data (NULL, "tst-pam_get_data-1", &constdataptr);
  if (retval == PAM_SUCCESS)
    {
      fprintf (stderr, "test1: pam_get_data (NULL, ...) returned PAM_SUCCESS\n");
      return 1;
    }

  /* setup pam handle */
  retval = pam_start (service, user, &conv, &pamh);
  if (retval != PAM_SUCCESS)
    {
      fprintf (stderr, "pam_start (%s, %s, &conv, &pamh) returned %d (%s)\n",
               service, user, retval, pam_strerror (pamh, retval));
      return 1;
    }

  /* 2: check for call from application */
  retval = pam_get_data (pamh, "tst-pam_get_data-2", &constdataptr);
  if (retval != PAM_SYSTEM_ERR)
    {
      fprintf (stderr,
	       "test2: pam_get_data returned %d when expecting PAM_SYSTEM_ERR\n",
	       retval);
      return 1;
    }

  /* 3: Check that pam data is properly set and replaced */
  __PAM_TO_MODULE(pamh);
  dataptr = strdup ("test3a");
  retval = pam_set_data (pamh, "tst-pam_get_data-3", dataptr,
			 tst_str_data_cleanup);
  if (retval != PAM_SUCCESS)
    {
      free (dataptr);
      fprintf (stderr,
	       "test3a: first pam_set_data failed: %d (%s)\n",
	       retval, pam_strerror (pamh, retval));
      return 1;
    }

  retval = pam_get_data (pamh, "tst-pam_get_data-3", &constdataptr);
  if (retval != PAM_SUCCESS)
    {
      fprintf (stderr,
	       "test3a: first pam_get_data failed: %d (%s)\n",
	       retval, pam_strerror (pamh, retval));
      return 1;
    }

  if (constdataptr != dataptr)
    {
      fprintf (stderr,
	       "test3a: first pam_get_data data is not matching %p: %p\n",
	       constdataptr, dataptr);
      return 1;
    }

  if (strcmp ((const char *) constdataptr, "test3a") != 0)
    {
      fprintf (stderr,
	       "test3a: first pam_get_data strings are not matching: '%s' vs '%s'\n",
	       (const char *) constdataptr, "test3a");
      return 1;
    }

  dataptr = strdup ("test3a");
  retval = pam_set_data (pamh, "tst-pam_get_data-3", dataptr,
			 tst_str_data_cleanup);
  if (retval != PAM_SUCCESS)
    {
      free (dataptr);
      fprintf (stderr,
	       "test3a: second pam_set_data failed: %d (%s)\n",
	       retval, pam_strerror (pamh, retval));
      return 1;
    }

  retval = pam_get_data (pamh, "tst-pam_get_data-3", &constdataptr);
  if (retval != PAM_SUCCESS)
    {
      fprintf (stderr,
	       "test3a: second pam_get_data failed: %d (%s)\n",
	       retval, pam_strerror (pamh, retval));
      return 1;
    }

  if (constdataptr != dataptr)
    {
      fprintf (stderr,
	       "test3a: second pam_get_data data is not matching %p: %p\n",
	       constdataptr, dataptr);
      return 1;
    }

  if (strcmp ((const char *) constdataptr, "test3a") != 0)
    {
      fprintf (stderr,
	       "test3a: second pam_get_data strings are not matching: '%s' vs '%s'\n",
	       (const char *) constdataptr, "test3a");
      return 1;
    }

  /* 4: Check that pam an error is returned when getting NULL data */
  __PAM_TO_MODULE(pamh);
  dataptr = strdup ("test4a");
  retval = pam_set_data (pamh, "tst-pam_get_data-4", dataptr,
			 tst_str_data_cleanup);
  if (retval != PAM_SUCCESS)
    {
      free (dataptr);
      fprintf (stderr,
	       "test4a: first pam_set_data failed: %d (%s)\n",
	       retval, pam_strerror (pamh, retval));
      return 1;
    }

  retval = pam_get_data (pamh, "tst-pam_get_data-4", &constdataptr);
  if (retval != PAM_SUCCESS)
    {
      fprintf (stderr,
	       "test4a: first pam_get_data failed: %d (%s)\n",
	       retval, pam_strerror (pamh, retval));
      return 1;
    }

  if (constdataptr != dataptr)
    {
      fprintf (stderr,
	       "test4a: first pam_get_data data is not matching %p: %p\n",
	       constdataptr, dataptr);
      return 1;
    }

  retval = pam_set_data (pamh, "tst-pam_get_data-4", NULL, NULL);
  if (retval != PAM_SUCCESS)
    {
      fprintf (stderr,
	       "test4a: second pam_set_data failed: %d (%s)\n",
	       retval, pam_strerror (pamh, retval));
      return 1;
    }

  retval = pam_get_data (pamh, "tst-pam_get_data-4", &constdataptr);
  if (retval != PAM_NO_MODULE_DATA)
    {
      fprintf (stderr,
	       "test4a: pam_set_data did not fail as expected failed: %d (%s)\n",
	       retval, pam_strerror (pamh, retval));
      return 1;
    }

  /* 5: get pam data can get values after unsetting them */
  __PAM_TO_MODULE(pamh);
  dataptr = strdup ("test5a");
  retval = pam_set_data (pamh, "tst-pam_set_data-5a", dataptr,
			 tst_str_data_cleanup);
  if (retval != PAM_SUCCESS)
    {
      fprintf (stderr,
	       "test5a: pam_set_data failed: %d (%s)\n",
	       retval, pam_strerror (pamh, retval));
      return 1;
    }

  dataptr = strdup ("test5b");
  retval = pam_set_data (pamh, "tst-pam_set_data-5b", dataptr,
			 tst_str_data_cleanup);
  if (retval != PAM_SUCCESS)
    {
      fprintf (stderr,
	       "test5b: pam_set_data failed: %d (%s)\n",
	       retval, pam_strerror (pamh, retval));
      return 1;
    }

  dataptr = strdup ("test5c");
  retval = pam_set_data (pamh, "tst-pam_set_data-5c", dataptr,
			 tst_str_data_cleanup);
  if (retval != PAM_SUCCESS)
    {
      fprintf (stderr,
	       "test5c: pam_set_data failed: %d (%s)\n",
	       retval, pam_strerror (pamh, retval));
      return 1;
    }

  retval = pam_get_data (pamh, "tst-pam_set_data-5a", &constdataptr);
  if (retval != PAM_SUCCESS)
    {
      fprintf (stderr,
	       "test5d: pam_get_data failed: %d (%s)\n",
	       retval, pam_strerror (pamh, retval));
      return 1;
    }
  retval = pam_get_data (pamh, "tst-pam_set_data-5b", &constdataptr);
  if (retval != PAM_SUCCESS)
    {
      fprintf (stderr,
	       "test5e: pam_get_data failed: %d (%s)\n",
	       retval, pam_strerror (pamh, retval));
      return 1;
    }
  retval = pam_get_data (pamh, "tst-pam_set_data-5c", &constdataptr);
  if (retval != PAM_SUCCESS)
    {
      fprintf (stderr,
	       "test5f: pam_get_data failed: %d (%s)\n",
	       retval, pam_strerror (pamh, retval));
      return 1;
    }

  retval = pam_set_data (pamh, "tst-pam_set_data-5b", NULL, NULL);
  if (retval != PAM_SUCCESS)
    {
      fprintf (stderr,
	       "test5g: pam_set_data failed: %d (%s)\n",
	       retval, pam_strerror (pamh, retval));
      return 1;
    }

  retval = pam_get_data (pamh, "tst-pam_set_data-5a", &constdataptr);
  if (retval != PAM_SUCCESS)
    {
      fprintf (stderr,
	       "test5h: pam_get_data failed: %d (%s)\n",
	       retval, pam_strerror (pamh, retval));
      return 1;
    }
  retval = pam_get_data (pamh, "tst-pam_set_data-5b", &constdataptr);
  if (retval != PAM_NO_MODULE_DATA)
    {
      fprintf (stderr,
	       "test5i: pam_get_data did not fail as expected failed: %d (%s)\n",
	       retval, pam_strerror (pamh, retval));
      return 1;
    }
  retval = pam_get_data (pamh, "tst-pam_set_data-5c", &constdataptr);
  if (retval != PAM_SUCCESS)
    {
      fprintf (stderr,
	       "test5j: pam_get_data failed: %d (%s)\n",
	       retval, pam_strerror (pamh, retval));
      return 1;
    }

  retval = pam_set_data (pamh, "tst-pam_set_data-5a", NULL, NULL);
  if (retval != PAM_SUCCESS)
    {
      fprintf (stderr,
	       "test5k: pam_set_data failed: %d (%s)\n",
	       retval, pam_strerror (pamh, retval));
      return 1;
    }
  retval = pam_get_data (pamh, "tst-pam_set_data-5a", &constdataptr);
  if (retval != PAM_NO_MODULE_DATA)
    {
      fprintf (stderr,
	       "test5l: pam_get_data did not fail as expected failed: %d (%s)\n",
	       retval, pam_strerror (pamh, retval));
      return 1;
    }
  retval = pam_get_data (pamh, "tst-pam_set_data-5b", &constdataptr);
  if (retval != PAM_NO_MODULE_DATA)
    {
      fprintf (stderr,
	       "test5m: pam_get_data did not fail as expected failed: %d (%s)\n",
	       retval, pam_strerror (pamh, retval));
      return 1;
    }
  retval = pam_get_data (pamh, "tst-pam_set_data-5c", &constdataptr);
  if (retval != PAM_SUCCESS)
    {
      fprintf (stderr,
	       "test5n: pam_get_data failed: %d (%s)\n",
	       retval, pam_strerror (pamh, retval));
      return 1;
    }

  retval = pam_set_data (pamh, "tst-pam_set_data-5c", NULL, NULL);
  if (retval != PAM_SUCCESS)
    {
      fprintf (stderr,
	       "test5o: pam_set_data failed: %d (%s)\n",
	       retval, pam_strerror (pamh, retval));
      return 1;
    }
  retval = pam_get_data (pamh, "tst-pam_set_data-5a", &constdataptr);
  if (retval != PAM_NO_MODULE_DATA)
    {
      fprintf (stderr,
	       "test5p: pam_get_data did not fail as expected failed: %d (%s)\n",
	       retval, pam_strerror (pamh, retval));
      return 1;
    }
  retval = pam_get_data (pamh, "tst-pam_set_data-5b", &constdataptr);
  if (retval != PAM_NO_MODULE_DATA)
    {
      fprintf (stderr,
	       "test5q: pam_get_data did not fail as expected failed: %d (%s)\n",
	       retval, pam_strerror (pamh, retval));
      return 1;
    }
  retval = pam_get_data (pamh, "tst-pam_set_data-5c", &constdataptr);
  if (retval != PAM_NO_MODULE_DATA)
    {
      fprintf (stderr,
	       "test5r: pam_get_data did not fail as expected failed: %d (%s)\n",
	       retval, pam_strerror (pamh, retval));
      return 1;
    }

  dataptr = strdup ("test5d");
  retval = pam_set_data (pamh, "tst-pam_set_data-5d", dataptr,
			 tst_str_data_cleanup);
  if (retval != PAM_SUCCESS)
    {
      fprintf (stderr,
	       "test5s: pam_set_data failed: %d (%s)\n",
	       retval, pam_strerror (pamh, retval));
      return 1;
    }

  __PAM_TO_APP(pamh);

  retval = pam_end (pamh, PAM_SUCCESS);
  if (retval != PAM_SUCCESS)
    {
      fprintf (stderr,
	       "pam_end reported an error: %d (%s)\n",
	       retval, pam_strerror (pamh, retval));
      return 1;
    }

  return 0;
}
