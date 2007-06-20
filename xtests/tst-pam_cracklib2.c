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

/* This test case checks
   Patch 1688777: pam_cracklib support for minimum character classes */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <security/pam_appl.h>

/* A conversation function which uses an internally-stored value for
   the responses. */
static int
fake_conv (int num_msg, const struct pam_message **msgm UNUSED,
	   struct pam_response **response, void *appdata_ptr UNUSED)
{
  static int calls = 0;
  struct pam_response *reply;
  int count;

  /* Sanity test. */
  if (num_msg <= 0)
    return PAM_CONV_ERR;

  /* Allocate memory for the responses. */
  reply = calloc (num_msg, sizeof (struct pam_response));
  if (reply == NULL)
    return PAM_CONV_ERR;

  /* Each prompt elicits the same response. */
  for (count = 0; count < num_msg; ++count)
    {
      reply[count].resp_retcode = 0;
      /* first tow calls get a correct password, second a too
	 easy one. */
      if (calls > 1)
	reply[count].resp = strdup ("too easy");
      else
	{
	  ++calls;
	  reply[count].resp = strdup ("1a9C*8dK");
	}
    }

  /* Set the pointers in the response structure and return. */
  *response = reply;
  return PAM_SUCCESS;
}

static struct pam_conv conv = {
    fake_conv,
    NULL
};


int
main(int argc, char *argv[])
{
  pam_handle_t *pamh=NULL;
  const char *user="root";
  int retval;
  int debug = 0;

  /* Simulate passwd call by normal user */
  setuid (65534);

  if (argc > 1 && strcmp (argv[1], "-d") == 0)
    debug = 1;

  retval = pam_start("tst-pam_cracklib2", user, &conv, &pamh);
  if (retval != PAM_SUCCESS)
    {
      if (debug)
	fprintf (stderr, "cracklib2: pam_start returned %d\n", retval);
      return 1;
    }

  /* Try one, first input is correct, second is NULL */
  retval = pam_chauthtok (pamh, 0);
  if (retval != PAM_SUCCESS)
    {
      if (debug)
	fprintf (stderr, "cracklib2-1: pam_chauthtok returned %d\n", retval);
      return 1;
    }

  /* Try two, second input is NULL */
  retval = pam_chauthtok (pamh, 0);
  if (retval != PAM_AUTHTOK_ERR)
    {
      if (debug)
        fprintf (stderr, "cracklib2-2: pam_chauthtok returned %d\n", retval);
      return 1;
    }


  retval = pam_end (pamh,retval);
  if (retval != PAM_SUCCESS)
    {
      if (debug)
	fprintf (stderr, "cracklib2: pam_end returned %d\n", retval);
      return 1;
    }
  return 0;
}
