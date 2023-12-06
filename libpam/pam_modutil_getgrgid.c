/*
 * $Id$
 *
 * This function provides a thread safer version of getgrgid() for use
 * with PAM modules that care about this sort of thing.
 *
 * XXX - or at least it should provide a thread-safe alternative.
 */

#include "pam_modutil_private.h"

#include <errno.h>
#include <limits.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>

struct group *
pam_modutil_getgrgid(pam_handle_t *pamh UNUSED, gid_t gid)
{
#ifdef HAVE_GETGRGID_R

    void *buffer=NULL;
    size_t length = PWD_INITIAL_LENGTH;

    do {
	int status;
	void *new_buffer;
	struct group *result = NULL;

	new_buffer = realloc(buffer, sizeof(struct group) + length);
	if (new_buffer == NULL) {

	    D(("out of memory"));

	    /* no memory for the user - so delete the memory */
	    if (buffer) {
		free(buffer);
	    }
	    return NULL;
	}
	buffer = new_buffer;

	/* make the re-entrant call to get the grp structure */
	errno = 0;
	status = getgrgid_r(gid, buffer,
			    sizeof(struct group) + (char *) buffer,
			    length, &result);
	if (!status && (result == buffer)) {
	    D(("success"));
	    return result;
	} else if (errno != ERANGE && errno != EINTR) {
		/* no sense in repeating the call */
		break;
	}

	length <<= PWD_LENGTH_SHIFT;

    } while (length < PWD_ABSURD_PWD_LENGTH);

    D(("grp structure took %zu bytes or so of memory",
       length+sizeof(struct group)));

    free(buffer);
    return NULL;

#else /* ie. ifndef HAVE_GETGRGID_R */

    /*
     * Sorry, there does not appear to be a reentrant version of
     * getgrgid(). So, we use the standard libc function.
     */

    return getgrgid(gid);

#endif /* def HAVE_GETGRGID_R */
}
