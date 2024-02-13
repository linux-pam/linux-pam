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

#include "config.h"

#include "pam_private.h"

#include <stdlib.h>
#include <string.h>

int _pam_add_alloc(
    pam_handle_t *pamh,
    void *data)
{
    D(("called"));

    IF_NO_PAMH(pamh, PAM_SYSTEM_ERR);

    if (pamh->alloc.len >= pamh->alloc.size) {
	void **p;
	size_t n = pamh->alloc.len + 16;

	p = realloc(pamh->alloc.array, n * sizeof(void *));
	if (p == NULL) {
	    pam_syslog(pamh, LOG_CRIT,
		       "pam_add_alloc: cannot allocate data");
	    return PAM_BUF_ERR;
	}

	pamh->alloc.array = p;
	pamh->alloc.size = n;
    }

    pamh->alloc.array[pamh->alloc.len++] = data;

    return PAM_SUCCESS;
}

void _pam_free_alloc(pam_handle_t *pamh)
{
    size_t i;

    D(("called"));

    IF_NO_PAMH(pamh, /* no return value for void fn */);

    for (i = 0; i < pamh->alloc.len; i++) {
	_pam_drop(pamh->alloc.array[i]);
    }
    free(pamh->alloc.array);
    pamh->alloc.len = 0;
    pamh->alloc.size = 0;
}
