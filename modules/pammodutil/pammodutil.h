#ifndef PAMMODUTIL_H
#define PAMMODUTIL_H

/*
 * $Id$
 *
 * Copyright (c) 2001 Andrew Morgan <morgan@kernel.org>
 */

#include <security/_pam_aconf.h>
#include <security/_pam_macros.h>
#include <security/pam_modules.h>
#include <security/_pam_modutil.h>

#define PWD_INITIAL_LENGTH     0x100
#define PWD_ABSURD_PWD_LENGTH  0x8000

/* This is a simple cleanup, it just free()s the 'data' memory */
extern void _pammodutil_cleanup(pam_handle_t *pamh, void *data,
				int error_status);

#endif /* PAMMODUTIL_H */
