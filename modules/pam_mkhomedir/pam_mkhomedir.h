/*
 * $Id$
 *
 * this file is associated with the Linux-PAM mkhomedir module and its helper.
 * it was written by Valentin Lefebvre <valentin.lefebvre@suse.com>
 *
 */

#ifndef PAM_MKHOMEDIR_H
#define PAM_MKHOMEDIR_H

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

#include <security/pam_ext.h>
#include <security/pam_modutil.h>

#define SKELDIR "/etc/skel"
#ifdef VENDORDIR
#define VENDOR_SKELDIR (VENDORDIR "/skel")
#endif

#endif
