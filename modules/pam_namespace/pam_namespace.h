/******************************************************************************
 * A module for Linux-PAM that will set the default namespace after 
 * establishing a session via PAM.
 *
 * (C) Copyright IBM Corporation 2005
 * (C) Copyright Red Hat 2006
 * All Rights Reserved.
 *
 * Written by: Janak Desai <janak@us.ibm.com>
 * With Revisions by: Steve Grubb <sgrubb@redhat.com>
 * Derived from a namespace setup patch by Chad Sellers <cdselle@tycho.nsa.gov>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * on the rights to use, copy, modify, merge, publish, distribute, sub
 * license, and/or sell copies of the Software, and to permit persons to whom
 * the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT.  IN NO EVENT SHALL
 * IBM AND/OR THEIR SUPPLIERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#if !(defined(linux))
#error THIS CODE IS KNOWN TO WORK ONLY ON LINUX !!!
#endif

#include "config.h"

#include <stdio.h>
#include <stdio_ext.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <pwd.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <libgen.h>
#include <fcntl.h>
#include <sched.h>
#include "security/pam_modules.h"
#include "security/pam_modutil.h"
#include "security/pam_ext.h"
#include "md5.h"

#ifdef WITH_SELINUX
#include <selinux/selinux.h>
#endif

#ifndef CLONE_NEWNS
#define CLONE_NEWNS 0x00020000 /* Flag to create new namespace */
#endif

/*
 * Module defines
 */
#ifndef PAM_NAMESPACE_CONFIG
#define PAM_NAMESPACE_CONFIG "/etc/security/namespace.conf"
#endif

#ifndef NAMESPACE_INIT_SCRIPT
#define NAMESPACE_INIT_SCRIPT "/etc/security/namespace.init"
#endif

#define PAMNS_DEBUG           0x00000100 /* Running in debug mode */
#define PAMNS_SELINUX_ENABLED 0x00000400 /* SELinux is enabled */
#define PAMNS_CTXT_BASED_INST 0x00000800 /* Context based instance needed */
#define PAMNS_GEN_HASH        0x00002000 /* Generate md5 hash for inst names */
#define PAMNS_IGN_CONFIG_ERR  0x00004000 /* Ignore format error in conf file */
#define PAMNS_IGN_INST_PARENT_MODE  0x00008000 /* Ignore instance parent mode */

/*
 * Polyinstantiation method options, based on user, security context
 * or both
 */
enum polymethod {
    USER,
    CONTEXT,
    BOTH,
};

/*
 * Depending on the application using this namespace module, we
 * may need to unmount priviously bind mounted instance directory.
 * Applications such as login and sshd, that establish a new 
 * session unmount of instance directory is not needed. For applications
 * such as su and newrole, that switch the identity, this module 
 * has to unmount previous instance directory first and re-mount
 * based on the new indentity. For other trusted applications that
 * just want to undo polyinstantiation, only unmount of previous
 * instance directory is needed.
 */
enum unmnt_op {
    NO_UNMNT,
    UNMNT_REMNT,
    UNMNT_ONLY,
};

/*
 * Structure that holds information about a directory to polyinstantiate
 */
struct polydir_s {
    char dir[PATH_MAX];    	       	/* directory to polyinstantiate */
    char instance_prefix[PATH_MAX];	/* prefix for instance dir path name */
    enum polymethod method;		/* method used to polyinstantiate */
    unsigned int num_uids;		/* number of override uids */
    uid_t *uid;				/* list of override uids */
    struct polydir_s *next;		/* pointer to the next polydir entry */
};

struct instance_data {
    pam_handle_t *pamh;		/* The pam handle for this instance */
    struct polydir_s *polydirs_ptr; /* The linked list pointer */
    char user[LOGIN_NAME_MAX];	/* User name */
    uid_t uid;			/* The uid of the user */
    unsigned long flags;		/* Flags for debug, selinux etc */
};
