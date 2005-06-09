/* pam_motd module */

/*
 * Modified for pam_motd by Ben Collins <bcollins@debian.org>
 *
 * Based off of:
 * $Id$
 *
 * Written by Michael K. Johnson <johnsonm@redhat.com> 1996/10/24
 *
 */

#include <security/_pam_aconf.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>

#include <security/_pam_macros.h>
/*
 * here, we make a definition for the externally accessible function
 * in this file (this definition is required for static a module
 * but strongly encouraged generally) it is used to instruct the
 * modules include file to define the function prototypes.
 */

#define PAM_SM_SESSION
#define DEFAULT_MOTD	"/etc/motd"

#include <security/pam_modules.h>
#include <security/_pam_modutil.h>

/* --- session management functions (only) --- */

PAM_EXTERN
int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
                        const char **argv)
{
     return PAM_IGNORE;
}

static char default_motd[] = DEFAULT_MOTD;

PAM_EXTERN
int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
                   const char **argv)
{
     int retval = PAM_IGNORE;
     int fd;
     char *mtmp=NULL;
     char *motd_path=NULL;
     const void *void_conv;
     const struct pam_conv *conversation;
     struct pam_message message;
     struct pam_message *pmessage = &message;
     struct pam_response *resp = NULL;
     struct stat st;

     if (flags & PAM_SILENT) {
	return retval;
     }

    for (; argc-- > 0; ++argv) {
        if (!strncmp(*argv,"motd=",5)) {

            motd_path = (char *) strdup(5+*argv);
            if (motd_path != NULL) {
                D(("set motd path: %s", motd_path));
            } else {
                D(("failed to duplicate motd path - ignored"));
            }
	}
     }

     if (motd_path == NULL)
	motd_path = default_motd;

     message.msg_style = PAM_TEXT_INFO;

     if ((fd = open(motd_path, O_RDONLY, 0)) >= 0) {
       if (motd_path != default_motd)
         free(motd_path);
       /* fill in message buffer with contents of motd */
       if ((fstat(fd, &st) < 0) || !st.st_size) {
         close(fd);
         return retval;
       }
       message.msg = mtmp = malloc(st.st_size+1);
       /* if malloc failed... */
       if (!message.msg) {
           close(fd);
           return retval;
       }
       if (_pammodutil_read(fd, mtmp, st.st_size) == st.st_size) {
	   if (mtmp[st.st_size-1] == '\n')
		mtmp[st.st_size-1] = '\0';
	   else
		mtmp[st.st_size] = '\0';
	   close(fd);

 	   /* Use conversation function to give user contents of motd */
	   if (pam_get_item(pamh, PAM_CONV, &void_conv) ==
	               PAM_SUCCESS && void_conv) {
	       conversation = void_conv;
	       conversation->conv(1, (const struct pam_message **)&pmessage,
	            &resp, conversation->appdata_ptr);
	       if (resp)
	           _pam_drop_reply(resp, 1);
           }
       }
       free(mtmp);
     } else {
       if (motd_path != default_motd)
         free(motd_path);
     }

     return retval;
}


#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_motd_modstruct = {
     "pam_motd",
     NULL,
     NULL,
     NULL,
     pam_sm_open_session,
     pam_sm_close_session,
     NULL,
};

#endif

/* end of module definition */
