/*
 * by Elliot Lee <sopwith@redhat.com>, Red Hat Software. July 25, 1996.
 * log refused access error christopher mccrory <chrismcc@netus.com> 1998/7/11
 *
 * This code began life as the pam_rootok module.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <syslog.h>
#include <stdarg.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>

#ifdef PAM_DEBUG
#include <assert.h>
#endif

/*
 * here, we make a definition for the externally accessible function
 * in this file (this definition is required for static a module
 * but strongly encouraged generally) it is used to instruct the
 * modules include file to define the function prototypes.
 */

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_PASSWORD
#define PAM_SM_SESSION

#include <security/pam_modules.h>
#include <security/_pam_macros.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>

/* --- authentication management functions (only) --- */

/* Extended Items that are not directly available via pam_get_item() */
#define EI_GROUP (1 << 0)
#define EI_SHELL (1 << 1)

/* Constants for apply= parameter */
#define APPLY_TYPE_NULL		0
#define APPLY_TYPE_NONE		1
#define APPLY_TYPE_USER		2
#define APPLY_TYPE_GROUP	3

#define LESSER(a, b) ((a) < (b) ? (a) : (b))

PAM_EXTERN int
pam_sm_authenticate (pam_handle_t *pamh, int flags UNUSED,
		     int argc, const char **argv)
{
    int retval, i, citem=0, extitem=0, onerr=PAM_SERVICE_ERR, sense=2, quiet=0;
    const void *void_citemp;
    const char *citemp;
    char *ifname=NULL;
    char aline[256];
    char mybuf[256],myval[256];
    struct stat fileinfo;
    FILE *inf;
    char apply_val[256];
    int apply_type;

    /* Stuff for "extended" items */
    struct passwd *userinfo;

    apply_type=APPLY_TYPE_NULL;
    memset(apply_val,0,sizeof(apply_val));

    for(i=0; i < argc; i++) {
	{
	    const char *junk;

	    /* option quiet has no value */
	    if(!strcmp(argv[i],"quiet")) {
		quiet = 1;
		continue;
	    }

	    memset(mybuf,'\0',sizeof(mybuf));
	    memset(myval,'\0',sizeof(myval));
	    junk = strchr(argv[i], '=');
	    if((junk == NULL) || (junk - argv[i]) >= (int) sizeof(mybuf)) {
		pam_syslog(pamh,LOG_ERR, "Bad option: \"%s\"",
			 argv[i]);
		continue;
	    }
	    strncpy(mybuf, argv[i],
		    LESSER(junk - argv[i], (int)sizeof(mybuf) - 1));
	    strncpy(myval, junk + 1, sizeof(myval) - 1);
	}
	if(!strcmp(mybuf,"onerr"))
	    if(!strcmp(myval,"succeed"))
		onerr = PAM_SUCCESS;
	    else if(!strcmp(myval,"fail"))
		onerr = PAM_SERVICE_ERR;
	    else {
	        if (ifname) free (ifname);
		return PAM_SERVICE_ERR;
	    }
	else if(!strcmp(mybuf,"sense"))
	    if(!strcmp(myval,"allow"))
		sense=0;
	    else if(!strcmp(myval,"deny"))
		sense=1;
	    else {
	        if (ifname) free (ifname);
		return onerr;
	    }
	else if(!strcmp(mybuf,"file")) {
	    if (ifname) free (ifname);
	    ifname = (char *)malloc(strlen(myval)+1);
	    if (!ifname)
		return PAM_BUF_ERR;
	    strcpy(ifname,myval);
	} else if(!strcmp(mybuf,"item"))
	    if(!strcmp(myval,"user"))
		citem = PAM_USER;
	    else if(!strcmp(myval,"tty"))
		citem = PAM_TTY;
	    else if(!strcmp(myval,"rhost"))
		citem = PAM_RHOST;
	    else if(!strcmp(myval,"ruser"))
		citem = PAM_RUSER;
	    else { /* These items are related to the user, but are not
		      directly gettable with pam_get_item */
		citem = PAM_USER;
		if(!strcmp(myval,"group"))
		    extitem = EI_GROUP;
		else if(!strcmp(myval,"shell"))
		    extitem = EI_SHELL;
		else
		    citem = 0;
	    } else if(!strcmp(mybuf,"apply")) {
		apply_type=APPLY_TYPE_NONE;
		memset(apply_val,'\0',sizeof(apply_val));
		if (myval[0]=='@') {
		    apply_type=APPLY_TYPE_GROUP;
		    strncpy(apply_val,myval+1,sizeof(apply_val)-1);
		} else {
		    apply_type=APPLY_TYPE_USER;
		    strncpy(apply_val,myval,sizeof(apply_val)-1);
		}
	    } else {
		free(ifname);
		pam_syslog(pamh,LOG_ERR, "Unknown option: %s",mybuf);
		return onerr;
	    }
    }

    if(!citem) {
	pam_syslog(pamh,LOG_ERR,
		  "Unknown item or item not specified");
	free(ifname);
	return onerr;
    } else if(!ifname) {
	pam_syslog(pamh,LOG_ERR, "List filename not specified");
	return onerr;
    } else if(sense == 2) {
	pam_syslog(pamh,LOG_ERR,
		  "Unknown sense or sense not specified");
	free(ifname);
	return onerr;
    } else if(
	      (apply_type==APPLY_TYPE_NONE) ||
	      ((apply_type!=APPLY_TYPE_NULL) && (*apply_val=='\0'))
              ) {
	pam_syslog(pamh,LOG_ERR,
		  "Invalid usage for apply= parameter");
        free (ifname);
	return onerr;
    }

    /* Check if it makes sense to use the apply= parameter */
    if (apply_type != APPLY_TYPE_NULL) {
	if((citem==PAM_USER) || (citem==PAM_RUSER)) {
	    pam_syslog(pamh,LOG_WARNING,
		      "Non-sense use for apply= parameter");
	    apply_type=APPLY_TYPE_NULL;
	}
	if(extitem && (extitem==EI_GROUP)) {
	    pam_syslog(pamh,LOG_WARNING,
		      "Non-sense use for apply= parameter");
	    apply_type=APPLY_TYPE_NULL;
	}
    }

    /* Short-circuit - test if this session apply for this user */
    {
	const char *user_name;
	int rval;

	rval=pam_get_user(pamh,&user_name,NULL);
	if((rval==PAM_SUCCESS) && user_name && user_name[0]) {
	    /* Got it ? Valid ? */
	    if(apply_type==APPLY_TYPE_USER) {
		if(strcmp(user_name, apply_val)) {
		    /* Does not apply to this user */
#ifdef PAM_DEBUG
		    pam_syslog(pamh,LOG_DEBUG,
			      "don't apply: apply=%s, user=%s",
			     apply_val,user_name);
#endif /* PAM_DEBUG */
		    free(ifname);
		    return PAM_IGNORE;
		}
	    } else if(apply_type==APPLY_TYPE_GROUP) {
		if(!pam_modutil_user_in_group_nam_nam(pamh,user_name,apply_val)) {
		    /* Not a member of apply= group */
#ifdef PAM_DEBUG
		    pam_syslog(pamh,LOG_DEBUG,

			     "don't apply: %s not a member of group %s",
			     user_name,apply_val);
#endif /* PAM_DEBUG */
		    free(ifname);
		    return PAM_IGNORE;
		}
	    }
	}
    }

    retval = pam_get_item(pamh,citem,&void_citemp);
    citemp = void_citemp;
    if(retval != PAM_SUCCESS) {
	free(ifname);
	return onerr;
    }
    if((citem == PAM_USER) && !citemp) {
	retval = pam_get_user(pamh,&citemp,NULL);
	if (retval != PAM_SUCCESS || !citemp) {
	    free(ifname);
	    return PAM_SERVICE_ERR;
	}
    }
    if((citem == PAM_TTY) && citemp) {
        /* Normalize the TTY name. */
        if(strncmp(citemp, "/dev/", 5) == 0) {
            citemp += 5;
        }
    }

    if(!citemp || (strlen(citemp) == 0)) {
	free(ifname);
	/* The item was NULL - we are sure not to match */
	return sense?PAM_SUCCESS:PAM_AUTH_ERR;
    }

    if(extitem) {
	switch(extitem) {
	    case EI_GROUP:
		/* Just ignore, call pam_modutil_in_group... later */
		break;
	    case EI_SHELL:
		/* Assume that we have already gotten PAM_USER in
		   pam_get_item() - a valid assumption since citem
		   gets set to PAM_USER in the extitem switch */
		userinfo = pam_modutil_getpwnam(pamh, citemp);
		if (userinfo == NULL) {
		    pam_syslog(pamh,LOG_ERR, "getpwnam(%s) failed",
			     citemp);
		    free(ifname);
		    return onerr;
		}
		citemp = userinfo->pw_shell;
		break;
	    default:
		pam_syslog(pamh,LOG_ERR,

			 "Internal weirdness, unknown extended item %d",
			 extitem);
		free(ifname);
		return onerr;
	}
    }
#ifdef PAM_DEBUG
    pam_syslog(pamh,LOG_INFO,

	     "Got file = %s, item = %d, value = %s, sense = %d",
	     ifname, citem, citemp, sense);
#endif
    if(lstat(ifname,&fileinfo)) {
	if(!quiet)
		pam_syslog(pamh,LOG_ERR, "Couldn't open %s",ifname);
	free(ifname);
	return onerr;
    }

    if((fileinfo.st_mode & S_IWOTH)
       || !S_ISREG(fileinfo.st_mode)) {
	/* If the file is world writable or is not a
	   normal file, return error */
	pam_syslog(pamh,LOG_ERR,
		 "%s is either world writable or not a normal file",
		 ifname);
	free(ifname);
	return PAM_AUTH_ERR;
    }

    inf = fopen(ifname,"r");
    if(inf == NULL) { /* Check that we opened it successfully */
	if (onerr == PAM_SERVICE_ERR) {
	    /* Only report if it's an error... */
	    pam_syslog(pamh,LOG_ERR,  "Error opening %s", ifname);
	}
	free(ifname);
	return onerr;
    }
    /* There should be no more errors from here on */
    retval=PAM_AUTH_ERR;
    /* This loop assumes that PAM_SUCCESS == 0
       and PAM_AUTH_ERR != 0 */
#ifdef PAM_DEBUG
    assert(PAM_SUCCESS == 0);
    assert(PAM_AUTH_ERR != 0);
#endif
    while((fgets(aline,sizeof(aline),inf) != NULL)
	  && retval) {
	char *a = aline;

	if(strlen(aline) == 0)
	    continue;
	if(aline[strlen(aline) - 1] == '\n')
	    aline[strlen(aline) - 1] = '\0';
	if(strlen(aline) == 0)
	    continue;
	if(aline[strlen(aline) - 1] == '\r')
	    aline[strlen(aline) - 1] = '\0';
	if(citem == PAM_TTY) {
	    if(strncmp(a, "/dev/", 5) == 0)
		a += 5;
	}
	if (extitem == EI_GROUP) {
	    retval = !pam_modutil_user_in_group_nam_nam(pamh,
		citemp, aline);
	} else {
	    retval = strcmp(a, citemp);
	}
    }

    fclose(inf);
    free(ifname);
    if ((sense && retval) || (!sense && !retval)) {
#ifdef PAM_DEBUG
	pam_syslog(pamh,LOG_INFO,
		 "Returning PAM_SUCCESS, retval = %d", retval);
#endif
	return PAM_SUCCESS;
    }
    else {
	const void *service;
	const char *user_name;
#ifdef PAM_DEBUG
	pam_syslog(pamh,LOG_INFO,
		 "Returning PAM_AUTH_ERR, retval = %d", retval);
#endif
	(void) pam_get_item(pamh, PAM_SERVICE, &service);
	(void) pam_get_user(pamh, &user_name, NULL);
	if (!quiet)
	    pam_syslog (pamh, LOG_ALERT, "Refused user %s for service %s",
	                user_name, (const char *)service);
	return PAM_AUTH_ERR;
    }
}

PAM_EXTERN int
pam_sm_setcred (pam_handle_t *pamh UNUSED, int flags UNUSED,
		int argc UNUSED, const char **argv UNUSED)
{
    return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_acct_mgmt (pam_handle_t *pamh, int flags,
		  int argc, const char **argv)
{
    return pam_sm_authenticate(pamh, flags, argc, argv);
}

PAM_EXTERN int
pam_sm_open_session (pam_handle_t *pamh, int flags,
		     int argc, const char **argv)
{
    return pam_sm_authenticate(pamh, flags, argc, argv);
}

PAM_EXTERN int
pam_sm_close_session (pam_handle_t *pamh, int flags,
		      int argc, const char **argv)
{
    return pam_sm_authenticate(pamh, flags, argc, argv);
}

PAM_EXTERN int
pam_sm_chauthtok (pam_handle_t *pamh, int flags,
		  int argc, const char **argv)
{
    return pam_sm_authenticate(pamh, flags, argc, argv);
}

#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_listfile_modstruct = {
    "pam_listfile",
    pam_sm_authenticate,
    pam_sm_setcred,
    pam_sm_acct_mgmt,
    pam_sm_open_session,
    pam_sm_close_session,
    pam_sm_chauthtok,
};

#endif /* PAM_STATIC */

/* end of module definition */
