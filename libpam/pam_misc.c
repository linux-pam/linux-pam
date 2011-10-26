/* pam_misc.c -- This is random stuff
 *
 * Copyright (c) Andrew G. Morgan <morgan@kernel.org> 2000-2003
 * All rights reserved.
 *
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

#include "pam_private.h"

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <ctype.h>

char *_pam_StrTok(char *from, const char *format, char **next)
/*
 * this function is a variant of the standard strtok, it differs in that
 * it takes an additional argument and doesn't nul terminate tokens until
 * they are actually reached.
 */
{
     char table[256], *end;
     int i;

     if (from == NULL && (from = *next) == NULL)
	  return from;

     /* initialize table */
     for (i=1; i<256; table[i++] = '\0');
     for (i=0; format[i] ;
	  table[(unsigned char)format[i++]] = 'y');

     /* look for first non-format char */
     while (*from && table[(unsigned char)*from]) {
	  ++from;
     }

     if (*from == '[') {
	 /*
	  * special case, "[...]" is considered to be a single
	  * object.  Note, however, if one of the format[] chars is
	  * '[' this single string will not be read correctly.
	  * Note, any '[' inside the outer "[...]" pair will survive.
	  * Note, the first ']' will terminate this string, but
	  *  that "\]" will get compressed into "]". That is:
	  *
	  *   "[..[..\]..]..." --> "..[..].."
	  */
	 char *to;
	 for (to=end=++from; *end && *end != ']'; ++to, ++end) {
	     if (*end == '\\' && end[1] == ']')
		 ++end;
	     if (to != end) {
		 *to = *end;
	     }
	 }
	 if (to != end) {
	     *to = '\0';
	 }
	 /* note, this string is stripped of its edges: "..." is what
            remains */
     } else if (*from) {
	 /* simply look for next blank char */
	 for (end=from; *end && !table[(unsigned char)*end]; ++end);
     } else {
	 return (*next = NULL);                    /* no tokens left */
     }

     /* now terminate what we have */
     if (*end)
	 *end++ = '\0';

     /* indicate what it left */
     if (*end) {
	 *next = end;
     } else {
	 *next = NULL;                      /* have found last token */
     }

     /* return what we have */
     return from;
}

/*
 * Safe duplication of character strings. "Paranoid"; don't leave
 * evidence of old token around for later stack analysis.
 */

char *_pam_strdup(const char *x)
{
     register char *new=NULL;

     if (x != NULL) {
	  register int len;

	  len = strlen (x) + 1;  /* length of string including NUL */
	  if ((new = malloc(len)) == NULL) {
	       len = 0;
	       pam_syslog(NULL, LOG_CRIT, "_pam_strdup: failed to get memory");
	  } else {
	       strcpy (new, x);
	  }
	  x = NULL;
     }

     return new;                 /* return the duplicate or NULL on error */
}

/*
 * Safe duplication of memory buffers. "Paranoid"; don't leave
 * evidence of old token around for later stack analysis.
 */

char *_pam_memdup(const char *x, int len)
{
     register char *new=NULL;

     if (x != NULL) {
         if ((new = malloc(len)) == NULL) {
             len = 0;
             pam_syslog(NULL, LOG_CRIT, "_pam_memdup: failed to get memory");
         } else {
             memcpy (new, x, len);
         }
         x = NULL;
     }

     return new;                 /* return the duplicate or NULL on error */
}

/* Generate argv, argc from s */
/* caller must free(argv)     */

int _pam_mkargv(char *s, char ***argv, int *argc)
{
    int l;
    int argvlen = 0;
    char *sbuf, *sbuf_start;
    char **our_argv = NULL;
    char **argvbuf;
    char *argvbufp;
#ifdef PAM_DEBUG
    int count=0;
#endif

    D(("_pam_mkargv called: %s",s));

    *argc = 0;

    l = strlen(s);
    if (l) {
	if ((sbuf = sbuf_start = _pam_strdup(s)) == NULL) {
	    pam_syslog(NULL, LOG_CRIT,
		       "pam_mkargv: null returned by _pam_strdup");
	    D(("arg NULL"));
	} else {
	    /* Overkill on the malloc, but not large */
	    argvlen = (l + 1) * ((sizeof(char)) + sizeof(char *));
	    if ((our_argv = argvbuf = malloc(argvlen)) == NULL) {
		pam_syslog(NULL, LOG_CRIT,
			   "pam_mkargv: null returned by malloc");
	    } else {
		char *tmp=NULL;

		argvbufp = (char *) argvbuf + (l * sizeof(char *));
		D(("[%s]",sbuf));
		while ((sbuf = _pam_StrTok(sbuf, " \n\t", &tmp))) {
		    D(("arg #%d",++count));
		    D(("->[%s]",sbuf));
		    strcpy(argvbufp, sbuf);
		    D(("copied token"));
		    *argvbuf = argvbufp;
		    argvbufp += strlen(argvbufp) + 1;
		    D(("stepped in argvbufp"));
		    (*argc)++;
		    argvbuf++;
		    sbuf = NULL;
		    D(("loop again?"));
		}
	    }
	    _pam_drop(sbuf_start);
	}
    }

    *argv = our_argv;

    D(("_pam_mkargv returned"));

    return(argvlen);
}

/*
 * this function is used to protect the modules from accidental or
 * semi-mallicious harm that an application may do to confuse the API.
 */

void _pam_sanitize(pam_handle_t *pamh)
{
    int old_caller_is = pamh->caller_is;

    /*
     * this is for security. We reset the auth-tokens here.
     */
    __PAM_TO_MODULE(pamh);
    pam_set_item(pamh, PAM_AUTHTOK, NULL);
    pam_set_item(pamh, PAM_OLDAUTHTOK, NULL);
    pamh->caller_is = old_caller_is;
}

/*
 * This function scans the array and replaces the _PAM_ACTION_UNDEF
 * entries with the default action.
 */

void _pam_set_default_control(int *control_array, int default_action)
{
    int i;

    for (i=0; i<_PAM_RETURN_VALUES; ++i) {
	if (control_array[i] == _PAM_ACTION_UNDEF) {
	    control_array[i] = default_action;
	}
    }
}

/*
 * This function is used to parse a control string.  This string is a
 * series of tokens of the following form:
 *
 *               "[ ]*return_code[ ]*=[ ]*action/[ ]".
 */

#include "pam_tokens.h"

void _pam_parse_control(int *control_array, char *tok)
{
    const char *error;
    int ret;

    while (*tok) {
	int act, len;

	/* skip leading space */
	while (isspace((int)*tok) && *++tok);
	if (!*tok)
	    break;

	/* identify return code */
	for (ret=0; ret<=_PAM_RETURN_VALUES; ++ret) {
	    len = strlen(_pam_token_returns[ret]);
	    if (!strncmp(_pam_token_returns[ret], tok, len)) {
		break;
	    }
	}
	if (ret > _PAM_RETURN_VALUES || !*(tok += len)) {
	    error = "expecting return value";
	    goto parse_error;
	}

	/* observe '=' */
	while (isspace((int)*tok) && *++tok);
	if (!*tok || *tok++ != '=') {
	    error = "expecting '='";
	    goto parse_error;
	}

	/* skip leading space */
	while (isspace((int)*tok) && *++tok);
	if (!*tok) {
	    error = "expecting action";
	    goto parse_error;
	}

	/* observe action type */
	for (act=0; act < (-(_PAM_ACTION_UNDEF)); ++act) {
	    len = strlen(_pam_token_actions[act]);
	    if (!strncmp(_pam_token_actions[act], tok, len)) {
		act *= -1;
		tok += len;
		break;
	    }
	}
	if (act > 0) {
	    /*
	     * Either we have a number or we have hit an error.  In
	     * principle, there is nothing to stop us accepting
	     * negative offsets. (Although we would have to think of
	     * another way of encoding the tokens.)  However, I really
	     * think this would be both hard to administer and easily
	     * cause looping problems.  So, for now, we will just
	     * allow forward jumps.  (AGM 1998/1/7)
	     */
	    if (!isdigit((int)*tok)) {
		error = "expecting jump number";
		goto parse_error;
	    }
	    /* parse a number */
	    act = 0;
	    do {
		act *= 10;
		act += *tok - '0';      /* XXX - this assumes ascii behavior */
	    } while (*++tok && isdigit((int)*tok));
	    if (! act) {
		/* we do not allow 0 jumps.  There is a token ('ignore')
                   for that */
		error = "expecting non-zero";
		goto parse_error;
	    }
	}

	/* set control_array element */
	if (ret != _PAM_RETURN_VALUES) {
	    control_array[ret] = act;
	} else {
	    /* set the default to 'act' */
	    _pam_set_default_control(control_array, act);
	}
    }

    /* that was a success */
    return;

parse_error:
    /* treat everything as bad */
    pam_syslog(NULL, LOG_ERR, "pam_parse: %s; [...%s]", error, tok);
    for (ret=0; ret<_PAM_RETURN_VALUES; control_array[ret++]=_PAM_ACTION_BAD);

}
