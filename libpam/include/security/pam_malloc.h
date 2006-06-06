/*
 * <security/pam_appl.h>
 *
 * This file (via the use of macros) defines a wrapper for the malloc
 * family of calls. It logs where the memory was requested and also
 * where it was free()'d and keeps a list of currently requested memory.
 *
 * It is hoped that it will provide some help in locating memory leaks.
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

#ifndef PAM_MALLOC_H
#define PAM_MALLOC_H

#ifdef __cplusplus
extern "C" {
#endif

/* these are the macro definitions for the stdlib.h memory functions */

#define malloc(s)      pam_malloc(s,__FILE__,__FUNCTION__,__LINE__)
#define calloc(n,s)    pam_calloc(n,s,__FILE__,__FUNCTION__,__LINE__)
#define free(x)        pam_free(x,__FILE__,__FUNCTION__,__LINE__)
#define realloc(x,s)   pam_realloc(x,s,__FILE__,__FUNCTION__,__LINE__)
#define exit(i)        pam_exit(i,__FILE__,__FUNCTION__,__LINE__)
#undef strdup
#define strdup(s)      pam_strdup(s,__FILE__,__FUNCTION__,__LINE__)

/* these are the prototypes for the wrapper functions */

#include <sys/types.h>

extern void *pam_malloc(size_t s,const char *,const char *, int);
extern void *pam_calloc(size_t n,size_t s,const char *,const char *, int);
extern void  pam_free(void *x,const char *,const char *, int);
extern void *pam_memalign(size_t a,size_t s
			 ,const char *,const char *, int);
extern void *pam_realloc(void *x,size_t s,const char *,const char *, int);
extern void *pam_valloc(size_t s,const char *,const char *, int);
extern void *pam_alloca(size_t s,const char *,const char *, int);
extern void  pam_exit(int i,const char *,const char *, int);
extern char *pam_strdup(const char *,const char *,const char *, int);

/* these are the flags used to turn on and off diagnostics */

#define PAM_MALLOC_LEAKED             01
#define PAM_MALLOC_REQUEST            02
#define PAM_MALLOC_FREE               04
#define PAM_MALLOC_EXCH               (PAM_MALLOC_FREED|PAM_MALLOC_EXCH)
#define PAM_MALLOC_RESIZE            010
#define PAM_MALLOC_FAIL              020
#define PAM_MALLOC_NULL              040
#define PAM_MALLOC_VERIFY           0100
#define PAM_MALLOC_FUNC             0200
#define PAM_MALLOC_PAUSE            0400
#define PAM_MALLOC_STOP            01000

#define PAM_MALLOC_ALL              0777

#define PAM_MALLOC_DEFAULT     \
  (PAM_MALLOC_LEAKED|PAM_MALLOC_PAUSE|PAM_MALLOC_FAIL)

#include <stdio.h>

extern FILE *pam_malloc_outfile;      /* defaults to stdout */

/* how much output do you want? */

extern int pam_malloc_flags;
extern int pam_malloc_delay_length;      /* how long to pause on errors */

#ifdef __cplusplus
}
#endif

#endif /* PAM_MALLOC_H */
