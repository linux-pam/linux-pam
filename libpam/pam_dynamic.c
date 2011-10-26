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

#include "pam_private.h"

#ifndef PAM_STATIC

#ifdef PAM_SHL
# include <dl.h>
#elif defined(PAM_DYLD)
# include <mach-o/dyld.h>
#else /* PAM_SHL */
# include <dlfcn.h>
#endif /* PAM_SHL */

#ifndef SHLIB_SYM_PREFIX
#define SHLIB_SYM_PREFIX "_"
#endif

void *_pam_dlopen(const char *mod_path)
{
#ifdef PAM_SHL
	return shl_load(mod_path, BIND_IMMEDIATE, 0L);
#elif defined(PAM_DYLD)
	NSObjectFileImage ofile;
	void *ret = NULL;

	if (NSCreateObjectFileImageFromFile(mod_path, &ofile) !=
			NSObjectFileImageSuccess )
		return NULL;

	ret = NSLinkModule(ofile, mod_path, NSLINKMODULE_OPTION_PRIVATE | NSLINKMODULE_OPTION_BINDNOW);
	NSDestroyObjectFileImage(ofile);

	return ret;
#else
	return dlopen(mod_path, RTLD_NOW);
#endif
}

servicefn _pam_dlsym(void *handle, const char *symbol)
{
#ifdef PAM_SHL
	char *_symbol = NULL;
	servicefn ret;

	if( symbol == NULL )
		return NULL;

	if( shl_findsym(&handle, symbol, (short) TYPE_PROCEDURE, &ret ){
		_symbol = malloc( strlen(symbol) + sizeof(SHLIB_SYM_PREFIX) + 1 );
		if( _symbol == NULL )
			return NULL;
		strcpy(_symbol, SHLIB_SYM_PREFIX);
		strcat(_symbol, symbol);
		if( shl_findsym(&handle, _symbol,
				(short) TYPE_PROCEDURE, &ret ){
			free(_symbol);
			return NULL;
		}
		free(_symbol);
	}

	return ret;

#elif defined(PAM_DYLD)
	NSSymbol nsSymbol;
	char *_symbol;

	if( symbol == NULL )
		return NULL;
	_symbol = malloc( strlen(symbol) + 2 );
	if( _symbol == NULL )
		return NULL;
	strcpy(_symbol, SHLIB_SYM_PREFIX);
	strcat(_symbol, symbol);

	nsSymbol = NSLookupSymbolInModule(handle, _symbol);
	if( nsSymbol == NULL )
		return NULL;
	free(_symbol);

	return (servicefn)NSAddressOfSymbol(nsSymbol);
#else
	return (servicefn) dlsym(handle, symbol);
#endif
}

void _pam_dlclose(void *handle)
{
#ifdef PAM_SHL
	shl_unload(handle);
#elif defined(PAM_DYLD)
	NSUnLinkModule((NSModule)handle, NSUNLINKMODULE_OPTION_NONE);
#else
	dlclose(handle);
#endif

	return;
}

const char *
_pam_dlerror (void)
{
#if defined(PAM_SHL) || defined(PAM_DYLD)
        return "unknown";
#else
        return dlerror ();
#endif
}

#endif
