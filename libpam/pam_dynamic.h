#ifndef _PAM_DYNAMIC_H
#define _PAM_DYNAMIC_H

typedef int (*servicefn)(pam_handle_t *, int, int, char **);

void *_pam_dlopen (const char *mod_path);
servicefn _pam_dlsym (void *handle, const char *symbol);
void _pam_dlclose (void *handle);
const char *_pam_dlerror (void);

#endif
