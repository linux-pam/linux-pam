#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>

#include <security/pam_appl.h>
#include <security/pam_misc.h>

int main(int argc, char **argv)
{
    void *handle;

    handle = dlopen("./pam.so", RTLD_NOW);
    if (handle == NULL) {
	fprintf(stderr, "failed to load pam.so: %s\n", dlerror());
	exit(1);
    }

    /* handle->XXX points to each of the PAM functions */
    
    
    if (dlclose(handle)) {
	fprintf(stderr, "failed to unload pam.so: %s\n", dlerror());
	exit(1);
    }

    exit(0);
}
