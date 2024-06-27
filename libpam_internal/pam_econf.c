/* pam_econf.c -- routines to parse configuration files with libeconf */

#include "config.h"

#ifdef USE_ECONF

#include <stdio.h>
#include <security/_pam_macros.h>
#include "pam_econf.h"

econf_err pam_econf_readconfig(econf_file **key_file,
			       const char *usr_conf_dir,
			       const char *etc_conf_dir,
			       const char *config_name,
			       const char *config_suffix,
			       const char *delim,
			       const char *comment,
			       bool (*callback)(const char *filename, const void *data),
			       const void *callback_data)
{
    econf_err ret;
    D(("Read configuration from directory %s and %s", etc_conf_dir, usr_conf_dir));
    ret = econf_readDirsWithCallback(key_file,
				     usr_conf_dir,
				     etc_conf_dir,
				     config_name,
				     config_suffix,
				     delim,
				     comment,
				     callback, callback_data);
    return ret;
}

#endif /* USE_ECONF */
