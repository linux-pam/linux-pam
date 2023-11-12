/*
 * pam_env module
 *
 * Written by Dave Kinchlea <kinch@kinch.ark.com> 1997/01/31
 * Inspired by Andrew Morgan <morgan@kernel.org>, who also supplied the
 * template for this file (via pam_mail)
 */

#define DEFAULT_ETC_ENVFILE     "/etc/environment"
#ifdef VENDORDIR
#define VENDOR_DEFAULT_ETC_ENVFILE (VENDORDIR "/environment")
#endif
#define DEFAULT_READ_ENVFILE    1

#define DEFAULT_USER_ENVFILE    ".pam_environment"
#define DEFAULT_USER_READ_ENVFILE 0

#include "config.h"

#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef USE_ECONF
#include <libeconf.h>
#endif

#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/_pam_macros.h>
#include <security/pam_ext.h>
#include "pam_inline.h"

/* This little structure makes it easier to keep variables together */

typedef struct var {
  char *name;
  char *value;
  char *defval;
  char *override;
} VAR;

#define DEFAULT_CONF_FILE	(SCONFIGDIR "/pam_env.conf")
#ifdef VENDOR_SCONFIGDIR
#define VENDOR_DEFAULT_CONF_FILE (VENDOR_SCONFIGDIR "/pam_env.conf")
#endif

#define BUF_SIZE 8192
#define MAX_ENV  8192

#define GOOD_LINE    0
#define BAD_LINE     100       /* This must be > the largest PAM_* error code */

#define DEFINE_VAR   101
#define UNDEFINE_VAR 102
#define ILLEGAL_VAR  103

/* This is a special value used to designate an empty string */
static char quote='\0';

static void free_string_array(char **array)
{
    if (array == NULL)
      return;
    for (char **entry = array; *entry != NULL; ++entry) {
      pam_overwrite_string(*entry);
      free(*entry);
    }
    free(array);
}

/* argument parsing */

#define PAM_DEBUG_ARG       0x01

static int
_pam_parse (const pam_handle_t *pamh, int argc, const char **argv,
	    const char **conffile, const char **envfile, int *readenv,
	    const char **user_envfile, int *user_readenv)
{
    int ctrl=0;

    *user_envfile = DEFAULT_USER_ENVFILE;
    *envfile = NULL;
    *readenv = DEFAULT_READ_ENVFILE;
    *user_readenv = DEFAULT_USER_READ_ENVFILE;
    *conffile = NULL;

    /* step through arguments */
    for (; argc-- > 0; ++argv) {
	const char *str;

	/* generic options */

	if (!strcmp(*argv,"debug"))
	    ctrl |= PAM_DEBUG_ARG;
	else if ((str = pam_str_skip_prefix(*argv, "conffile=")) != NULL) {
	  if (str[0] == '\0') {
	    pam_syslog(pamh, LOG_ERR,
		       "conffile= specification missing argument - ignored");
	  } else {
	    *conffile = str;
	    D(("new Configuration File: %s", *conffile));
	  }
	} else if ((str = pam_str_skip_prefix(*argv, "envfile=")) != NULL) {
	  if (str[0] == '\0') {
	    pam_syslog (pamh, LOG_ERR,
			"envfile= specification missing argument - ignored");
	  } else {
	    *envfile = str;
	    D(("new Env File: %s", *envfile));
	  }
	} else if ((str = pam_str_skip_prefix(*argv, "user_envfile=")) != NULL) {
	  if (str[0] == '\0') {
	    pam_syslog (pamh, LOG_ERR,
			"user_envfile= specification missing argument - ignored");
	  } else {
	    *user_envfile = str;
	    D(("new User Env File: %s", *user_envfile));
	  }
	} else if ((str = pam_str_skip_prefix(*argv, "readenv=")) != NULL) {
	  *readenv = atoi(str);
	} else if ((str = pam_str_skip_prefix(*argv, "user_readenv=")) != NULL) {
	  *user_readenv = atoi(str);
	} else
	  pam_syslog(pamh, LOG_ERR, "unknown option: %s", *argv);
    }

    if (*user_readenv)
	pam_syslog(pamh, LOG_DEBUG, "deprecated reading of user environment enabled");

    return ctrl;
}

#ifdef USE_ECONF

#define ENVIRONMENT "environment"
#define PAM_ENV "pam_env"

static int
isDirectory(const char *path) {
   struct stat statbuf;
   if (stat(path, &statbuf) != 0)
       return 0;
   return S_ISDIR(statbuf.st_mode);
}

static int
econf_read_file(const pam_handle_t *pamh, const char *filename, const char *delim,
			   const char *name, const char *suffix, const char *subpath,
			   char ***lines)
{
    econf_file *key_file = NULL;
    econf_err error;
    size_t key_number = 0;
    char **keys = NULL;
    const char *base_dir = "";

    if (filename != NULL) {
      if (isDirectory(filename)) {
	/* Set base directory which can be different from root */
	D(("filename argument is a directory: %s", filename));
	base_dir = filename;
      } else {
	/* Read only one file */
	error = econf_readFile (&key_file, filename, delim, "#");
	D(("File name is: %s", filename));
	if (error != ECONF_SUCCESS) {
	  pam_syslog(pamh, LOG_ERR, "Unable to open env file: %s: %s", filename,
		     econf_errString(error));
          if (error == ECONF_NOFILE)
            return PAM_IGNORE;
          else
            return PAM_ABORT;
	}
      }
    }
    if (filename == NULL || base_dir[0] != '\0') {
      /* Read and merge all setting in e.g. /usr/etc and /etc */
      char *vendor_dir = NULL, *sysconf_dir;
      if (subpath != NULL && subpath[0] != '\0') {
#ifdef VENDORDIR
	if (asprintf(&vendor_dir, "%s%s/%s/", base_dir, VENDORDIR, subpath) < 0) {
	  pam_syslog(pamh, LOG_ERR, "Cannot allocate memory.");
	  return PAM_BUF_ERR;
	}
#endif
	if (asprintf(&sysconf_dir, "%s%s/%s/", base_dir, SYSCONFDIR, subpath) < 0) {
	  pam_syslog(pamh, LOG_ERR, "Cannot allocate memory.");
	  free(vendor_dir);
	  return PAM_BUF_ERR;
	}
      } else {
#ifdef VENDORDIR
	if (asprintf(&vendor_dir, "%s%s/", base_dir, VENDORDIR) < 0) {
	  pam_syslog(pamh, LOG_ERR, "Cannot allocate memory.");
	  return PAM_BUF_ERR;
	}
#endif
	if (asprintf(&sysconf_dir, "%s%s/", base_dir, SYSCONFDIR) < 0) {
	  pam_syslog(pamh, LOG_ERR, "Cannot allocate memory.");
	  free(vendor_dir);
	  return PAM_BUF_ERR;
	}
      }

      D(("Read configuration from directory %s and %s", vendor_dir, sysconf_dir));
      error = econf_readDirs (&key_file, vendor_dir, sysconf_dir, name, suffix,
			      delim, "#");
      free(vendor_dir);
      free(sysconf_dir);
      if (error != ECONF_SUCCESS) {
        if (error == ECONF_NOFILE) {
	  pam_syslog(pamh, LOG_ERR, "Configuration file not found: %s%s", name, suffix);
          return PAM_IGNORE;
        } else {
          char *error_filename = NULL;
          uint64_t error_line = 0;

          econf_errLocation(&error_filename, &error_line);
          pam_syslog(pamh, LOG_ERR, "Unable to read configuration file %s line %ld: %s",
                     error_filename,
                     error_line,
                     econf_errString(error));
          free(error_filename);
          return PAM_ABORT;
	}
      }
    }

    error = econf_getKeys(key_file, NULL, &key_number, &keys);
    if (error != ECONF_SUCCESS && error != ECONF_NOKEY) {
      pam_syslog(pamh, LOG_ERR, "Unable to read keys: %s",
		 econf_errString(error));
      econf_freeFile(key_file);
      return PAM_ABORT;
    }

    *lines = malloc((key_number +1)* sizeof(char**));
    if (*lines == NULL) {
      pam_syslog(pamh, LOG_ERR, "Cannot allocate memory.");
      econf_free(keys);
      econf_freeFile(key_file);
      return PAM_BUF_ERR;
    }

    (*lines)[key_number] = 0;

    for (size_t i = 0; i < key_number; i++) {
      char *val;

      error = econf_getStringValue (key_file, NULL, keys[i], &val);
      if (error != ECONF_SUCCESS) {
	pam_syslog(pamh, LOG_ERR, "Unable to get string from key %s: %s",
		   keys[i],
		   econf_errString(error));
      } else {
        if (asprintf(&(*lines)[i],"%s%c%s", keys[i], delim[0], val) < 0) {
	  pam_syslog(pamh, LOG_ERR, "Cannot allocate memory.");
          econf_free(keys);
          econf_freeFile(key_file);
	  (*lines)[i] = NULL;
	  free_string_array(*lines);
	  free (val);
	  return PAM_BUF_ERR;
	}
	free (val);
      }
    }

    econf_free(keys);
    econf_free(key_file);
    return PAM_SUCCESS;
}

#else

/*
 * This is where we read a line of the PAM config file. The line may be
 * preceded by lines of comments and also extended with "\\\n"
 */
static int
_assemble_line(FILE *f, char *buffer, int buf_len)
{
    char *p = buffer;
    char *s, *os;
    int used = 0;
    int whitespace;

    /* loop broken with a 'break' when a non-'\\n' ended line is read */

    D(("called."));
    for (;;) {
	if (used >= buf_len) {
	    /* Overflow */
	    D(("overflow"));
	    return -1;
	}
	if (fgets(p, buf_len - used, f) == NULL) {
	    if (used) {
		/* Incomplete read */
		return -1;
	    } else {
		/* EOF */
		return 0;
	    }
	}
	if (p[0] == '\0') {
	    D(("corrupted or binary file"));
	    return -1;
	}
	if (p[strlen(p)-1] != '\n' && !feof(f)) {
	    D(("line too long"));
	    return -1;
	}

	/* skip leading spaces --- line may be blank */

	whitespace = strspn(p, " \n\t");
	s = p + whitespace;
	if (*s && (*s != '#')) {
	    used += whitespace;
	    os = s;

	    /*
	     * we are only interested in characters before the first '#'
	     * character
	     */

	    while (*s && *s != '#')
		 ++s;
	    if (*s == '#') {
		 *s = '\0';
		 used += strlen(os);
		 break;                /* the line has been read */
	    }

	    s = os;

	    /*
	     * Check for backslash by scanning back from the end of
	     * the entered line, the '\n' has been included since
	     * normally a line is terminated with this
	     * character. fgets() should only return one though!
	     */

	    s += strlen(s);
	    while (s > os && ((*--s == ' ') || (*s == '\t')
			      || (*s == '\n')));

	    /* check if it ends with a backslash */
	    if (*s == '\\') {
		*s = '\0';              /* truncate the line here */
		used += strlen(os);
		p = s;                  /* there is more ... */
	    } else {
		/* End of the line! */
		used += strlen(os);
		break;                  /* this is the complete line */
	    }

	} else {
	    /* Nothing in this line */
	    /* Don't move p         */
	}
    }

    return used;
}

static int read_file(const pam_handle_t *pamh, const char*filename, char ***lines)
{
    FILE *conf;
    char buffer[BUF_SIZE];

    D(("Parsed file name is: %s", filename));

    if ((conf = fopen(filename,"r")) == NULL) {
      pam_syslog(pamh, LOG_ERR, "Unable to open env file: %s", filename);
      return PAM_IGNORE;
    }

    size_t i = 0;
    *lines = malloc((i + 1)* sizeof(char*));
    if (*lines == NULL) {
      pam_syslog(pamh, LOG_ERR, "Cannot allocate memory.");
      (void) fclose(conf);
      return PAM_BUF_ERR;
    }
    (*lines)[i] = 0;
    while (_assemble_line(conf, buffer, BUF_SIZE) > 0) {
      char **tmp = NULL;
      D(("Read line: %s", buffer));
      tmp = realloc(*lines, (++i + 1) * sizeof(char*));
      if (tmp == NULL) {
	pam_syslog(pamh, LOG_ERR, "Cannot allocate memory.");
	(void) fclose(conf);
	free_string_array(*lines);
	pam_overwrite_array(buffer);
	return PAM_BUF_ERR;
      }
      *lines = tmp;
      (*lines)[i-1] = strdup(buffer);
      if ((*lines)[i-1] == NULL) {
        pam_syslog(pamh, LOG_ERR, "Cannot allocate memory.");
        (void) fclose(conf);
        free_string_array(*lines);
        pam_overwrite_array(buffer);
        return PAM_BUF_ERR;
      }
      (*lines)[i] = 0;
    }

    (void) fclose(conf);
    pam_overwrite_array(buffer);
    return PAM_SUCCESS;
}
#endif

static int
_parse_line(const pam_handle_t *pamh, const char *buffer, VAR *var)
{
  /*
   * parse buffer into var, legal syntax is
   * VARIABLE [DEFAULT=[[string]] [OVERRIDE=[value]]
   *
   * Any other options defined make this a bad line,
   * error logged and no var set
   */

  int length, quoteflg=0;
  const char *ptr, *tmpptr;
  char **valptr;

  D(("Called buffer = <%s>", buffer));

  length = strcspn(buffer," \t\n");

  if ((var->name = malloc(length + 1)) == NULL) {
    pam_syslog(pamh, LOG_CRIT, "Couldn't malloc %d bytes", length+1);
    return PAM_BUF_ERR;
  }

  /*
   * The first thing on the line HAS to be the variable name,
   * it may be the only thing though.
   */
  strncpy(var->name, buffer, length);
  var->name[length] = '\0';
  D(("var->name = <%s>, length = %d", var->name, length));

  /*
   * Now we check for arguments, we only support two kinds and ('cause I am lazy)
   * each one can actually be listed any number of times
   */

  ptr = buffer+length;
  while ((length = strspn(ptr, " \t")) > 0) {
    ptr += length;                              /* remove leading whitespace */
    D((ptr));
    if ((tmpptr = pam_str_skip_prefix(ptr, "DEFAULT=")) != NULL) {
      ptr = tmpptr;
      D(("Default arg found: <%s>", ptr));
      valptr=&(var->defval);
    } else if ((tmpptr = pam_str_skip_prefix(ptr, "OVERRIDE=")) != NULL) {
      ptr = tmpptr;
      D(("Override arg found: <%s>", ptr));
      valptr=&(var->override);
    } else {
      D(("Unrecognized options: <%s> - ignoring line", ptr));
      pam_syslog(pamh, LOG_ERR, "Unrecognized Option: %s - ignoring line", ptr);
      return BAD_LINE;
    }

    if ('"' != *ptr) {       /* Escaped quotes not supported */
      length = strcspn(ptr, " \t\n");
      tmpptr = ptr+length;
    } else {
      tmpptr = strchr(++ptr, '"');
      if (!tmpptr) {
	D(("Unterminated quoted string: %s", ptr-1));
	pam_syslog(pamh, LOG_ERR, "Unterminated quoted string: %s", ptr-1);
	return BAD_LINE;
      }
      length = tmpptr - ptr;
      if (*++tmpptr && ' ' != *tmpptr && '\t' != *tmpptr && '\n' != *tmpptr) {
	D(("Quotes must cover the entire string: <%s>", ptr));
	pam_syslog(pamh, LOG_ERR, "Quotes must cover the entire string: <%s>", ptr);
	return BAD_LINE;
      }
      quoteflg++;
    }
    if (length) {
      if ((*valptr = malloc(length + 1)) == NULL) {
	D(("Couldn't malloc %d bytes", length+1));
	pam_syslog(pamh, LOG_CRIT, "Couldn't malloc %d bytes", length+1);
	return PAM_BUF_ERR;
      }
      (void)strncpy(*valptr,ptr,length);
      (*valptr)[length]='\0';
    } else if (quoteflg) {
      quoteflg--;
      *valptr = &quote;      /* a quick hack to handle the empty string */
    }
    ptr = tmpptr;         /* Start the search where we stopped */
  } /* while */

  /*
   * The line is parsed, all is well.
   */

  D(("Exit."));
  ptr = NULL; tmpptr = NULL; valptr = NULL;
  return GOOD_LINE;
}

static const char *
_pam_get_item_byname(pam_handle_t *pamh, const char *name)
{
  /*
   * This function just allows me to use names as given in the config
   * file and translate them into the appropriate PAM_ITEM macro
   */

  int item;
  const void *itemval;

  D(("Called."));
  if (strcmp(name, "PAM_USER") == 0 || strcmp(name, "HOME") == 0 || strcmp(name, "SHELL") == 0) {
    item = PAM_USER;
  } else if (strcmp(name, "PAM_USER_PROMPT") == 0) {
    item = PAM_USER_PROMPT;
  } else if (strcmp(name, "PAM_TTY") == 0) {
    item = PAM_TTY;
  } else if (strcmp(name, "PAM_RUSER") == 0) {
    item = PAM_RUSER;
  } else if (strcmp(name, "PAM_RHOST") == 0) {
    item = PAM_RHOST;
  } else {
    D(("Unknown PAM_ITEM: <%s>", name));
    pam_syslog (pamh, LOG_ERR, "Unknown PAM_ITEM: <%s>", name);
    return NULL;
  }

  if (pam_get_item(pamh, item, &itemval) != PAM_SUCCESS) {
    D(("pam_get_item failed"));
    return NULL;     /* let pam_get_item() log the error */
  }

  if (itemval && (strcmp(name, "HOME") == 0 || strcmp(name, "SHELL") == 0)) {
    struct passwd *user_entry;
    user_entry = pam_modutil_getpwnam (pamh, itemval);
    if (!user_entry) {
      pam_syslog(pamh, LOG_ERR, "No such user!?");
      return NULL;
    }
    return (strcmp(name, "SHELL") == 0) ?
      user_entry->pw_shell :
      user_entry->pw_dir;
  }

  D(("Exit."));
  return itemval;
}

static int
_expand_arg(pam_handle_t *pamh, char **value)
{
  const char *orig=*value, *tmpptr=NULL;
  char *ptr;       /*
		    * Sure would be nice to use tmpptr but it needs to be
		    * a constant so that the compiler will shut up when I
		    * call pam_getenv and _pam_get_item_byname -- sigh
		    */

  /* No unexpanded variable can be bigger than BUF_SIZE */
  char type, tmpval[BUF_SIZE];

  /* I know this shouldn't be hard-coded but it's so much easier this way */
  char tmp[MAX_ENV] = {};
  size_t idx = 0;

  /*
   * (possibly non-existent) environment variables can be used as values
   * by prepending a "$" and wrapping in {} (ie: ${HOST}), can escape with "\"
   * (possibly non-existent) PAM items can be used as values
   * by prepending a "@" and wrapping in {} (ie: @{PAM_RHOST}, can escape
   *
   */
  D(("Expanding <%s>",orig));
  while (*orig) {     /* while there is some input to deal with */
    if ('\\' == *orig) {
      ++orig;
      if ('$' != *orig && '@' != *orig) {
	D(("Unrecognized escaped character: <%c> - ignoring", *orig));
	pam_syslog(pamh, LOG_ERR,
		   "Unrecognized escaped character: <%c> - ignoring",
		   *orig);
      } else if (idx + 1 < MAX_ENV) {
	tmp[idx++] = *orig++;        /* Note the increment */
      } else {
	/* is it really a good idea to try to log this? */
	D(("Variable buffer overflow: <%s> + <%s>", tmp, tmpptr));
	pam_syslog (pamh, LOG_ERR, "Variable buffer overflow: <%s> + <%s>",
		 tmp, tmpptr);
	goto buf_err;
      }
      continue;
    }
    if ('$' == *orig || '@' == *orig) {
      if ('{' != *(orig+1)) {
	D(("Expandable variables must be wrapped in {}"
	   " <%s> - ignoring", orig));
	pam_syslog(pamh, LOG_ERR, "Expandable variables must be wrapped in {}"
		 " <%s> - ignoring", orig);
	if (idx + 1 < MAX_ENV) {
	  tmp[idx++] = *orig++;        /* Note the increment */
	}
	continue;
      } else {
	D(("Expandable argument: <%s>", orig));
	type = *orig;
	orig+=2;     /* skip the ${ or @{ characters */
	ptr = strchr(orig, '}');
	if (ptr) {
	  *ptr++ = '\0';
	} else {
	  D(("Unterminated expandable variable: <%s>", orig-2));
	  pam_syslog(pamh, LOG_ERR,
		     "Unterminated expandable variable: <%s>", orig-2);
	  goto abort_err;
	}
	strncpy(tmpval, orig, sizeof(tmpval));
	tmpval[sizeof(tmpval)-1] = '\0';
	orig=ptr;
	/*
	 * so, we know we need to expand tmpval, it is either
	 * an environment variable or a PAM_ITEM. type will tell us which
	 */
	switch (type) {

	case '$':
	  D(("Expanding env var: <%s>",tmpval));
	  tmpptr = pam_getenv(pamh, tmpval);
	  D(("Expanded to <%s>", tmpptr));
	  break;

	case '@':
	  D(("Expanding pam item: <%s>",tmpval));
	  tmpptr = _pam_get_item_byname(pamh, tmpval);
	  D(("Expanded to <%s>", tmpptr));
	  break;

	default:
	  D(("Impossible error, type == <%c>", type));
	  pam_syslog(pamh, LOG_CRIT, "Impossible error, type == <%c>", type);
	  goto abort_err;
	}         /* switch */

	if (tmpptr) {
	  size_t len = strlen(tmpptr);
	  if (idx + len < MAX_ENV) {
	    strcpy(tmp + idx, tmpptr);
	    idx += len;
	  } else {
	    /* is it really a good idea to try to log this? */
	    D(("Variable buffer overflow: <%s> + <%s>", tmp, tmpptr));
	    pam_syslog (pamh, LOG_ERR,
			"Variable buffer overflow: <%s> + <%s>", tmp, tmpptr);
	    goto buf_err;
	  }
	}
      }           /* if ('{' != *orig++) */
    } else {      /* if ( '$' == *orig || '@' == *orig) */
      if (idx + 1 < MAX_ENV) {
	tmp[idx++] = *orig++;        /* Note the increment */
      } else {
	/* is it really a good idea to try to log this? */
	D(("Variable buffer overflow: <%s> + <%s>", tmp, tmpptr));
	pam_syslog(pamh, LOG_ERR,
		   "Variable buffer overflow: <%s> + <%s>", tmp, tmpptr);
	goto buf_err;
      }
    }
  }              /* for (;*orig;) */

  if (idx > strlen(*value)) {
    free(*value);
    if ((*value = malloc(idx + 1)) == NULL) {
      D(("Couldn't malloc %d bytes for expanded var", idx + 1));
      pam_syslog (pamh, LOG_CRIT, "Couldn't malloc %lu bytes for expanded var",
	       (unsigned long)idx+1);
      goto buf_err;
    }
  }
  strcpy(*value, tmp);
  pam_overwrite_array(tmp);
  pam_overwrite_array(tmpval);
  D(("Exit."));

  return PAM_SUCCESS;
buf_err:
  pam_overwrite_array(tmp);
  pam_overwrite_array(tmpval);
  return PAM_BUF_ERR;
abort_err:
  pam_overwrite_array(tmp);
  pam_overwrite_array(tmpval);
  return PAM_ABORT;
}

static int
_check_var(pam_handle_t *pamh, VAR *var)
{
  /*
   * Examine the variable and determine what action to take.
   * Returns DEFINE_VAR, UNDEFINE_VAR depending on action to take
   * or a PAM_* error code if passed back from other routines
   *
   * if no DEFAULT provided, the empty string is assumed
   * if no OVERRIDE provided, the empty string is assumed
   * if DEFAULT=  and OVERRIDE evaluates to the empty string,
   *    this variable should be undefined
   * if DEFAULT=""  and OVERRIDE evaluates to the empty string,
   *    this variable should be defined with no value
   * if OVERRIDE=value   and value turns into the empty string, DEFAULT is used
   *
   * If DEFINE_VAR is to be returned, the correct value to define will
   * be pointed to by var->value
   */

  int retval;

  D(("Called."));

  /*
   * First thing to do is to expand any arguments, but only
   * if they are not the special quote values (cause expand_arg
   * changes memory).
   */

  if (var->defval && (&quote != var->defval) &&
      ((retval = _expand_arg(pamh, &(var->defval))) != PAM_SUCCESS)) {
      return retval;
  }
  if (var->override && (&quote != var->override) &&
      ((retval = _expand_arg(pamh, &(var->override))) != PAM_SUCCESS)) {
    return retval;
  }

  /* Now its easy */

  if (var->override && *(var->override)) {
    /* if there is a non-empty string in var->override, we use it */
    D(("OVERRIDE variable <%s> being used: <%s>", var->name, var->override));
    var->value = var->override;
    retval = DEFINE_VAR;
  } else {

    var->value = var->defval;
    if (&quote == var->defval) {
      /*
       * This means that the empty string was given for defval value
       * which indicates that a variable should be defined with no value
       */
      D(("An empty variable: <%s>", var->name));
      retval = DEFINE_VAR;
    } else if (var->defval) {
      D(("DEFAULT variable <%s> being used: <%s>", var->name, var->defval));
      retval = DEFINE_VAR;
    } else {
      D(("UNDEFINE variable <%s>", var->name));
      retval = UNDEFINE_VAR;
    }
  }

  D(("Exit."));
  return retval;
}

static void
_clean_var(VAR *var)
{
    if (var->name) {
      pam_overwrite_string(var->name);
      free(var->name);
    }
    if (var->defval && (&quote != var->defval)) {
      pam_overwrite_string(var->defval);
      free(var->defval);
    }
    if (var->override && (&quote != var->override)) {
      pam_overwrite_string(var->override);
      free(var->override);
    }
    var->name = NULL;
    var->value = NULL;    /* never has memory specific to it */
    var->defval = NULL;
    var->override = NULL;
    return;
}

static int
_define_var(pam_handle_t *pamh, int ctrl, VAR *var)
{
  /* We have a variable to define, this is a simple function */

  char *envvar;
  int retval = PAM_SUCCESS;

  D(("Called."));
  if (asprintf(&envvar, "%s=%s", var->name, var->value) < 0) {
    pam_syslog(pamh, LOG_CRIT, "out of memory");
    return PAM_BUF_ERR;
  }

  retval = pam_putenv(pamh, envvar);
  if (ctrl & PAM_DEBUG_ARG) {
    pam_syslog(pamh, LOG_DEBUG, "pam_putenv(\"%s\")", envvar);
  }
  _pam_drop(envvar);
  D(("Exit."));
  return retval;
}

static int
_undefine_var(pam_handle_t *pamh, int ctrl, VAR *var)
{
  /* We have a variable to undefine, this is a simple function */

  D(("Called and exit."));
  if (ctrl & PAM_DEBUG_ARG) {
    pam_syslog(pamh, LOG_DEBUG, "remove variable \"%s\"", var->name);
  }
  return pam_putenv(pamh, var->name);
}

static int
_parse_config_file(pam_handle_t *pamh, int ctrl, const char *file)
{
    int retval;
    VAR Var, *var=&Var;
    char **conf_list = NULL;

    var->name=NULL; var->defval=NULL; var->override=NULL;

    D(("Called."));

#ifdef USE_ECONF
    /* If "file" is not NULL, only this file will be parsed. */
    retval = econf_read_file(pamh, file, " \t", PAM_ENV, ".conf", "security", &conf_list);
#else
    /* Only one file will be parsed. So, file has to be set. */
    if (file == NULL) /* No filename has been set via argv. */
      file = DEFAULT_CONF_FILE;
#ifdef VENDOR_DEFAULT_CONF_FILE
    /*
    * Check whether file is available.
    * If it does not exist, fall back to VENDOR_DEFAULT_CONF_FILE file.
    */
    struct stat stat_buffer;
    if (stat(file, &stat_buffer) != 0 && errno == ENOENT) {
      file = VENDOR_DEFAULT_CONF_FILE;
    }
#endif
    retval = read_file(pamh, file, &conf_list);
#endif

    if (retval != PAM_SUCCESS)
      return retval;

    for (char **conf = conf_list; *conf != NULL; ++conf) {
      if ((retval = _parse_line(pamh, *conf, var)) == GOOD_LINE) {
	retval = _check_var(pamh, var);

	if (DEFINE_VAR == retval) {
	  retval = _define_var(pamh, ctrl, var);

	} else if (UNDEFINE_VAR == retval) {
	  retval = _undefine_var(pamh, ctrl, var);
	}
      }
      if (PAM_SUCCESS != retval && ILLEGAL_VAR != retval
	  && BAD_LINE != retval && PAM_BAD_ITEM != retval) break;

      _clean_var(var);

    }  /* for */

    /* tidy up */
    free_string_array(conf_list);
    _clean_var(var);        /* We could have got here prematurely,
			     * this is safe though */
    D(("Exit."));
    return (retval != 0 ? PAM_ABORT : PAM_SUCCESS);
}

static int
_parse_env_file(pam_handle_t *pamh, int ctrl, const char *file)
{
    int retval=PAM_SUCCESS, i, t;
    char *key, *mark;
    char **env_list = NULL;

#ifdef USE_ECONF
    retval = econf_read_file(pamh, file, "=", ENVIRONMENT, "", "", &env_list);
#else
    /* Only one file will be parsed. So, file has to be set. */
    if (file == NULL) /* No filename has been set via argv. */
      file = DEFAULT_ETC_ENVFILE;
#ifdef VENDOR_DEFAULT_ETC_ENVFILE
    /*
    * Check whether file is available.
    * If it does not exist, fall back to VENDOR_DEFAULT_ETC_ENVFILE; file.
    */
    struct stat stat_buffer;
    if (stat(file, &stat_buffer) != 0 && errno == ENOENT) {
      file = VENDOR_DEFAULT_ETC_ENVFILE;
    }
#endif
    retval = read_file(pamh, file, &env_list);
#endif

    if (retval != PAM_SUCCESS)
        return retval == PAM_IGNORE ? PAM_SUCCESS : retval;

    for (char **env = env_list; *env != NULL; ++env) {
        key = *env;

	/* skip leading white space */
	key += strspn(key, " \n\t");

	/* skip blanks lines and comments */
	if (key[0] == '#')
	    continue;

	/* skip over "export " if present so we can be compat with
	   bash type declarations */
	if (strncmp(key, "export ", (size_t) 7) == 0)
	    key += 7;

	/* now find the end of value */
	mark = key;
	while(mark[0] != '\n' && mark[0] != '#' && mark[0] != '\0')
	    mark++;
	if (mark[0] != '\0')
	    mark[0] = '\0';

       /*
	* sanity check, the key must be alphanumeric
	*/

	if (key[0] == '=') {
		pam_syslog(pamh, LOG_ERR,
		           "missing key name '%s' in %s', ignoring",
		           key, file);
		continue;
	}

	for ( i = 0 ; key[i] != '=' && key[i] != '\0' ; i++ )
	    if (!isalnum((unsigned char)key[i]) && key[i] != '_') {
		pam_syslog(pamh, LOG_ERR,
		           "non-alphanumeric key '%s' in %s', ignoring",
		           key, file);
		break;
	    }
	/* non-alphanumeric key, ignore this line */
	if (key[i] != '=' && key[i] != '\0')
	    continue;

	/* now we try to be smart about quotes around the value,
	   but not too smart, we can't get all fancy with escaped
	   values like bash */
	if (key[i] == '=' && (key[++i] == '\"' || key[i] == '\'')) {
	    for ( t = i+1 ; key[t] != '\0' ; t++)
		if (key[t] != '\"' && key[t] != '\'')
		    key[i++] = key[t];
		else if (key[t+1] != '\0')
		    key[i++] = key[t];
	    key[i] = '\0';
	}

	/* if this is a request to delete a variable, check that it's
	   actually set first, so we don't get a vague error back from
	   pam_putenv() */
	for (i = 0; key[i] != '=' && key[i] != '\0'; i++);

	if (key[i] == '\0' && !pam_getenv(pamh,key))
	    continue;

	/* set the env var, if it fails, we break out of the loop */
	retval = pam_putenv(pamh, key);
	if (retval != PAM_SUCCESS) {
	    D(("error setting env \"%s\"", key));
	    break;
	} else if (ctrl & PAM_DEBUG_ARG) {
	    pam_syslog(pamh, LOG_DEBUG,
		       "pam_putenv(\"%s\")", key);
	}
    }

    /* tidy up */
    free_string_array(env_list);
    D(("Exit."));
    return retval;
}

/* --- authentication management functions (only) --- */

int
pam_sm_authenticate (pam_handle_t *pamh UNUSED, int flags UNUSED,
		     int argc UNUSED, const char **argv UNUSED)
{
  return PAM_IGNORE;
}

static int
handle_env (pam_handle_t *pamh, int argc, const char **argv)
{
  int retval, ctrl, readenv=DEFAULT_READ_ENVFILE;
  int user_readenv = DEFAULT_USER_READ_ENVFILE;
  const char *conf_file = NULL, *env_file = NULL, *user_env_file = NULL;

  /*
   * this module sets environment variables read in from a file
   */

  D(("Called."));
  ctrl = _pam_parse(pamh, argc, argv, &conf_file, &env_file,
		    &readenv, &user_env_file, &user_readenv);

  retval = _parse_config_file(pamh, ctrl, conf_file);

  if(readenv && retval == PAM_SUCCESS) {
    retval = _parse_env_file(pamh, ctrl, env_file);
    if (retval == PAM_IGNORE)
      retval = PAM_SUCCESS;
  }

  if(user_readenv && retval == PAM_SUCCESS) {
    char *envpath = NULL;
    struct passwd *user_entry = NULL;
    const char *username;
    struct stat statbuf;

    username = _pam_get_item_byname(pamh, "PAM_USER");

    if (username)
      user_entry = pam_modutil_getpwnam (pamh, username);
    if (!user_entry) {
      pam_syslog(pamh, LOG_ERR, "No such user!?");
    }
    else {
      if (asprintf(&envpath, "%s/%s", user_entry->pw_dir, user_env_file) < 0)
	{
	  pam_syslog(pamh, LOG_CRIT, "Out of memory");
	  return PAM_BUF_ERR;
	}
      if (stat(envpath, &statbuf) == 0) {
	PAM_MODUTIL_DEF_PRIVS(privs);

	if (pam_modutil_drop_priv(pamh, &privs, user_entry)) {
	  retval = PAM_SESSION_ERR;
	} else {
	  retval = _parse_config_file(pamh, ctrl, envpath);
	  if (pam_modutil_regain_priv(pamh, &privs))
	    retval = PAM_SESSION_ERR;
	}
        if (retval == PAM_IGNORE)
          retval = PAM_SUCCESS;
      }
      free(envpath);
    }
  }

  /* indicate success or failure */
  D(("Exit."));
  return retval;
}

int
pam_sm_acct_mgmt (pam_handle_t *pamh UNUSED, int flags UNUSED,
		  int argc UNUSED, const char **argv UNUSED)
{
  pam_syslog (pamh, LOG_NOTICE, "pam_sm_acct_mgmt called inappropriately");
  return PAM_SERVICE_ERR;
}

int
pam_sm_setcred (pam_handle_t *pamh, int flags UNUSED,
		int argc, const char **argv)
{
  D(("Called"));
  return handle_env (pamh, argc, argv);
}

int
pam_sm_open_session (pam_handle_t *pamh, int flags UNUSED,
		     int argc, const char **argv)
{
  D(("Called"));
  return handle_env (pamh, argc, argv);
}

int
pam_sm_close_session (pam_handle_t *pamh UNUSED, int flags UNUSED,
		      int argc UNUSED, const char **argv UNUSED)
{
  D(("Called and Exit"));
  return PAM_SUCCESS;
}

int
pam_sm_chauthtok (pam_handle_t *pamh UNUSED, int flags UNUSED,
		  int argc UNUSED, const char **argv UNUSED)
{
  pam_syslog (pamh, LOG_NOTICE, "pam_sm_chauthtok called inappropriately");
  return PAM_SERVICE_ERR;
}

/* end of module definition */
