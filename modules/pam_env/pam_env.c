/*
 * pam_env module
 *
 * Written by Dave Kinchlea <kinch@kinch.ark.com> 1997/01/31
 * Inspired by Andrew Morgan <morgan@kernel.org>, who also supplied the
 * template for this file (via pam_mail)
 */

#include "config.h"

#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef USE_ECONF
#include "pam_econf.h"
#endif

#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/_pam_macros.h>
#include <security/pam_ext.h>
#include "pam_inline.h"
#include "pam_line.h"

/* This little structure makes it easier to keep variables together */

typedef struct var {
  char *name;
  char *value;
  char *defval;
  char *override;
} VAR;

#define DEFAULT_READ_ENVFILE    1

#define DEFAULT_USER_ENVFILE    ".pam_environment"
#define DEFAULT_USER_READ_ENVFILE 0

#define DEFAULT_CONF_FILE	(SCONFIG_DIR "/pam_env.conf")
#ifdef VENDOR_SCONFIG_DIR
#define VENDOR_DEFAULT_CONF_FILE (VENDOR_SCONFIG_DIR "/pam_env.conf")
#endif

#define GOOD_LINE    0
#define BAD_LINE     100       /* This must be > the largest PAM_* error code */

#define DEFINE_VAR   101
#define UNDEFINE_VAR 102

struct string_buffer {
  char *str;
  size_t len;
  size_t size;
};

#define ENVD_EXPAND_DEPTH_ERROR (-1)

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

static int
isDirectory(const char *path) {
   struct stat statbuf;
   if (stat(path, &statbuf) != 0)
       return 0;
   return S_ISDIR(statbuf.st_mode);
}

#ifdef USE_ECONF

#define ENVIRONMENT "environment"
#define PAM_ENV "pam_env"

/*
 * Remove escaped newline from string.
 *
 * All occurrences of "\\n" will be removed from string.
 */
static void
econf_unescnl(char *val)
{
    char *dest, *p;

    dest = p = val;

    while (*p != '\0') {
      if (p[0] == '\\' && p[1] == '\n') {
	p += 2;
      } else {
	*dest++ = *p++;
      }
    }
    *dest = '\0';
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
	if ((vendor_dir = pam_asprintf("%s%s/%s/", base_dir, VENDORDIR, subpath)) == NULL) {
	  pam_syslog(pamh, LOG_ERR, "Cannot allocate memory.");
	  return PAM_BUF_ERR;
	}
#endif
	if ((sysconf_dir = pam_asprintf("%s%s/%s/", base_dir, SYSCONFDIR, subpath)) == NULL) {
	  pam_syslog(pamh, LOG_ERR, "Cannot allocate memory.");
	  free(vendor_dir);
	  return PAM_BUF_ERR;
	}
      } else {
#ifdef VENDORDIR
	if ((vendor_dir = pam_asprintf("%s%s/", base_dir, VENDORDIR)) == NULL) {
	  pam_syslog(pamh, LOG_ERR, "Cannot allocate memory.");
	  return PAM_BUF_ERR;
	}
#endif
	if ((sysconf_dir = pam_asprintf("%s%s/", base_dir, SYSCONFDIR)) == NULL) {
	  pam_syslog(pamh, LOG_ERR, "Cannot allocate memory.");
	  free(vendor_dir);
	  return PAM_BUF_ERR;
	}
      }

      error = pam_econf_readconfig (&key_file, vendor_dir, sysconf_dir, name, suffix,
				    delim, "#", NULL, NULL);
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

    *lines = calloc((key_number + 1), sizeof(char**));
    if (*lines == NULL) {
      pam_syslog(pamh, LOG_ERR, "Cannot allocate memory.");
      econf_free(keys);
      econf_freeFile(key_file);
      return PAM_BUF_ERR;
    }

    size_t n = 0;
    for (size_t i = 0; i < key_number; i++) {
      char *val;

      error = econf_getStringValue (key_file, NULL, keys[i], &val);
      if (error != ECONF_SUCCESS || val == NULL) {
	pam_syslog(pamh, LOG_ERR, "Unable to get string from key %s: %s",
		   keys[i],
		   econf_errString(error));
      } else {
        econf_unescnl(val);
        if (((*lines)[n] = pam_asprintf("%s%c%s", keys[i], delim[0], val)) == NULL) {
	  pam_syslog(pamh, LOG_ERR, "Cannot allocate memory.");
          econf_free(keys);
          econf_freeFile(key_file);
	  (*lines)[i] = NULL;
	  free_string_array(*lines);
	  free (val);
	  return PAM_BUF_ERR;
	}
	free (val);
	n++;
      }
    }

    econf_free(keys);
    econf_free(key_file);
    return PAM_SUCCESS;
}
#endif

#ifndef USE_ECONF
static int read_file(const pam_handle_t *pamh, const char*filename, char ***lines)
{
    FILE *conf;
    struct pam_line_buffer buffer;

    _pam_line_buffer_init(&buffer);

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
    (*lines)[i] = NULL;
    while (_pam_line_assemble(conf, &buffer, '\0') > 0) {
      char *p = buffer.assembled;
      char **tmp = NULL;
      D(("Read line: %s", p));
      tmp = realloc(*lines, (++i + 1) * sizeof(char*));
      if (tmp == NULL) {
	pam_syslog(pamh, LOG_ERR, "Cannot allocate memory.");
	(void) fclose(conf);
	free_string_array(*lines);
	_pam_line_buffer_clear(&buffer);
	return PAM_BUF_ERR;
      }
      *lines = tmp;
      (*lines)[i-1] = strdup(p);
      if ((*lines)[i-1] == NULL) {
        pam_syslog(pamh, LOG_ERR, "Cannot allocate memory.");
        (void) fclose(conf);
        free_string_array(*lines);
        _pam_line_buffer_clear(&buffer);
        return PAM_BUF_ERR;
      }
      (*lines)[i] = NULL;
    }

    (void) fclose(conf);
    _pam_line_buffer_clear(&buffer);
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

  /*
   * The first thing on the line HAS to be the variable name,
   * it may be the only thing though.
   */
  if ((var->name = strndup(buffer, length)) == NULL) {
    D(("out of memory"));
    pam_syslog(pamh, LOG_CRIT, "out of memory");
    return PAM_BUF_ERR;
  }
  D(("var->name = <%s>, length = %d", var->name, length));

  /*
   * Now we check for arguments, we only support two kinds and ('cause I am lazy)
   * each one can actually be listed any number of times
   */

  ptr = buffer+length;
  while ((length = strspn(ptr, " \t")) > 0) {
    ptr += length;                              /* remove leading whitespace */
    D(("%s", ptr));
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
      if (*valptr != &quote)
	free(*valptr);
      if ((*valptr = strndup(ptr, length)) == NULL) {
	D(("out of memory"));
	pam_syslog(pamh, LOG_CRIT, "out of memory");
	return PAM_BUF_ERR;
      }
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

static void
_strbuf_init(struct string_buffer *buffer)
{
  buffer->str = NULL;
  buffer->len = 0;
  buffer->size = 0;
}

static void
_strbuf_free(struct string_buffer *buffer)
{
  pam_overwrite_n(buffer->str, buffer->len);
  _pam_drop(buffer->str);
  buffer->len = 0;
  buffer->size = 0;
}

/*
 * Allocates given amount of bytes in buffer for addition.
 * Internally adding an extra byte for NUL character.
 *
 * Returns 0 on success, 1 on error.
 */
static int
_strbuf_reserve(struct string_buffer *buffer, size_t add)
{
  char *p;
  size_t s;

  /* Is already enough memory allocated? */
  if (add < buffer->size - buffer->len) {
    return 0;
  }

  /* Can the requested bytes (plus additional NUL byte) fit at all? */
  if (buffer->len >= SIZE_MAX - add) {
    return 1;
  }

  if (buffer->size == 0 && add < 64) {
    /* Start with 64 bytes if that's enough */
    s = 64;
  } else if (buffer->size >= SIZE_MAX / 2 || buffer->size * 2 < buffer->len + add + 1) {
    /* If doubling is not enough (or not possible), get as much as needed */
    s = buffer->len + add + 1;
  } else {
    /* Ideally, double allocated memory */
    s = buffer->size * 2;
  }

  if ((p = realloc(buffer->str, s)) == NULL) {
    return 1;
  }

  buffer->str = p;
  buffer->size = s;

  return 0;
}

static int
_strbuf_add_char(struct string_buffer *buffer, char c)
{
  D(("Called <%s> + <%c>.", buffer->str == NULL ? "" : buffer->str, c));

  if (_strbuf_reserve(buffer, 1)) {
    return 1;
  }

  buffer->str[buffer->len++] = c;
  buffer->str[buffer->len] = '\0';

  return 0;
}

static int
_strbuf_add_string(struct string_buffer *buffer, const char *str)
{
  size_t len = strlen(str);

  D(("Called <%s> + <%s>.", buffer->str == NULL ? "" : buffer->str, str));

  if (_strbuf_reserve(buffer, len)) {
    return 1;
  }

  strcpy(buffer->str + buffer->len, str);
  buffer->len += len;

  return 0;
}

static int
_envd_valid_name(const char *name, size_t length)
{
  if (length == 0 ||
      (!isalpha((unsigned char)name[0]) && name[0] != '_'))
    return 0;
  for (size_t i = 1; i < length; ++i) {
    if (!isalnum((unsigned char)name[i]) && name[i] != '_')
      return 0;
  }
  return 1;
}

static int
_envd_expand_text(pam_handle_t *pamh, const char *text, char quote_char,
		  struct string_buffer *buffer, unsigned int depth)
{
  if (depth > 16)
    return ENVD_EXPAND_DEPTH_ERROR;

  while (*text != '\0') {
    if (*text == '\\' && quote_char != '\'') {
      char next = text[1];
      if (next == '\0') {
	if (_strbuf_add_char(buffer, '\\'))
	  return 1;
	++text;
      } else if (quote_char != '"' || next == '"' || next == '$' ||
		 next == '\\' || next == '`' || next == '\n') {
	if (next != '\n' && _strbuf_add_char(buffer, next))
	  return 1;
	text += 2;
      } else {
	if (_strbuf_add_char(buffer, *text++))
	  return 1;
      }
      continue;
    }

    if (*text != '$') {
      if (_strbuf_add_char(buffer, *text++))
	return 1;
      continue;
    }

    if (text[1] == '$') {
      if (_strbuf_add_char(buffer, '$'))
	return 1;
      text += 2;
      continue;
    }

    const char *name = NULL;
    size_t name_length = 0;
    const char *replacement = NULL;
    const char *operator_value = NULL;
    size_t operator_length = 0;
    size_t reference_length = 0;
    char operator_char = '\0';
    int colon_operator = 0;
    const char *end = NULL;
    const char *reference = text;

    if (text[1] == '{') {
      const char *close = text + 2;
      unsigned int nested = 0;
      for (; *close != '\0'; ++close) {
	if (close[0] == '$' && close[1] == '{') {
	  ++nested;
	  ++close;
	} else if (*close == '}') {
	  if (nested == 0)
	    break;
	  --nested;
	}
      }
      if (*close == '\0') {
	if (_strbuf_add_char(buffer, *text++))
	  return 1;
	continue;
      }

      name = text + 2;
      end = close;
      for (const char *p = name; p < close; ++p) {
	if (p[0] == ':' && p + 1 < close &&
	    (p[1] == '-' || p[1] == '+')) {
	  operator_char = p[1];
	  colon_operator = 1;
	  operator_value = p + 2;
	  end = p;
	  break;
	} else if (p[0] == '-') {
	  operator_char = p[0];
	  operator_value = p + 1;
	  end = p;
	  break;
	}
      }
      name_length = (size_t)(end - name);
      if (operator_value != NULL)
	operator_length = (size_t)(close - operator_value);
      reference_length = (size_t)(close + 1 - reference);
      text = close + 1;
    } else if (isalpha((unsigned char)text[1]) || text[1] == '_') {
      name = text + 1;
      while (isalnum((unsigned char)name[name_length]) ||
	     name[name_length] == '_')
	++name_length;
      reference_length = name_length + 1;
      text = name + name_length;
    } else {
      if (_strbuf_add_char(buffer, *text++))
	return 1;
      continue;
    }

    if (!_envd_valid_name(name, name_length)) {
      char *literal = strndup(reference, reference_length);
      if (literal == NULL)
	return 1;
      int error = _strbuf_add_string(buffer, literal);
      free(literal);
      if (error)
	return 1;
      continue;
    }

    char *variable_name = strndup(name, name_length);
    if (variable_name == NULL)
      return 1;
    replacement = pam_getenv(pamh, variable_name);
    free(variable_name);

    if (operator_char == '-' &&
	(replacement == NULL || (colon_operator && *replacement == '\0'))) {
      char *value = strndup(operator_value, operator_length);
      if (value == NULL)
	return 1;
      int error = _envd_expand_text(pamh, value, quote_char, buffer, depth + 1);
      free(value);
      if (error)
	return error;
    } else if (operator_char == '+' && replacement != NULL &&
	       *replacement != '\0') {
      char *value = strndup(operator_value, operator_length);
      if (value == NULL)
	return 1;
      int error = _envd_expand_text(pamh, value, quote_char, buffer, depth + 1);
      free(value);
      if (error)
	return error;
    } else if ((operator_char == '\0' || operator_char == '-') &&
	       replacement != NULL &&
	       _strbuf_add_string(buffer, replacement)) {
      return 1;
    }
  }

  return 0;
}

static char *
_envd_expand_value(pam_handle_t *pamh, const char *value, char quote_char,
		   int *error)
{
  struct string_buffer buffer;
  char *result;

  _strbuf_init(&buffer);
  *error = _envd_expand_text(pamh, value, quote_char, &buffer, 0);
  if (*error != 0) {
    _strbuf_free(&buffer);
    return NULL;
  }
  result = strdup(buffer.str == NULL ? "" : buffer.str);
  _strbuf_free(&buffer);
  return result;
}

static int
_envd_set_line(pam_handle_t *pamh, int ctrl, const char *filename, char *line)
{
  char *key = line;
  char *equals;
  char *value;
  char quote_char = '\0';
  char *value_end;
  char *expanded;
  char *variable;
  char *envvar;
  size_t key_length;
  int retval;
  int expansion_error;

  key += strspn(key, " \t\r");
  if (*key == '\0' || *key == '#' || *key == ';')
    return PAM_SUCCESS;

  equals = strchr(key, '=');
  if (equals == NULL) {
    pam_syslog(pamh, LOG_ERR, "Invalid environment.d assignment in %s, ignoring",
	       filename);
    return PAM_SUCCESS;
  }
  value_end = equals;
  while (value_end > key && (value_end[-1] == ' ' || value_end[-1] == '\t'))
    --value_end;
  key_length = (size_t)(value_end - key);
  if (!_envd_valid_name(key, key_length)) {
    pam_syslog(pamh, LOG_ERR, "Invalid environment.d variable in %s, ignoring",
	       filename);
    return PAM_SUCCESS;
  }

  value = equals + 1;
  value += strspn(value, " \t\r");
  value_end = value + strlen(value);
  while (value_end > value &&
	 (value_end[-1] == ' ' || value_end[-1] == '\t' ||
	  value_end[-1] == '\r'))
    --value_end;

  if (*value == '"' || *value == '\'') {
    char *close;
    quote_char = *value++;
    close = value;
    while (close < value_end) {
      if (quote_char == '"' && *close == '\\' && close + 1 < value_end &&
	  (close[1] == '"' || close[1] == '$' || close[1] == '\\' ||
	   close[1] == '`')) {
	++close;
      } else if (*close == quote_char) {
	break;
      }
      ++close;
    }
    if (close == value_end || strspn(close + 1, " \t\r") != strlen(close + 1)) {
      pam_syslog(pamh, LOG_ERR, "Invalid quoted environment.d value in %s, ignoring",
		 filename);
      return PAM_SUCCESS;
    }
    *close = '\0';
  } else {
    *value_end = '\0';
  }

  expanded = _envd_expand_value(pamh, value, quote_char, &expansion_error);
  if (expanded == NULL) {
    if (expansion_error == ENVD_EXPAND_DEPTH_ERROR) {
      pam_syslog(pamh, LOG_ERR, "Invalid environment.d assignment in %s, ignoring",
		 filename);
      return PAM_SUCCESS;
    }
    pam_syslog(pamh, LOG_ERR, "Cannot expand environment.d value in %s",
	       filename);
    return PAM_BUF_ERR;
  }
  variable = strndup(key, key_length);
  if (variable == NULL) {
    pam_overwrite_string(expanded);
    free(expanded);
    pam_syslog(pamh, LOG_ERR, "Cannot allocate memory.");
    return PAM_BUF_ERR;
  }
  envvar = pam_asprintf("%s=%s", variable, expanded);
  free(variable);
  pam_overwrite_string(expanded);
  free(expanded);
  if (envvar == NULL) {
    pam_syslog(pamh, LOG_ERR, "Cannot allocate memory.");
    return PAM_BUF_ERR;
  }

  retval = pam_putenv(pamh, envvar);
  if (retval != PAM_SUCCESS) {
    D(("error setting environment.d variable \"%s\"", key));
  } else if (ctrl & PAM_DEBUG_ARG) {
    pam_syslog(pamh, LOG_DEBUG, "pam_putenv(\"%s\")", envvar);
  }
  pam_overwrite_string(envvar);
  free(envvar);
  return retval;
}

static char
_envd_quote_state(const char *line)
{
  const char *value = strchr(line, '=');
  char quote_char;

  if (value == NULL)
    return '\0';
  value += 1 + strspn(value + 1, " \t\r");
  quote_char = *value;
  if (quote_char != '"' && quote_char != '\'')
    return '\0';
  ++value;

  while (*value != '\0') {
    if (quote_char == '"' && *value == '\\' && value[1] != '\0') {
      ++value;
    } else if (*value == quote_char) {
      return '\0';
    }
    ++value;
  }
  return quote_char;
}

static int
_parse_envd_file(pam_handle_t *pamh, int ctrl, const char *filename)
{
  FILE *fp;
  char *line = NULL;
  size_t capacity = 0;
  ssize_t length;
  struct string_buffer logical_line;
  int retval = PAM_SUCCESS;

  fp = fopen(filename, "r");
  if (fp == NULL) {
    if (errno == ENOENT)
      return PAM_SUCCESS;
    pam_syslog(pamh, LOG_ERR, "Unable to open environment.d file: %s: %s",
	       filename, strerror(errno));
    return PAM_ABORT;
  }

  _strbuf_init(&logical_line);
  while ((length = getline(&line, &capacity, fp)) >= 0) {
    int has_newline = length > 0 && line[length - 1] == '\n';
    if (has_newline)
      line[--length] = '\0';
    if (logical_line.str == NULL) {
      const char *first_nonblank = line + strspn(line, " \t\r");
      if (*first_nonblank == '#' || *first_nonblank == ';')
	continue;
    }
    if (_strbuf_add_string(&logical_line, line)) {
      retval = PAM_BUF_ERR;
      break;
    }

    char quote_char = _envd_quote_state(logical_line.str);
    size_t trailing_backslashes = 0;
    while (trailing_backslashes < logical_line.len &&
	   logical_line.str[logical_line.len - trailing_backslashes - 1] == '\\')
      ++trailing_backslashes;
    if (has_newline && quote_char != '\'' && trailing_backslashes % 2 == 1) {
      logical_line.str[--logical_line.len] = '\0';
      continue;
    }
    if (has_newline && quote_char != '\0') {
      if (_strbuf_add_char(&logical_line, '\n')) {
	retval = PAM_BUF_ERR;
	break;
      }
      continue;
    }

    if (logical_line.str != NULL) {
      retval = _envd_set_line(pamh, ctrl, filename, logical_line.str);
      if (retval != PAM_SUCCESS)
	break;
    }
    _strbuf_free(&logical_line);
  }

  if (retval == PAM_SUCCESS && ferror(fp)) {
    pam_syslog(pamh, LOG_ERR, "Unable to read environment.d file: %s: %s",
	       filename, strerror(errno));
    retval = PAM_ABORT;
  }
  if (retval == PAM_SUCCESS && logical_line.str != NULL)
    retval = _envd_set_line(pamh, ctrl, filename, logical_line.str);
  _strbuf_free(&logical_line);
  free(line);
  if (fclose(fp) != 0 && retval == PAM_SUCCESS) {
    pam_syslog(pamh, LOG_ERR, "Unable to close environment.d file: %s: %s",
	       filename, strerror(errno));
    retval = PAM_ABORT;
  }
  if (retval == PAM_BUF_ERR)
    pam_syslog(pamh, LOG_ERR, "Cannot allocate memory.");
  return retval;
}

struct envd_file {
  char *name;
  char *path;
  int priority;
};

static char *
_find_environment_file(const pam_handle_t *pamh, const char *base_dir)
{
  char *system_file;
  struct stat statbuf;
  int stat_error;

  system_file = pam_asprintf("%s%s/environment",
			     base_dir == NULL ? "" : base_dir, SYSCONFDIR);
  if (system_file == NULL) {
    pam_syslog(pamh, LOG_ERR, "Cannot allocate memory.");
    return NULL;
  }
  if (stat(system_file, &statbuf) == 0 || errno != ENOENT)
    return system_file;

#ifdef VENDORDIR
  char *vendor_file = pam_asprintf("%s%s/environment",
				   base_dir == NULL ? "" : base_dir, VENDORDIR);
  if (vendor_file == NULL) {
    pam_syslog(pamh, LOG_ERR, "Cannot allocate memory.");
    free(system_file);
    return NULL;
  }
  if (stat(vendor_file, &statbuf) == 0) {
    free(system_file);
    return vendor_file;
  }
  stat_error = errno;
  free(vendor_file);
#else
  stat_error = errno;
#endif

  if (stat_error != ENOENT) {
    pam_syslog(pamh, LOG_ERR, "Unable to inspect environment file: %s",
	       strerror(stat_error));
  }
  return system_file;
}

static int
_envd_file_compare(const void *left, const void *right)
{
  const struct envd_file *a = left;
  const struct envd_file *b = right;
  int comparison = strcmp(a->name, b->name);

  if (comparison != 0)
    return comparison;
  return (a->priority > b->priority) - (a->priority < b->priority);
}

static int
_envd_add_directory(const pam_handle_t *pamh, const char *directory,
		    int priority, struct envd_file **files, size_t *count)
{
  DIR *dir;
  struct dirent *entry;
  struct stat null_stat;
  int has_null_stat = stat("/dev/null", &null_stat) == 0;

  if (directory == NULL)
    return PAM_SUCCESS;

  dir = opendir(directory);
  if (dir == NULL) {
    if (errno == ENOENT || errno == ENOTDIR)
      return PAM_SUCCESS;
    pam_syslog(pamh, LOG_ERR, "Unable to open environment.d directory %s: %s",
	       directory, strerror(errno));
    return PAM_ABORT;
  }

  for (;;) {
    size_t name_length;
    char *path;
    struct stat statbuf;
    struct envd_file *new_files;

    errno = 0;
    entry = readdir(dir);
    if (entry == NULL) {
      if (errno != 0) {
	pam_syslog(pamh, LOG_ERR, "Unable to read environment.d directory %s: %s",
		   directory, strerror(errno));
	closedir(dir);
	return PAM_ABORT;
      }
      break;
    }

    name_length = strlen(entry->d_name);
    if (name_length <= sizeof(".conf") - 1 ||
	strcmp(entry->d_name + name_length - (sizeof(".conf") - 1), ".conf") != 0)
      continue;
    path = pam_asprintf("%s/%s", directory, entry->d_name);
    if (path == NULL) {
      pam_syslog(pamh, LOG_ERR, "Cannot allocate memory.");
      closedir(dir);
      return PAM_BUF_ERR;
    }
    if (stat(path, &statbuf) != 0) {
      if (errno != ENOENT) {
	free(path);
	continue;
      }
    } else if (!S_ISREG(statbuf.st_mode) &&
	       !(has_null_stat && statbuf.st_dev == null_stat.st_dev &&
		 statbuf.st_ino == null_stat.st_ino)) {
      free(path);
      continue;
    }

    new_files = realloc(*files, (*count + 1) * sizeof(**files));
    if (new_files == NULL) {
      free(path);
      pam_syslog(pamh, LOG_ERR, "Cannot allocate memory.");
      closedir(dir);
      return PAM_BUF_ERR;
    }
    *files = new_files;
    (*files)[*count].name = strdup(entry->d_name);
    (*files)[*count].path = path;
    (*files)[*count].priority = priority;
    if ((*files)[*count].name == NULL) {
      free(path);
      pam_syslog(pamh, LOG_ERR, "Cannot allocate memory.");
      closedir(dir);
      return PAM_BUF_ERR;
    }
    ++*count;
  }

  if (closedir(dir) != 0) {
    pam_syslog(pamh, LOG_ERR, "Unable to close environment.d directory %s: %s",
	       directory, strerror(errno));
    return PAM_ABORT;
  }
  return PAM_SUCCESS;
}

static int
_parse_envd(pam_handle_t *pamh, int ctrl, const char *base_dir)
{
  struct envd_file *files = NULL;
  size_t count = 0;
  char *vendor_dir = NULL;
  char *sysconf_dir;
  int retval;

#ifdef VENDORDIR
  vendor_dir = pam_asprintf("%s%s/environment.d",
			    base_dir == NULL ? "" : base_dir, VENDORDIR);
  if (vendor_dir == NULL) {
    pam_syslog(pamh, LOG_ERR, "Cannot allocate memory.");
    return PAM_BUF_ERR;
  }
#endif
  sysconf_dir = pam_asprintf("%s%s/environment.d",
			     base_dir == NULL ? "" : base_dir, SYSCONFDIR);
  if (sysconf_dir == NULL) {
    pam_syslog(pamh, LOG_ERR, "Cannot allocate memory.");
    free(vendor_dir);
    return PAM_BUF_ERR;
  }

  retval = _envd_add_directory(pamh, vendor_dir, 0, &files, &count);
  if (retval == PAM_SUCCESS)
    retval = _envd_add_directory(pamh, sysconf_dir, 1, &files, &count);
  free(vendor_dir);
  free(sysconf_dir);
  if (retval != PAM_SUCCESS)
    goto done;

  if (count > 1)
    qsort(files, count, sizeof(*files), _envd_file_compare);
  for (size_t i = 0; i < count;) {
    size_t next = i + 1;
    size_t selected = i;
    struct stat file_stat, null_stat;
    int masked = 0;

    while (next < count && strcmp(files[i].name, files[next].name) == 0) {
      selected = next;
      ++next;
    }
    if (stat(files[selected].path, &file_stat) == 0 &&
	stat("/dev/null", &null_stat) == 0 &&
	file_stat.st_dev == null_stat.st_dev && file_stat.st_ino == null_stat.st_ino)
      masked = 1;
    if (!masked) {
      retval = _parse_envd_file(pamh, ctrl, files[selected].path);
      if (retval != PAM_SUCCESS)
	break;
    }
    i = next;
  }

done:
  for (size_t i = 0; i < count; ++i) {
    free(files[i].name);
    free(files[i].path);
  }
  free(files);
  return retval;
}

static int
_expand_arg(pam_handle_t *pamh, char **value)
{
  char *orig=*value;
  struct string_buffer buf;

  /*
   * Return early if there are no special characters present in the value.
   */
  if ((*value)[strcspn(*value, "\\$@")] == '\0') {
    return PAM_SUCCESS;
  }

  _strbuf_init(&buf);

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
      if ('$' != *orig && '@' != *orig && '\\' != *orig) {
	if (*orig) {
	  D(("Unrecognized escaped character: <%c> - ignoring", *orig));
	  pam_syslog(pamh, LOG_ERR,
		     "Unrecognized escaped character: <%c> - ignoring",
		     *orig);
	} else {
	  D(("Ignoring backslash at end of string"));
	  pam_syslog(pamh, LOG_ERR, "Ignoring backslash at end of string");
	}
      } else {
	/* Note the increment */
	if (_strbuf_add_char(&buf, *orig++)) {
	  goto buf_err;
	}
      }
      continue;
    }
    if ('$' == *orig || '@' == *orig) {
      if ('{' != *(orig+1)) {
	D(("Expandable variables must be wrapped in {}"
	   " <%s> - ignoring", orig));
	pam_syslog(pamh, LOG_ERR, "Expandable variables must be wrapped in {}"
		 " <%s> - ignoring", orig);
	/* Note the increment */
	if (_strbuf_add_char(&buf, *orig++)) {
	  goto buf_err;
	}
	continue;
      } else {
	const char *tmpptr=NULL, *tmpval;
	char *ptr;       /*
			  * Sure would be nice to use tmpptr but it needs to be
			  * a constant so that the compiler will shut up when I
			  * call pam_getenv and _pam_get_item_byname -- sigh
			  */
	char type;

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
	tmpval = orig;
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
	  if (_strbuf_add_string(&buf, tmpptr)) {
	    goto buf_err;
	  }
	}
      }           /* if ('{' != *orig++) */
    } else {      /* if ( '$' == *orig || '@' == *orig) */
      /* Note the increment */
      if (_strbuf_add_char(&buf, *orig++)) {
	goto buf_err;
      }
    }
  }              /* for (;*orig;) */

  if (buf.len > strlen(*value)) {
    free(*value);
    if ((*value = strdup(buf.str)) == NULL) {
      goto buf_err;
    }
  } else {
    const char *tmpptr = buf.str == NULL ? "" : buf.str;
    strcpy(*value, tmpptr);
  }
  _strbuf_free(&buf);
  D(("Exit."));

  return PAM_SUCCESS;
buf_err:
  _strbuf_free(&buf);
  return PAM_BUF_ERR;
abort_err:
  _strbuf_free(&buf);
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

  /* Now it's easy */

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
}

static int
_define_var(pam_handle_t *pamh, int ctrl, VAR *var)
{
  /* We have a variable to define, this is a simple function */

  char *envvar;
  int retval = PAM_SUCCESS;

  D(("Called."));
  if ((envvar = pam_asprintf("%s=%s", var->name, var->value)) == NULL) {
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
#else /* !USE_ECONF */
    /* Only one file will be parsed. So, file has to be set. */
    if (file == NULL) { /* No filename has been set via argv. */
      file = DEFAULT_CONF_FILE;
# ifdef VENDOR_DEFAULT_CONF_FILE
      /*
       * Check whether DEFAULT_CONF_FILE file is available.
       * If it does not exist, fall back to VENDOR_DEFAULT_CONF_FILE file.
       */
      struct stat stat_buffer;
      if (stat(file, &stat_buffer) != 0 && errno == ENOENT)
        file = VENDOR_DEFAULT_CONF_FILE;
# endif
    }
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
      if (PAM_SUCCESS != retval
	  && BAD_LINE != retval && PAM_BAD_ITEM != retval) break;

      retval = PAM_SUCCESS;
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
_parse_env_assignments(pam_handle_t *pamh, int ctrl, const char *file)
{
    int retval=PAM_SUCCESS, i, t;
    char *key, *mark;
    char **env_list = NULL;

#ifdef USE_ECONF
    retval = econf_read_file(pamh, file, "=", ENVIRONMENT, "", "", &env_list);
#else
    retval = read_file(pamh, file, &env_list);
#endif

    if (retval != PAM_SUCCESS)
      return retval;

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

static int
_parse_env_file(pam_handle_t *pamh, int ctrl, const char *file)
{
  int retval = PAM_SUCCESS;
  const char *base_dir = NULL;
  char *resolved_file = NULL;
  int read_envd = file == NULL;

  if (file != NULL && isDirectory(file)) {
    base_dir = file;
    read_envd = 1;
  }
  if (read_envd) {
    resolved_file = _find_environment_file(pamh, base_dir);
    if (resolved_file == NULL)
      return PAM_BUF_ERR;
    file = resolved_file;
  }

  retval = _parse_env_assignments(pamh, ctrl, file);
  if (retval == PAM_IGNORE)
    retval = PAM_SUCCESS;
  if (retval == PAM_SUCCESS && read_envd)
    retval = _parse_envd(pamh, ctrl, base_dir);
  free(resolved_file);
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
      if ((envpath = pam_asprintf("%s/%s", user_entry->pw_dir, user_env_file)) == NULL)
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
