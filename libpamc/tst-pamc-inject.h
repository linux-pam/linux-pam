/*
 * Force-included only when compiling private libpamc test objects.
 *
 * Include libc headers BEFORE renaming calls.  Renaming their declarations
 * also renames fortified inline wrappers, whose bodies can still call the
 * real read()/__read_chk() or __vasprintf_chk() and bypass our hooks.
 * The hook implementations are compiled without this header and continue
 * using normal fortified, sanitizer-intercepted libc entry points.
 */
#ifndef TST_PAMC_INJECT_H
#define TST_PAMC_INJECT_H

#include <config.h>

#if defined(PAMC_TEST_IO) && defined(PAMC_TEST_FAULTS)
# error Select exactly one libpamc injection mode
#elif defined(PAMC_TEST_IO)
# include <unistd.h>
# include "tst-pamc-io.h"
# undef read
# undef write
# define read pamc_test_read
# define write pamc_test_write
#elif defined(PAMC_TEST_FAULTS)
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <unistd.h>
# include <sys/wait.h>
# include "tst-pamc-faults.h"
# undef malloc
# undef calloc
# undef strdup
# undef free
# undef vasprintf
# undef pipe
# undef fork
# undef dup2
# undef execle
# undef waitpid
# define malloc pamc_fault_malloc
# define calloc pamc_fault_calloc
# define strdup pamc_fault_strdup
# define free pamc_fault_free
# define vasprintf pamc_fault_vasprintf
# define pipe pamc_fault_pipe
# define fork pamc_fault_fork
# define dup2 pamc_fault_dup2
# define execle pamc_fault_execle
# define waitpid pamc_fault_waitpid
#else
# error Select a libpamc injection mode
#endif

#endif
