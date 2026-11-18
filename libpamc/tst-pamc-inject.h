/*
 * Force-included only when compiling private libpamc I/O test objects.
 * Include libc headers BEFORE renaming calls: fortified inline wrappers
 * otherwise bypass injection through read()/__read_chk().
 * Hook implementations use normal fortified libc entry points.
 */
#ifndef TST_PAMC_INJECT_H
#define TST_PAMC_INJECT_H

#include <config.h>

#ifndef PAMC_TEST_IO
# error Select libpamc I/O injection mode
#endif
#include <unistd.h>
#include "tst-pamc-io.h"
#undef read
#undef write
#define read pamc_test_read
#define write pamc_test_write

#endif
