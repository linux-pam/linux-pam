/*
 * Check pam_unix hash selection without reading or changing system files.
 * Only the login.defs lookup and logging are replaced; the control parser
 * is compiled from the module sources.  Password hash generation is
 * covered separately by tst-pam_unix-bcrypt-gen.
 */
#include "config.h"
#include "test_assert.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modutil.h>

#include "support.h"

static pam_handle_t *test_pamh;
static const char *encrypt_method;
static unsigned int log_count;

char *
pam_modutil_search_key(pam_handle_t *pamh UNUSED, const char *file_name,
                      const char *key)
{
        ASSERT_EQ(0, strcmp(file_name, LOGIN_DEFS));
        if (strcmp(key, "ENCRYPT_METHOD") == 0 && encrypt_method != NULL)
                return strdup(encrypt_method);
        return NULL;
}

void
pam_syslog(const pam_handle_t *pamh UNUSED, int priority UNUSED,
           const char *fmt, ...)
{
        va_list ap;
        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
        fputc('\n', stderr);
        ++log_count;
}

static unsigned long long
parse(const char *method, const char **args, int argc, int *rounds)
{
        encrypt_method = method;
        log_count = 0;
        *rounds = 0;
        unsigned long long ctrl = _set_ctrl(test_pamh, 0, NULL, rounds, NULL,
                                            argc, args);
        ASSERT_EQ(0U, log_count);
        return ctrl;
}

static void
check_bcrypt(const char *method, const char **args, int argc, int expected_rounds)
{
        int rounds;
        unsigned long long ctrl = parse(method, args, argc, &rounds);
        ASSERT_EQ(unix_args[UNIX_BLOWFISH_PASS].flag, ctrl & UNIX_HASH_ALGO_FLAGS);
        ASSERT_EQ(expected_rounds, rounds);
        ASSERT_NE(0ULL, on(UNIX_ALGO_ROUNDS, ctrl));
}

int
main(void)
{
        const char *bcrypt[] = { "bcrypt" };
        const char *blowfish[] = { "blowfish" };
        const char *sha512[] = { "sha512" };
        const char *last_bcrypt[] = { "sha512", "bcrypt" };
        const char *last_blowfish[] = { "bcrypt", "blowfish" };
        const char *last_sha512[] = { "bcrypt", "sha512" };
        const char *low[] = { "bcrypt", "rounds=1" };
        const char *high[] = { "rounds=100", "bcrypt" };
        int rounds;

        struct pam_conv conv = { NULL, NULL };
        const char *srcdir = getenv("srcdir");
        ASSERT_NE(NULL, srcdir);
        ASSERT_EQ(PAM_SUCCESS,
                  pam_start_confdir("confdir", "", &conv, srcdir, &test_pamh));
        ASSERT_NE(NULL, test_pamh);

        /* Existing spelling, new spelling, and login.defs are equivalent. */
        check_bcrypt(NULL, blowfish, 1, 5);
        check_bcrypt(NULL, bcrypt, 1, 5);
        check_bcrypt("BLOWFISH", NULL, 0, 5);
        check_bcrypt("BCRYPT", NULL, 0, 5);
        check_bcrypt("bCrYpT", NULL, 0, 5);
        check_bcrypt("SHA512", bcrypt, 1, 5);
        check_bcrypt(NULL, last_bcrypt, 2, 5);
        check_bcrypt(NULL, last_blowfish, 2, 5);
        check_bcrypt(NULL, low, 2, 4);
        check_bcrypt(NULL, high, 2, 31);

        /* Later module arguments still override aliases and login.defs. */
        unsigned long long ctrl = parse("BCRYPT", last_sha512, 2, &rounds);
        ASSERT_EQ(unix_args[UNIX_SHA512_PASS].flag, ctrl & UNIX_HASH_ALGO_FLAGS);
        ASSERT_EQ(0, rounds);

        /* A sole sha512 argument overrides ENCRYPT_METHOD=BCRYPT directly. */
        ctrl = parse("BCRYPT", sha512, 1, &rounds);
        ASSERT_EQ(unix_args[UNIX_SHA512_PASS].flag, ctrl & UNIX_HASH_ALGO_FLAGS);
        ASSERT_EQ(0, rounds);

        ctrl = parse(NULL, NULL, 0, &rounds);
        ASSERT_EQ(unix_args[UNIX_DEFAULT_HASH_ALGO].flag, ctrl & UNIX_HASH_ALGO_FLAGS);
        ASSERT_EQ(PAM_SUCCESS, pam_end(test_pamh, PAM_SUCCESS));
        puts("13 hash selection and rounds cases passed");
        return 0;
}
