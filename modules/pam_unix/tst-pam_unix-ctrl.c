/*
 * Check pam_unix hash selection without reading or changing system files.
 * Only the login.defs lookup and logging are replaced; the control parser and
 * password hashing implementation are compiled from the module sources.
 */
#include "config.h"
#include "test_assert.h"

#include <unistd.h>
#ifdef HAVE_CRYPT_H
#include <crypt.h>
#endif
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modutil.h>

#include "support.h"
#include "passverify.h"

static pam_handle_t *test_pamh;
static const char *encrypt_method;
static unsigned int log_count;
static int hash_supported;

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
check_bcrypt(const char *method, const char **args, int argc, int expected_rounds,
             int hash)
{
        int rounds;
        unsigned long long ctrl = parse(method, args, argc, &rounds);
        ASSERT_EQ(unix_args[UNIX_BLOWFISH_PASS].flag, ctrl & UNIX_HASH_ALGO_FLAGS);
        ASSERT_EQ(expected_rounds, rounds);
        ASSERT_NE(0ULL, on(UNIX_ALGO_ROUNDS, ctrl));
        if (hash && hash_supported) {
                char *result = create_password_hash(test_pamh, "test fixture", ctrl, rounds);
                ASSERT_NE(NULL, result);
                ASSERT_EQ(0, strncmp(result, "$2b$05$", 7));
                const char *verified = crypt("test fixture", result);
                ASSERT_NE(NULL, verified);
                ASSERT_EQ(0, strcmp(result, verified));
                free(result);
        }
}

int
main(void)
{
        const char *bcrypt[] = { "bcrypt" };
        const char *blowfish[] = { "blowfish" };
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

        /* The existing fallback generator is not supported by every bcrypt
         * backend. Keep option coverage independent of that generator route. */
#if defined(CRYPT_GENSALT_IMPLEMENTS_AUTO_ENTROPY) && CRYPT_GENSALT_IMPLEMENTS_AUTO_ENTROPY
        const unsigned long long legacy_ctrl = unix_args[UNIX_BLOWFISH_PASS].flag
                                             | unix_args[UNIX_ALGO_ROUNDS].flag;
        char *probe = create_password_hash(test_pamh, "test fixture", legacy_ctrl, 5);
        if (probe != NULL && strncmp(probe, "$2b$05$", 7) == 0) {
                const char *verified = crypt("test fixture", probe);
                hash_supported = verified != NULL && strcmp(probe, verified) == 0;
        }
        free(probe);
#endif
        if (!hash_supported)
                puts("bcrypt generation unavailable; checking option parsing only");

        /* Existing spelling, new spelling, and login.defs are equivalent. */
        check_bcrypt(NULL, blowfish, 1, 5, 1);
        check_bcrypt(NULL, bcrypt, 1, 5, 1);
        check_bcrypt("BLOWFISH", NULL, 0, 5, 1);
        check_bcrypt("BCRYPT", NULL, 0, 5, 1);
        check_bcrypt("bCrYpT", NULL, 0, 5, 0);
        check_bcrypt("SHA512", bcrypt, 1, 5, 0);
        check_bcrypt(NULL, last_bcrypt, 2, 5, 0);
        check_bcrypt(NULL, last_blowfish, 2, 5, 0);
        check_bcrypt(NULL, low, 2, 4, 0);
        check_bcrypt(NULL, high, 2, 31, 0);

        /* Later module arguments still override aliases and login.defs. */
        unsigned long long ctrl = parse("BCRYPT", last_sha512, 2, &rounds);
        ASSERT_EQ(unix_args[UNIX_SHA512_PASS].flag, ctrl & UNIX_HASH_ALGO_FLAGS);
        ASSERT_EQ(0, rounds);
        ctrl = parse(NULL, NULL, 0, &rounds);
        ASSERT_EQ(unix_args[UNIX_DEFAULT_HASH_ALGO].flag, ctrl & UNIX_HASH_ALGO_FLAGS);
        ASSERT_EQ(PAM_SUCCESS, pam_end(test_pamh, PAM_SUCCESS));
        puts("12 hash selection and rounds cases passed");
        if (hash_supported)
                puts("4 bcrypt generation and verification cases passed");
        return 0;
}
