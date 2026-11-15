/*
 * Check pam_unix bcrypt hash generation without reading or changing
 * system files.  libcrypt bcrypt capability is detected directly through
 * libcrypt itself, never through the module code under test; when the
 * backend cannot generate bcrypt hashes the test exits 77 (skip) instead
 * of silently weakening its assertions.  Only the login.defs lookup and
 * logging are replaced; the hashing implementation is compiled from the
 * module sources.
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

#define SKIP 77 /* GNU convention: test skipped, recognized by Meson */

static pam_handle_t *test_pamh;

char *
pam_modutil_search_key(pam_handle_t *pamh UNUSED, const char *file_name UNUSED,
                      const char *key UNUSED)
{
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
}

static int
bcrypt_generation_supported(void)
{
#if defined(CRYPT_GENSALT_IMPLEMENTS_AUTO_ENTROPY) && CRYPT_GENSALT_IMPLEMENTS_AUTO_ENTROPY
        /* Ask libcrypt for a bcrypt salt directly. */
#if defined(CRYPT_GENSALT_OUTPUT_SIZE) && CRYPT_GENSALT_OUTPUT_SIZE > 64
        char salt[CRYPT_GENSALT_OUTPUT_SIZE];
#else
        char salt[64];
#endif
        return crypt_gensalt_rn("$2b$", 5, NULL, 0, salt, sizeof(salt)) != NULL
                && strncmp(salt, "$2b$05$", 7) == 0;
#else
        /* The module builds the salt itself on this route; probe libcrypt
         * with a fixed, well-formed bcrypt salt instead. */
        const char *hash = crypt("capability probe",
                                 "$2b$05$abcdefghijklmnopqrstuu");
        return hash != NULL && strncmp(hash, "$2b$05$", 7) == 0;
#endif
}

static void
check_generation(unsigned long long ctrl, int rounds, const char *prefix)
{
        char *result = create_password_hash(test_pamh, "test fixture", ctrl,
                                            rounds);
        ASSERT_NE(NULL, result);
        ASSERT_EQ(0, strncmp(result, prefix, strlen(prefix)));
        const char *verified = crypt("test fixture", result);
        ASSERT_NE(NULL, verified);
        ASSERT_EQ(0, strcmp(result, verified));
        free(result);
}

int
main(void)
{
        int rounds;
        struct pam_conv conv = { NULL, NULL };
        const char *srcdir = getenv("srcdir");
        ASSERT_NE(NULL, srcdir);
        ASSERT_EQ(PAM_SUCCESS,
                  pam_start_confdir("confdir", "", &conv, srcdir, &test_pamh));
        ASSERT_NE(NULL, test_pamh);

        if (!bcrypt_generation_supported()) {
                puts("SKIP: libcrypt cannot generate bcrypt hashes");
                ASSERT_EQ(PAM_SUCCESS, pam_end(test_pamh, PAM_SUCCESS));
                return SKIP;
        }

        /* The blowfish control flag generates a $2b$ hash. */
        check_generation(unix_args[UNIX_BLOWFISH_PASS].flag
                         | unix_args[UNIX_ALGO_ROUNDS].flag, 5, "$2b$05$");

        /* The bcrypt alias selects the same generation end to end. */
        const char *bcrypt[] = { "bcrypt" };
        unsigned long long ctrl = _set_ctrl(test_pamh, 0, NULL, &rounds, NULL,
                                            1, bcrypt);
        ASSERT_EQ(unix_args[UNIX_BLOWFISH_PASS].flag, ctrl & UNIX_HASH_ALGO_FLAGS);
        check_generation(ctrl, rounds, "$2b$05$");

        ASSERT_EQ(PAM_SUCCESS, pam_end(test_pamh, PAM_SUCCESS));
        puts("2 bcrypt generation and verification cases passed");
        return 0;
}
