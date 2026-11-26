/*
 * Check parsing of the method field in namespace.conf.
 */

#include "pam_namespace.c"

#include <stdio.h>
#include <string.h>

static int failures;

static void
check_method(const char *method, enum polymethod expected_method,
	     unsigned int expected_flags, const char *expected_mount_opts,
	     const char *expected_init_script, int check_mode,
	     mode_t expected_mode)
{
    struct instance_data idata;
    struct polydir_s poly;
    char buf[256];

    memset(&idata, 0, sizeof(idata));
    memset(&poly, 0, sizeof(poly));
    snprintf(buf, sizeof(buf), "%s", method);

    if (parse_method(buf, &poly, &idata) != 0) {
	fprintf(stderr, "%s: parse_method failed\n", method);
	failures++;
	return;
    }
    if (poly.method != expected_method) {
	fprintf(stderr, "%s: method is %d, expected %d\n", method,
		poly.method, expected_method);
	failures++;
    }
    if (poly.flags != expected_flags) {
	fprintf(stderr, "%s: flags are %#x, expected %#x\n", method,
		poly.flags, expected_flags);
	failures++;
    }
    if (expected_mount_opts != NULL &&
	(poly.mount_opts == NULL ||
	 strcmp(poly.mount_opts, expected_mount_opts) != 0)) {
	fprintf(stderr, "%s: mount options are \"%s\", expected \"%s\"\n",
		method, poly.mount_opts ? poly.mount_opts : "(null)",
		expected_mount_opts);
	failures++;
    }
    if (expected_init_script != NULL &&
	(poly.init_script == NULL ||
	 strcmp(poly.init_script, expected_init_script) != 0)) {
	fprintf(stderr, "%s: init script is \"%s\", expected \"%s\"\n",
		method, poly.init_script ? poly.init_script : "(null)",
		expected_init_script);
	failures++;
    }
    if (check_mode && poly.mode != expected_mode) {
	fprintf(stderr, "%s: mode is %#o, expected %#o\n", method,
		poly.mode, expected_mode);
	failures++;
    }

    free(poly.init_script);
    free(poly.mount_opts);
}

int
main(void)
{
    char init_script[128];

    check_method("tmpfs:mntopts=mpol=bind:0-1", TMPFS, POLYDIR_MNTOPTS,
		 "mpol=bind:0-1", NULL, 0, 0);
    check_method("tmpfs:mntopts=size=50%:noinit", TMPFS,
		 POLYDIR_MNTOPTS | POLYDIR_NOINIT, "size=50%", NULL, 0, 0);
    check_method("tmpfs:mntopts=size=50%:", TMPFS, POLYDIR_MNTOPTS,
		 "size=50%", NULL, 0, 0);
    check_method("tmpfs:mntopts=size=50%::create=0700", TMPFS,
		 POLYDIR_MNTOPTS | POLYDIR_CREATE, "size=50%", NULL, 1, 0700);
    check_method("tmpfs:mntopts=mpol=bind:0-1:shared", TMPFS,
		 POLYDIR_MNTOPTS | POLYDIR_SHARED, "mpol=bind:0-1", NULL, 0, 0);
    check_method("tmpfs:mntopts=size=50%,nosuid", TMPFS, POLYDIR_MNTOPTS,
		 "size=50%", NULL, 0, 0);

    snprintf(init_script, sizeof(init_script), "%s%s", NAMESPACE_D_DIR,
	     "setup");
    check_method("user:iscript=setup::create=0700", USER,
		 POLYDIR_ISCRIPT | POLYDIR_CREATE, NULL, init_script, 1, 0700);

    return failures ? 1 : 0;
}
