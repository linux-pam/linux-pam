/* Discovery and loading through public APIs, never the host's agent paths. */
#include "test_assert.h"
#include "tst-pamc-fixture.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <security/pam_client.h>

static char root[PATH_MAX];
static char alternate[PATH_MAX];

static void
path(char *result, size_t size, const char *name)
{
	ASSERT_LT(snprintf(result, size, "%s/%s", root, name), (int) size);
}

static void
install(const char *name, const char *helper)
{
	char file[PATH_MAX];

	path(file, sizeof(file), name);
	ASSERT_EQ(0, symlink(helper, file));
}

static void
prepare(void)
{
	char directory[PATH_MAX];

	ASSERT_LT(snprintf(root, sizeof(root), "%s", getenv("PAMC_AGENT_PATH")),
		  (int) sizeof(root));
	path(directory, sizeof(directory), "first");
	ASSERT_EQ(0, mkdir(directory, 0700));
	path(directory, sizeof(directory), "second");
	ASSERT_EQ(0, mkdir(directory, 0700));
}

enum path_config { SINGLE_PATH, OVERLAPPING_PATHS };

static void
set_paths(enum path_config config)
{
	/* Components are suffixes under the private fixture directory. */
	char paths[4 * PATH_MAX];
	char first[PATH_MAX], second[PATH_MAX], missing[PATH_MAX];

	path(first, sizeof(first), "first");
	path(second, sizeof(second), "second");
	path(missing, sizeof(missing), "missing");
	if (config == SINGLE_PATH)
		ASSERT_EQ(0, setenv("PAMC_AGENT_PATH", first, 1));
	else {
		ASSERT_LT(snprintf(paths, sizeof(paths), "%s:%s:%s:%s", missing,
				   first, second, first), (int) sizeof(paths));
		ASSERT_EQ(0, setenv("PAMC_AGENT_PATH", paths, 1));
	}
}

static void
check_list(pamc_handle_t handle, const char *const *expected, size_t count)
{
	char **agents = pamc_list_agents(handle);

	ASSERT_NE(NULL, agents);
	for (size_t i = 0; i < count; ++i) {
		ASSERT_NE(NULL, agents[i]);
		ASSERT_EQ(0, strcmp(expected[i], agents[i]));
		free(agents[i]);
	}
	ASSERT_EQ(NULL, agents[count]);
	free(agents);
}

static void
test_listing(void)
{
	static const char *const expected[] = { "Alpha", "middle", "zeta" };
	char helper[PATH_MAX];

	prepare();
	path(helper, sizeof(helper), "fixture");
	set_paths(SINGLE_PATH);
	pamc_handle_t empty = pamc_start();
	ASSERT_NE(NULL, empty);
	check_list(empty, NULL, 0);
	ASSERT_EQ(PAM_BPC_TRUE, pamc_end(&empty));

	/* Multiple distinct names expose undercounted trees; overlapping and
	 * repeated directories must neither duplicate names nor inflate counts.
	 */
	install("first/zeta", helper);
	install("first/Alpha", helper);
	install("second/middle", helper);
	install("second/Alpha", helper);
	set_paths(OVERLAPPING_PATHS);
	pamc_handle_t handle = pamc_start();
	ASSERT_NE(NULL, handle);
	check_list(handle, expected, sizeof(expected) / sizeof(expected[0]));
	check_list(handle, expected, sizeof(expected) / sizeof(expected[0]));
	ASSERT_EQ(PAM_BPC_TRUE, pamc_end(&handle));
}

static void
test_agent_ids(void)
{
	static const char *const valid[] = { "A1_", "a@host.name" };
	static const char *const invalid[] = {
		".hidden", "@host", "name@", "name@.host", "a@@host",
		"a b", "a\x80", "!aaa", "a!aa", "aa!a", "aaa!"
	};
	char helper[PATH_MAX], name[PATH_MAX];

	prepare();
	path(helper, sizeof(helper), "fixture");
	for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); ++i) {
		ASSERT_LT(snprintf(name, sizeof(name), "first/%s", valid[i]),
			  (int) sizeof(name));
		install(name, helper);
	}
	for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
		ASSERT_LT(snprintf(name, sizeof(name), "first/%s", invalid[i]),
			  (int) sizeof(name));
		install(name, helper);
	}
	set_paths(SINGLE_PATH);
	pamc_handle_t handle = pamc_start();
	ASSERT_NE(NULL, handle);
	/* Illegal characters at every position catch skipped-character scans.
	 * Empty IDs and missing SELECT delimiters cannot be directory entries.
	 */
	check_list(handle, valid, sizeof(valid) / sizeof(valid[0]));
	static const char *const bad_selection[] = { "/identity", "identity" };
	for (size_t i = 0; i < sizeof(bad_selection) / sizeof(bad_selection[0]); ++i) {
		pamc_bp_t bp = NULL;
		PAM_BP_RENEW(&bp, PAM_BPC_SELECT, strlen(bad_selection[i]));
		ASSERT_NE(NULL, bp);
		memcpy(PAM_BP_WDATA(bp), bad_selection[i], strlen(bad_selection[i]));
		ASSERT_EQ(PAM_BPC_TRUE, pamc_converse(handle, &bp));
		ASSERT_NE(NULL, bp);
		ASSERT_EQ(PAM_BPC_FAIL, PAM_BP_RCONTROL(bp));
		PAM_BP_RENEW(&bp, 0, 0);
	}
	ASSERT_EQ(PAM_BPC_TRUE, pamc_end(&handle));
}

/* Identity payload: variant octet followed by four PID octets, big-endian. */
static uint32_t
identity(pamc_handle_t handle, const char *name, uint8_t variant)
{
	char selection[PATH_MAX];
	pamc_bp_t bp = NULL;

	ASSERT_LT(snprintf(selection, sizeof(selection), "%s/identity", name),
		  (int) sizeof(selection));
	PAM_BP_RENEW(&bp, PAM_BPC_SELECT, strlen(selection));
	ASSERT_NE(NULL, bp);
	memcpy(PAM_BP_WDATA(bp), selection, strlen(selection));
	ASSERT_EQ(PAM_BPC_TRUE, pamc_converse(handle, &bp));
	ASSERT_NE(NULL, bp);
	ASSERT_EQ(PAM_BPC_OK, PAM_BP_RCONTROL(bp));
	ASSERT_EQ(5U, PAM_BP_LENGTH(bp));
	const uint8_t *data = PAM_BP_RDATA(bp);
	ASSERT_EQ(variant, data[0]);
	uint32_t pid = ((uint32_t) data[1] << 24) | ((uint32_t) data[2] << 16)
		| ((uint32_t) data[3] << 8) | data[4];
	ASSERT_NE(0U, pid);
	PAM_BP_RENEW(&bp, 0, 0);
	return pid;
}

static void
test_loading(void)
{
	char helper[PATH_MAX];

	prepare();
	path(helper, sizeof(helper), "fixture");
	install("first/shared", helper);
	install("second/shared", alternate);
	install("second/fallback", alternate);
	set_paths(OVERLAPPING_PATHS);
	pamc_handle_t handle = pamc_start();
	ASSERT_NE(NULL, handle);
	/* Paths are captured at start, not taken from later environment changes. */
	ASSERT_EQ(0, setenv("PAMC_AGENT_PATH", "", 1));
	ASSERT_EQ(PAM_BPC_FALSE, pamc_load(handle, "not_installed"));
	ASSERT_EQ(PAM_BPC_FALSE, pamc_load(handle, "bad/name"));
	ASSERT_EQ(PAM_BPC_TRUE, pamc_load(handle, "shared"));
	/* Build variants 0/1 identify the first/alternate helper executable. */
	uint32_t first = identity(handle, "shared", 0);
	/* Repeated loading and reselection must use the same living process. */
	ASSERT_EQ(PAM_BPC_TRUE, pamc_load(handle, "shared"));
	ASSERT_EQ(first, identity(handle, "shared", 0));
	uint32_t second = identity(handle, "fallback", 1);
	ASSERT_NE(first, second);
	ASSERT_EQ(first, identity(handle, "shared", 0));
	ASSERT_EQ(PAM_BPC_FALSE, pamc_disable(handle, "shared"));
	ASSERT_EQ(PAM_BPC_TRUE, pamc_end(&handle));
	ASSERT_EQ(NULL, handle);
}

int
main(int argc, char **argv)
{
	ASSERT_EQ(3, argc);
	ASSERT_NE(NULL, realpath(argv[2], alternate));
	pamc_test_run(argv[1], test_listing);
	pamc_test_run(argv[1], test_agent_ids);
	pamc_test_run(argv[1], test_loading);
	return 0;
}
