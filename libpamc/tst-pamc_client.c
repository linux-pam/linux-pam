/* Public lifecycle tests.  Each callback runs in the supervised fixture. */
#include "test_assert.h"
#include "tst-pamc-fixture.h"

#include <string.h>
#include <security/pam_client.h>

static void
test_handles(void)
{
	pamc_handle_t empty = NULL;

	ASSERT_EQ(PAM_BPC_FALSE, pamc_end(NULL));
	ASSERT_EQ(PAM_BPC_FALSE, pamc_end(&empty));
	/* No configured directories means no host-dependent default agents. */
	ASSERT_EQ(0, setenv("PAMC_AGENT_PATH", "", 1));
	for (int i = 0; i < 3; ++i) {
		pamc_handle_t first = pamc_start(), second = pamc_start();

		ASSERT_NE(NULL, first);
		ASSERT_NE(NULL, second);
		ASSERT_NE(first, second);
		ASSERT_EQ(PAM_BPC_TRUE, pamc_end(&first));
		ASSERT_EQ(NULL, first);
		ASSERT_EQ(PAM_BPC_FALSE, pamc_end(&first));
		ASSERT_EQ(PAM_BPC_TRUE, pamc_end(&second));
		ASSERT_EQ(NULL, second);
	}
}

static void
test_disable(void)
{
	pamc_handle_t first = pamc_start(), second = pamc_start();

	ASSERT_NE(NULL, first);
	ASSERT_NE(NULL, second);
	ASSERT_EQ(PAM_BPC_FALSE, pamc_disable(NULL, "fixture"));
	ASSERT_EQ(PAM_BPC_FALSE, pamc_disable(first, NULL));
	ASSERT_EQ(PAM_BPC_FALSE, pamc_load(NULL, "fixture"));
	ASSERT_EQ(PAM_BPC_FALSE, pamc_load(first, NULL));
	ASSERT_EQ(PAM_BPC_FALSE, pamc_load(first, "not_installed"));
	ASSERT_EQ(PAM_BPC_TRUE, pamc_disable(first, "not_installed"));
	ASSERT_EQ(PAM_BPC_TRUE, pamc_disable(first, "fixture"));
	ASSERT_EQ(PAM_BPC_TRUE, pamc_disable(first, "fixture"));
	ASSERT_EQ(PAM_BPC_FALSE, pamc_load(first, "fixture"));
	/* Blocking is per handle; an already loaded agent cannot be disabled. */
	ASSERT_EQ(PAM_BPC_TRUE, pamc_load(second, "fixture"));
	ASSERT_EQ(PAM_BPC_FALSE, pamc_disable(second, "fixture"));
	ASSERT_EQ(PAM_BPC_TRUE, pamc_end(&first));
	ASSERT_EQ(PAM_BPC_TRUE, pamc_end(&second));
}

static void
select_mode(pamc_handle_t handle, const char *selection)
{
	pamc_bp_t bp = NULL;

	PAM_BP_RENEW(&bp, PAM_BPC_SELECT, strlen(selection));
	ASSERT_NE(NULL, bp);
	memcpy(PAM_BP_WDATA(bp), selection, strlen(selection));
	ASSERT_EQ(PAM_BPC_TRUE, pamc_converse(handle, &bp));
	ASSERT_NE(NULL, bp);
	ASSERT_EQ(PAM_BPC_OK, PAM_BP_RCONTROL(bp));
	PAM_BP_RENEW(&bp, 0, 0);
}

static void
test_shutdown(void)
{
	static const struct {
		const char *mode;
		int expected;
	} cases[] = {
		{ "other/echo", PAM_BPC_TRUE },
		{ "other/exit-failure", PAM_BPC_FALSE },
		{ "other/exit-signal", PAM_BPC_FALSE }
	};
	char original[PATH_MAX], alias[PATH_MAX];
	const char *directory = getenv("PAMC_AGENT_PATH");

	ASSERT_LT(snprintf(original, sizeof(original), "%s/fixture", directory),
		  (int) sizeof(original));
	ASSERT_LT(snprintf(alias, sizeof(alias), "%s/other", directory),
		  (int) sizeof(alias));
	ASSERT_EQ(0, symlink(original, alias));

	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
		pamc_handle_t handle = pamc_start();

		ASSERT_NE(NULL, handle);
		/* The newest agent is reaped first.  Even its failure must not
		 * prevent reaping the older successful agent or freeing block records.
		 */
		select_mode(handle, "fixture/echo");
		select_mode(handle, cases[i].mode);
		ASSERT_EQ(PAM_BPC_TRUE, pamc_disable(handle, "not_installed"));
		ASSERT_EQ(cases[i].expected, pamc_end(&handle));
		ASSERT_EQ(NULL, handle);
	}
}

int
main(int argc, char **argv)
{
	ASSERT_EQ(2, argc);
	pamc_test_run(argv[1], test_handles);
	pamc_test_run(argv[1], test_disable);
	pamc_test_run(argv[1], test_shutdown);
	return 0;
}
