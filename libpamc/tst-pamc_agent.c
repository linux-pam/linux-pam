/* Smoke tests for the reusable agent fixture, through the built libpamc. */
#include "test_assert.h"
#include "tst-pamc-fixture.h"

#include <string.h>
#include <security/pam_client.h>

static void
exercise_agent(const char *selection, int expected_end)
{
	/* NUL and high-bit bytes distinguish binary echo from a string copy. */
	static const uint8_t payload[] = { 0x11, 0x00, 0x80, 0xff };
	pamc_bp_t prompt = NULL;
	pamc_handle_t handle = pamc_start();

	ASSERT_NE(NULL, handle);
	PAM_BP_RENEW(&prompt, PAM_BPC_SELECT, strlen(selection));
	ASSERT_NE(NULL, prompt);
	memcpy(PAM_BP_WDATA(prompt), selection, strlen(selection));
	ASSERT_EQ(PAM_BPC_TRUE, pamc_converse(handle, &prompt));
	ASSERT_NE(NULL, prompt);
	ASSERT_EQ(PAM_BPC_OK, PAM_BP_RCONTROL(prompt));
	ASSERT_EQ(0U, PAM_BP_LENGTH(prompt));
	PAM_BP_RENEW(&prompt, 0, 0);

	/* Exercise more than one exchange in the same helper process. */
	static const uint8_t controls[] = { PAM_BPC_OK, PAM_BPC_DONE };
	for (size_t i = 0; i < sizeof(controls); ++i) {
		PAM_BP_RENEW(&prompt, controls[i], sizeof(payload));
		ASSERT_NE(NULL, prompt);
		memcpy(PAM_BP_WDATA(prompt), payload, sizeof(payload));
		ASSERT_EQ(PAM_BPC_TRUE, pamc_converse(handle, &prompt));
		ASSERT_NE(NULL, prompt);
		ASSERT_EQ(controls[i], PAM_BP_RCONTROL(prompt));
		ASSERT_EQ(sizeof(payload), PAM_BP_LENGTH(prompt));
		ASSERT_EQ(0, memcmp(payload, PAM_BP_RDATA(prompt), sizeof(payload)));
		ASSERT_EQ(0, PAM_BP_RDATA(prompt)[sizeof(payload)]);
		PAM_BP_RENEW(&prompt, 0, 0);
	}
	/*
	 * Closing the input delivers EOF and makes the helper return its mode's
	 * status.  pamc_end() must wait for and reap that helper.
	 */
	ASSERT_EQ(expected_end, pamc_end(&handle));
	ASSERT_EQ(NULL, handle);
}

static void
test_echo(void)
{
	exercise_agent("fixture/echo", PAM_BPC_TRUE);
}

static void
test_exit_failure(void)
{
	exercise_agent("fixture/exit-failure", PAM_BPC_FALSE);
}

int
main(int argc, char **argv)
{
	ASSERT_EQ(2, argc);
	pamc_test_run(argv[1], test_echo);
	pamc_test_run(argv[1], test_exit_failure);
	return 0;
}
