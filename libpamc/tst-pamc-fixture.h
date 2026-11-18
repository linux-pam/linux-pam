/* Shared harness for tests that execute a real libpamc agent. */
#ifndef TST_PAMC_FIXTURE_H
#define TST_PAMC_FIXTURE_H

/*
 * Run a test in a supervised process with PAMC_AGENT_PATH pointing only at a
 * private temporary directory containing the helper under the name fixture.
 * The helper path is resolved before symlinking.  The supervisor enforces a
 * deadline, kills/reaps leftover descendants even if an assertion aborts the
 * test, and removes the temporary directory before reporting the result.
 */
void pamc_test_run(const char *helper, void (*test)(void));

/* Set worker context that survives an assertion, crash, or timeout.  The
 * supervisor prints the latest context only when a test fails.
 */
void pamc_test_case(const char *format, ...)
	__attribute__((__format__(__printf__, 1, 2)));

#endif
