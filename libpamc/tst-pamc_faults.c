/*
 * Fail each allocation of an operation, then retry without injection.  Profile
 * the call count first rather than hardcoding allocator implementation details.
 * Every failure must roll back heap/descriptors and leave no child behind.
 * Separate debug/NDEBUG builds preserve the public macros' assertion policy.
 */
#include "test_assert.h"
#include "tst-pamc-fixture.h"
#include "tst-pamc-faults.h"

#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* Release library-owned reply allocations through the tracking free hook. */
#define PAM_BP_FREE pamc_fault_free
#include <security/pam_client.h>

static void
reset(void)
{
	pamc_fault_arm(FAULT_NONE, 0, 0);
}

static size_t
fd_count(void)
{
	DIR *dir = opendir("/proc/self/fd");
	struct dirent *entry;
	size_t count = 0;

	ASSERT_NE(NULL, dir);
	while ((entry = readdir(dir)) != NULL)
		if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, ".."))
			++count;
	ASSERT_EQ(0, closedir(dir));
	return count; /* Includes this function's directory FD on every call. */
}

static void
check_clean(size_t fds)
{
	ASSERT_EQ(0U, pamc_fault_live_blocks());
	ASSERT_EQ(fds, fd_count());
	errno = 0;
	ASSERT_EQ(-1, waitpid(-1, NULL, WNOHANG));
	ASSERT_EQ(ECHILD, errno);
}

static pamc_handle_t
start(void)
{
	pamc_handle_t handle = pamc_start();
	ASSERT_NE(NULL, handle);
	return handle;
}

static void
finish(pamc_handle_t *handle, int expected, size_t fds)
{
	ASSERT_EQ(expected, pamc_end(handle));
	ASSERT_EQ(NULL, *handle);
	check_clean(fds);
}

static void
test_start_allocations(void)
{
	pamc_test_case("pamc_start: allocation profile");
	/* Several path components exercise cleanup after partial initialization. */
	char paths[3 * PATH_MAX];
	const char *dir = getenv("PAMC_AGENT_PATH");
	ASSERT_LT(snprintf(paths, sizeof(paths), "%s:%s:%s", dir, dir, dir),
		  (int) sizeof(paths));
	ASSERT_EQ(0, setenv("PAMC_AGENT_PATH", paths, 1));
	size_t fds = fd_count();
	reset();
	pamc_handle_t handle = start();
	size_t allocations = pamc_fault_calls(FAULT_ALLOC);
	finish(&handle, PAM_BPC_TRUE, fds);
	ASSERT_NE(0U, allocations);
	for (size_t nth = 1; nth <= allocations; ++nth) {
		pamc_test_case("pamc_start: allocation %zu/%zu (injection)",
			       nth, allocations);
		pamc_fault_arm(FAULT_ALLOC, nth, 0);
		ASSERT_EQ(NULL, pamc_start());
		ASSERT_EQ(1U, pamc_fault_hits());
		check_clean(fds);
		reset();
		pamc_test_case("pamc_start: allocation %zu/%zu (recovery)",
			       nth, allocations);
		handle = start();
		finish(&handle, PAM_BPC_TRUE, fds);
	}
}

static void
test_disable_allocations(void)
{
	pamc_test_case("pamc_disable: allocation profile");
	size_t fds = fd_count();
	pamc_handle_t handle = start();
	reset();
	ASSERT_EQ(PAM_BPC_TRUE, pamc_disable(handle, "fixture"));
	size_t allocations = pamc_fault_calls(FAULT_ALLOC);
	finish(&handle, PAM_BPC_TRUE, fds);
	ASSERT_NE(0U, allocations);
	for (size_t nth = 1; nth <= allocations; ++nth) {
		pamc_test_case("pamc_disable: allocation %zu/%zu (injection)",
			       nth, allocations);
		reset();
		handle = start();
		size_t baseline = pamc_fault_live_blocks();
		pamc_fault_arm(FAULT_ALLOC, nth, 0);
		ASSERT_EQ(PAM_BPC_FALSE, pamc_disable(handle, "fixture"));
		ASSERT_EQ(1U, pamc_fault_hits());
		ASSERT_EQ(baseline, pamc_fault_live_blocks());
		ASSERT_EQ(fds, fd_count());
		reset();
		/* A failed disable must not accidentally leave the agent blocked. */
		pamc_test_case("pamc_disable: allocation %zu/%zu (recovery)",
			       nth, allocations);
		ASSERT_EQ(PAM_BPC_TRUE, pamc_load(handle, "fixture"));
		finish(&handle, PAM_BPC_TRUE, fds);
	}
}

static void
test_load_allocations(void)
{
	pamc_test_case("pamc_load: allocation profile");
	size_t fds = fd_count();
	pamc_handle_t handle = start();
	reset();
	ASSERT_EQ(PAM_BPC_TRUE, pamc_load(handle, "fixture"));
	size_t allocations = pamc_fault_calls(FAULT_ALLOC);
	ASSERT_NE(0U, pamc_fault_format_calls());
	finish(&handle, PAM_BPC_TRUE, fds);
	ASSERT_NE(0U, allocations);
	for (size_t nth = 1; nth <= allocations; ++nth) {
		pamc_test_case("pamc_load: allocation %zu/%zu (injection)",
			       nth, allocations);
		reset();
		handle = start();
		size_t baseline = pamc_fault_live_blocks();
		pamc_fault_arm(FAULT_ALLOC, nth, 0);
		ASSERT_EQ(PAM_BPC_FALSE, pamc_load(handle, "fixture"));
		ASSERT_EQ(1U, pamc_fault_hits());
		ASSERT_EQ(baseline, pamc_fault_live_blocks());
		ASSERT_EQ(fds, fd_count());
		reset();
		pamc_test_case("pamc_load: allocation %zu/%zu (recovery)",
			       nth, allocations);
		ASSERT_EQ(PAM_BPC_TRUE, pamc_load(handle, "fixture"));
		finish(&handle, PAM_BPC_TRUE, fds);
	}
}

static void
test_launch_failures(void)
{
	static const struct {
		const char *name;
		enum pamc_fault fault;
		size_t nth;
		int child_failure;
	} cases[] = {
		{ "pipe to agent", FAULT_PIPE, 1, 0 },
		{ "pipe from agent", FAULT_PIPE, 2, 0 },
		{ "fork", FAULT_FORK, 1, 0 },
		{ "execle", FAULT_EXEC, 1, 1 }
	};
	size_t fds = fd_count();
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
		pamc_test_case("pamc_load: %s, call %zu (injection)",
			       cases[i].name, cases[i].nth);
		reset();
		pamc_handle_t handle = start();
		size_t baseline = pamc_fault_live_blocks();
		if (cases[i].child_failure)
			pamc_fault_watch_child();
		pamc_fault_arm(cases[i].fault, cases[i].nth, 0);
		/* Child failures are asynchronous: load succeeds, end reports them.
		 * The child has its own copy of the injection counters after fork.
		 */
		ASSERT_EQ(cases[i].child_failure ? PAM_BPC_TRUE : PAM_BPC_FALSE,
			  pamc_load(handle, "fixture"));
		if (!cases[i].child_failure) {
			ASSERT_EQ(1U, pamc_fault_hits());
			ASSERT_EQ(baseline, pamc_fault_live_blocks());
			ASSERT_EQ(fds, fd_count());
		}
		reset();
		finish(&handle, cases[i].child_failure ? PAM_BPC_FALSE : PAM_BPC_TRUE,
		       fds);
		if (cases[i].child_failure) {
			struct pamc_child_fault report = pamc_fault_child_report();

			ASSERT_EQ(1U, report.hits);
			ASSERT_NE(0, report.expected_pid);
			ASSERT_EQ(report.expected_pid, report.injector_pid);
			ASSERT_EQ(cases[i].fault, report.fault);
			ASSERT_EQ(cases[i].nth, report.nth);
			pamc_fault_unwatch_child();
		}
		pamc_test_case("pamc_load: %s, call %zu (recovery)",
			       cases[i].name, cases[i].nth);
		handle = start();
		ASSERT_EQ(PAM_BPC_TRUE, pamc_load(handle, "fixture"));
		finish(&handle, PAM_BPC_TRUE, fds);
	}
}

int
main(int argc, char **argv)
{
	ASSERT_EQ(2, argc);
	pamc_test_run(argv[1], test_start_allocations);
	pamc_test_run(argv[1], test_disable_allocations);
	pamc_test_run(argv[1], test_load_allocations);
	pamc_test_run(argv[1], test_launch_failures);
	return 0;
}
