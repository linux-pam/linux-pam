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
#include <sys/resource.h>
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
free_list(char **agents)
{
	static const char *const expected[] = { "alpha", "fixture", "zeta" };
	ASSERT_NE(NULL, agents);
	for (size_t i = 0; i < sizeof(expected) / sizeof(expected[0]); ++i) {
		ASSERT_NE(NULL, agents[i]);
		ASSERT_EQ(0, strcmp(expected[i], agents[i]));
		pamc_fault_free(agents[i]);
	}
	ASSERT_EQ(NULL, agents[sizeof(expected) / sizeof(expected[0])]);
	pamc_fault_free(agents);
}

static void
test_list_allocations(void)
{
	pamc_test_case("pamc_list_agents: allocation profile");
	const char *dir = getenv("PAMC_AGENT_PATH");
	char helper[PATH_MAX], alias[PATH_MAX];
	static const char *const names[] = { "alpha", "zeta" };

	ASSERT_LT(snprintf(helper, sizeof(helper), "%s/fixture", dir),
		  (int) sizeof(helper));
	for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
		ASSERT_LT(snprintf(alias, sizeof(alias), "%s/%s", dir, names[i]),
			  (int) sizeof(alias));
		ASSERT_EQ(0, symlink(helper, alias));
	}
	size_t fds = fd_count();
	pamc_handle_t handle = start();
	size_t baseline = pamc_fault_live_blocks();
	reset();
	char **agents = pamc_list_agents(handle);
	size_t allocations = pamc_fault_calls(FAULT_ALLOC);
	free_list(agents);
	ASSERT_NE(0U, allocations);
	for (size_t nth = 1; nth <= allocations; ++nth) {
		pamc_test_case("pamc_list_agents: allocation %zu/%zu (injection)",
			       nth, allocations);
		pamc_fault_arm(FAULT_ALLOC, nth, 0);
		/* OOM must not masquerade as a successful but incomplete listing. */
		ASSERT_EQ(NULL, pamc_list_agents(handle));
		ASSERT_EQ(1U, pamc_fault_hits());
		ASSERT_EQ(baseline, pamc_fault_live_blocks());
		ASSERT_EQ(fds, fd_count());
		reset();
		pamc_test_case("pamc_list_agents: allocation %zu/%zu (recovery)",
			       nth, allocations);
		free_list(pamc_list_agents(handle));
	}
	finish(&handle, PAM_BPC_TRUE, fds);
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
		/* First dup2 installs stdout, second installs stdin. */
		{ "dup2 stdout", FAULT_DUP2, 1, 1 },
		{ "dup2 stdin", FAULT_DUP2, 2, 1 },
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

static void
test_interrupted_wait(void)
{
	pamc_test_case("pamc_end: waitpid call 1 interrupted, then retry");
	size_t fds = fd_count();
	pamc_handle_t handle = start();
	ASSERT_EQ(PAM_BPC_TRUE, pamc_load(handle, "fixture"));
	pamc_fault_arm(FAULT_WAIT_EINTR, 1, 0);
	finish(&handle, PAM_BPC_TRUE, fds);
	ASSERT_EQ(1U, pamc_fault_hits());
	ASSERT_EQ(2U, pamc_fault_calls(FAULT_WAIT_EINTR));
}

static void
test_pipe_relocation_failure(void)
{
	/* With 0/1 closed, the first pipe succeeds in those slots.  Limits of
	 * three/four descriptors prevent moving both ends above stderr, before
	 * a second pipe is even attempted.  Restore the limit before asserting
	 * results so diagnostics and sanitizer cleanup are not resource-limited.
	 */
	static const rlim_t limits[] = { 3, 4 };
	struct rlimit original;

	pamc_test_case("pamc_load: pipe relocation (setup)");
	ASSERT_EQ(0, getrlimit(RLIMIT_NOFILE, &original));
	ASSERT_EQ(0, close(STDIN_FILENO));
	ASSERT_EQ(0, close(STDOUT_FILENO));
	size_t fds = fd_count();
	for (size_t i = 0; i < sizeof(limits) / sizeof(limits[0]); ++i) {
		pamc_test_case("pamc_load: pipe relocation, descriptor limit %lu",
			       (unsigned long) limits[i]);
		reset();
		pamc_handle_t handle = start();
		size_t baseline = pamc_fault_live_blocks();
		struct rlimit low = original;
		ASSERT_LE(limits[i], original.rlim_max);
		low.rlim_cur = limits[i];
		ASSERT_EQ(0, setrlimit(RLIMIT_NOFILE, &low));
		int loaded = pamc_load(handle, "fixture");
		ASSERT_EQ(0, setrlimit(RLIMIT_NOFILE, &original));
		ASSERT_EQ(PAM_BPC_FALSE, loaded);
		ASSERT_EQ(1U, pamc_fault_calls(FAULT_PIPE));
		ASSERT_EQ(0U, pamc_fault_calls(FAULT_FORK));
		ASSERT_EQ(baseline, pamc_fault_live_blocks());
		ASSERT_EQ(fds, fd_count());
		finish(&handle, PAM_BPC_TRUE, fds);
	}
}

#ifdef NDEBUG
static void
test_reply_allocations(void)
{
	/* Debug builds intentionally terminate at PAM_BP_ASSERT on prompt OOM;
	 * tst-pam_bp checks that policy.  NDEBUG must handle failed reply and
	 * fallback allocations without returning TRUE with a NULL prompt.
	 */
	static const char selection[] = "fixture/echo";
	static const uint8_t payload[] = { 0x11, 0, 0x80, 0xff };
	size_t fds = fd_count();
	for (int persistent = 0; persistent <= 1; ++persistent) {
		pamc_test_case("pamc_converse: reply OOM, persistent=%d (setup)",
			       persistent);
		reset();
		pamc_handle_t handle = start();
		pamc_bp_t bp = NULL;
		PAM_BP_RENEW(&bp, PAM_BPC_SELECT, sizeof(selection) - 1);
		ASSERT_NE(NULL, bp);
		memcpy(PAM_BP_WDATA(bp), selection, sizeof(selection) - 1);
		ASSERT_EQ(PAM_BPC_TRUE, pamc_converse(handle, &bp));
		PAM_BP_RENEW(&bp, PAM_BPC_OK, sizeof(payload));
		ASSERT_NE(NULL, bp);
		memcpy(PAM_BP_WDATA(bp), payload, sizeof(payload));
		pamc_test_case("pamc_converse: reply OOM, persistent=%d (injection)",
			       persistent);
		pamc_fault_arm(FAULT_ALLOC, 1, persistent);
		ASSERT_EQ(persistent ? PAM_BPC_FALSE : PAM_BPC_TRUE,
			  pamc_converse(handle, &bp));
		ASSERT_EQ(persistent ? 2U : 1U, pamc_fault_hits());
		if (persistent)
			ASSERT_EQ(NULL, bp);
		else {
			ASSERT_NE(NULL, bp);
			ASSERT_EQ(PAM_BPC_FAIL, PAM_BP_RCONTROL(bp));
			ASSERT_EQ(0U, PAM_BP_LENGTH(bp));
		}
		reset();
		PAM_BP_RENEW(&bp, 0, 0);
		finish(&handle, PAM_BPC_TRUE, fds);
	}
}
#endif

int
main(int argc, char **argv)
{
	ASSERT_EQ(2, argc);
	pamc_test_run(argv[1], test_start_allocations);
	pamc_test_run(argv[1], test_disable_allocations);
	pamc_test_run(argv[1], test_load_allocations);
	pamc_test_run(argv[1], test_list_allocations);
	pamc_test_run(argv[1], test_launch_failures);
	pamc_test_run(argv[1], test_interrupted_wait);
	pamc_test_run(argv[1], test_pipe_relocation_failure);
#ifdef NDEBUG
	pamc_test_run(argv[1], test_reply_allocations);
#endif
	return 0;
}
