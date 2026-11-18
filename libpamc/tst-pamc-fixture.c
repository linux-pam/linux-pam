/* Linux process supervision and temporary agent installation for tests. */
#include "test_assert.h"
#include "tst-pamc-fixture.h"

#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

/* Leave time for cleanup and diagnostics before Meson's outer timeout. */
enum { TEST_TIMEOUT_SECONDS = 10 };
static volatile sig_atomic_t worker_pid;
static volatile sig_atomic_t timed_out;

/* One worker writes short case labels; the supervisor reads after waiting. */
enum { CONTEXT_BYTES = 512 };
static char *test_context;

void
pamc_test_case(const char *format, ...)
{
	va_list ap;

	ASSERT_NE(NULL, test_context);
	va_start(ap, format);
	int length = vsnprintf(test_context, CONTEXT_BYTES, format, ap);
	va_end(ap);
	ASSERT_NE(0, length >= 0);
	ASSERT_LT(length, CONTEXT_BYTES);
}

static void
timeout_handler(int signum UNUSED)
{
	int saved_errno = errno;

	timed_out = 1;
	/* The group includes the agent.  Also cover a worker not yet grouped. */
	if (worker_pid > 0) {
		kill(-worker_pid, SIGKILL);
		kill(worker_pid, SIGKILL);
	}
	errno = saved_errno;
}

void
pamc_test_run(const char *helper, void (*test)(void))
{
	const char *tmpdir = getenv("TMPDIR");
	char directory[PATH_MAX];
	char agent[PATH_MAX];
	char resolved_helper[PATH_MAX];
	struct sigaction action = { .sa_handler = timeout_handler }, old_action;
	int old_subreaper, status = 0, group_result, group_errno;
	pid_t pid, waited;

	ASSERT_NE(NULL, realpath(helper, resolved_helper));
	test_context = mmap(NULL, CONTEXT_BYTES, PROT_READ | PROT_WRITE,
			    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	ASSERT_NE(MAP_FAILED, (void *) test_context);
	/* Adopt orphaned agents if the worker aborts before pamc_end(). */
	ASSERT_EQ(0, prctl(PR_GET_CHILD_SUBREAPER, &old_subreaper));
	ASSERT_EQ(0, prctl(PR_SET_CHILD_SUBREAPER, 1));
	sigemptyset(&action.sa_mask);
	ASSERT_EQ(0, sigaction(SIGALRM, &action, &old_action));
	ASSERT_EQ(0, fflush(NULL));
	if (tmpdir == NULL)
		tmpdir = "/tmp";
	ASSERT_LT(snprintf(directory, sizeof(directory), "%s/pamc-test-XXXXXX",
			   tmpdir), (int) sizeof(directory));
	ASSERT_NE(NULL, mkdtemp(directory));
	ASSERT_LT(snprintf(agent, sizeof(agent), "%s/fixture", directory),
		  (int) sizeof(agent));
	if (symlink(resolved_helper, agent) != 0) {
		int saved_errno = errno;

		rmdir(directory);
		errno = saved_errno;
		perror("symlink test agent");
		abort();
	}

	timed_out = 0;
	pid = fork();
	if (pid == 0) {
		/* Only the supervisor handles the deadline signal. */
		ASSERT_EQ(0, sigaction(SIGALRM, &old_action, NULL));
		ASSERT_EQ(0, setpgid(0, 0));
		ASSERT_EQ(0, setenv("PAMC_AGENT_PATH", directory, 1));
		ASSERT_EQ(0, setenv("PAMC_TEST_SENTINEL", "client-only", 1));
		test();
		exit(EXIT_SUCCESS);
	}
	if (pid < 0) {
		int saved_errno = errno;

		unlink(agent);
		rmdir(directory);
		errno = saved_errno;
		perror("fork test worker");
		abort();
	}
	worker_pid = pid;
	/* Both sides set the group so the deadline cannot race worker startup. */
	group_result = setpgid(pid, pid);
	group_errno = errno;
	ASSERT_EQ(0U, alarm(TEST_TIMEOUT_SECONDS));
	do {
		waited = waitpid(pid, &status, 0);
	} while (waited == -1 && errno == EINTR);
	alarm(0);
	kill(-pid, SIGKILL);
	/* Reap adopted agents; normally pamc_end() has already reaped them. */
	int leftovers = 0;
	pid_t descendant;
	do {
		descendant = waitpid(-1, NULL, 0);
		if (descendant > 0)
			++leftovers;
	} while (descendant > 0 || (descendant == -1 && errno == EINTR));
	const int reap_errno = errno;

	/* Cleanup happens before assertions about the worker's outcome. */
	ASSERT_EQ(0, unlink(agent));
	ASSERT_EQ(0, rmdir(directory));
	if (waited != pid || timed_out || !WIFEXITED(status)
	    || WEXITSTATUS(status) != EXIT_SUCCESS || leftovers
	    || reap_errno != ECHILD
	    || (group_result != 0 && group_errno != ESRCH)) {
		if (test_context[0])
			fprintf(stderr, "Failing test case: %s\n", test_context);
	}
	ASSERT_EQ(0, munmap(test_context, CONTEXT_BYTES));
	test_context = NULL;
	ASSERT_EQ(0, sigaction(SIGALRM, &old_action, NULL));
	ASSERT_EQ(0, prctl(PR_SET_CHILD_SUBREAPER, old_subreaper));
	ASSERT_NE(0, group_result == 0 || group_errno == ESRCH);
	ASSERT_EQ(pid, waited);
	ASSERT_EQ(ECHILD, reap_errno);
	ASSERT_EQ(0, timed_out);
	ASSERT_NE(0, WIFEXITED(status));
	ASSERT_EQ(EXIT_SUCCESS, WEXITSTATUS(status));
	ASSERT_EQ(0, leftovers);
}
