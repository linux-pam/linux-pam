/*
 * Only private libpamc objects use these hooks; the driver, supervisor, libc,
 * and real agent do not.  Count allocation API calls rather than allocations
 * internal to libc, so failures are deterministic across libc versions.
 * A fixed table tracks every live library allocation without allocating its
 * own storage.  Tests release caller-owned results through pamc_fault_free().
 */
#include "test_assert.h"
#include "tst-pamc-faults.h"

#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

static enum pamc_fault armed;
static size_t fail_at, calls[FAULT_COUNT], hits, format_calls;
static int repeat;
/* These bounded fixtures keep far fewer than 256 objects live at once. */
static void *blocks[256];
static struct pamc_child_fault *child_report;
static pid_t reporting_parent;

void
pamc_fault_watch_child(void)
{
	ASSERT_EQ(NULL, child_report);
	child_report = mmap(NULL, sizeof(*child_report), PROT_READ | PROT_WRITE,
			    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	ASSERT_NE(MAP_FAILED, (void *) child_report);
	reporting_parent = getpid();
}

struct pamc_child_fault
pamc_fault_child_report(void)
{
	ASSERT_NE(NULL, child_report);
	return *child_report;
}

void
pamc_fault_unwatch_child(void)
{
	ASSERT_NE(NULL, child_report);
	ASSERT_EQ(0, munmap(child_report, sizeof(*child_report)));
	child_report = NULL;
}

void
pamc_fault_arm(enum pamc_fault fault, size_t nth, int persistent)
{
	armed = fault;
	fail_at = nth;
	repeat = persistent;
	hits = 0;
	format_calls = 0;
	memset(calls, 0, sizeof(calls));
}

size_t
pamc_fault_calls(enum pamc_fault fault)
{
	return calls[fault];
}

size_t
pamc_fault_format_calls(void)
{
	return format_calls;
}

size_t
pamc_fault_hits(void)
{
	return hits;
}

size_t
pamc_fault_live_blocks(void)
{
	size_t count = 0;
	for (size_t i = 0; i < sizeof(blocks) / sizeof(blocks[0]); ++i)
		count += blocks[i] != NULL;
	return count;
}

static int
fail(enum pamc_fault fault, int error)
{
	++calls[fault];
	if (armed != fault || fail_at == 0 || calls[fault] < fail_at
	    || (!repeat && calls[fault] != fail_at))
		return 0;
	++hits;
	if (child_report != NULL && getpid() != reporting_parent) {
		child_report->injector_pid = getpid();
		child_report->fault = fault;
		child_report->nth = calls[fault];
		++child_report->hits;
	}
	errno = error;
	return 1;
}

static void *
record(void *ptr)
{
	ASSERT_NE(NULL, ptr); /* Real, unplanned OOM is a test infrastructure error. */
	for (size_t i = 0; i < sizeof(blocks) / sizeof(blocks[0]); ++i) {
		if (blocks[i] == NULL) {
			blocks[i] = ptr;
			return ptr;
		}
	}
	fputs("libpamc allocation tracking table exhausted\n", stderr);
	abort();
}

void *
pamc_fault_malloc(size_t size)
{
	return fail(FAULT_ALLOC, ENOMEM) ? NULL : record(malloc(size));
}

void *
pamc_fault_calloc(size_t nmemb, size_t size)
{
	return fail(FAULT_ALLOC, ENOMEM) ? NULL : record(calloc(nmemb, size));
}

char *
pamc_fault_strdup(const char *text)
{
	return fail(FAULT_ALLOC, ENOMEM) ? NULL : record(strdup(text));
}

int
pamc_fault_vasprintf(char **result, const char *format, va_list ap)
{
	++format_calls;
	if (fail(FAULT_ALLOC, ENOMEM)) {
		*result = NULL;
		return -1;
	}
	int rc = vasprintf(result, format, ap);
	ASSERT_NE(-1, rc);
	record(*result);
	return rc;
}

void
pamc_fault_free(void *ptr)
{
	if (ptr != NULL) {
		for (size_t i = 0; i < sizeof(blocks) / sizeof(blocks[0]); ++i) {
			if (blocks[i] == ptr) {
				blocks[i] = NULL;
				break;
			}
		}
	}
	/* Requests allocated by the driver are deliberately not tracked. */
	free(ptr);
}

int
pamc_fault_pipe(int fds[2])
{
	return fail(FAULT_PIPE, EMFILE) ? -1 : pipe(fds);
}

pid_t
pamc_fault_fork(void)
{
	pid_t pid = fail(FAULT_FORK, EAGAIN) ? -1 : fork();
	if (pid > 0 && child_report != NULL)
		child_report->expected_pid = pid;
	return pid;
}

int
pamc_fault_dup2(int oldfd, int newfd)
{
	return fail(FAULT_DUP2, EBADF) ? -1 : dup2(oldfd, newfd);
}

int
pamc_fault_execle(const char *path, const char *arg0, ...)
{
	/* libpamc supplies argv[0] followed by two NULL (void *) arguments:
	 * the argument sentinel and the deliberately empty environment.
	 */
	va_list ap;
	va_start(ap, arg0);
	void *end = va_arg(ap, void *);
	void *env = va_arg(ap, void *);
	va_end(ap);
	ASSERT_EQ(NULL, end);
	ASSERT_EQ(NULL, env);
	return fail(FAULT_EXEC, ENOEXEC) ? -1
		: execle(path, arg0, (char *) NULL, (char **) NULL);
}

pid_t
pamc_fault_waitpid(pid_t pid, int *status, int options)
{
	return fail(FAULT_WAIT_EINTR, EINTR) ? -1 : waitpid(pid, status, options);
}
