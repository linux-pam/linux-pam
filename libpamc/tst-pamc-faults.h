/* Test-only replacements, enabled solely in private libpamc builds. */
#ifndef TST_PAMC_FAULTS_H
#define TST_PAMC_FAULTS_H

#include <stdarg.h>
#include <stddef.h>
#include <sys/types.h>

enum pamc_fault {
	FAULT_NONE, FAULT_ALLOC, FAULT_PIPE, FAULT_FORK, FAULT_DUP2,
	FAULT_EXEC, FAULT_WAIT_EINTR, FAULT_COUNT
};
/* nth == 0 disables injection but still counts calls.  persistent fails every
 * matching call from nth onward; otherwise exactly one call fails.
 */
void pamc_fault_arm(enum pamc_fault fault, size_t nth, int persistent);
size_t pamc_fault_calls(enum pamc_fault fault);
/* Ensure fortified formatting did not silently bypass allocation injection. */
size_t pamc_fault_format_calls(void);
size_t pamc_fault_hits(void);
size_t pamc_fault_live_blocks(void);

/* Shared, out-of-band evidence survives the agent child's _exit() or exec.
 * Read it only after pamc_end() has waited for that child.
 */
struct pamc_child_fault {
	pid_t expected_pid, injector_pid;
	enum pamc_fault fault;
	size_t nth, hits;
};
void pamc_fault_watch_child(void);
struct pamc_child_fault pamc_fault_child_report(void);
void pamc_fault_unwatch_child(void);
void *pamc_fault_malloc(size_t size);
void *pamc_fault_calloc(size_t nmemb, size_t size);
char *pamc_fault_strdup(const char *text);
void pamc_fault_free(void *ptr);
int pamc_fault_vasprintf(char **result, const char *format, va_list ap)
	__attribute__((__format__(__printf__, 2, 0)));
int pamc_fault_pipe(int fds[2]);
pid_t pamc_fault_fork(void);
int pamc_fault_dup2(int oldfd, int newfd);
int pamc_fault_execle(const char *path, const char *arg0, ...);
pid_t pamc_fault_waitpid(pid_t pid, int *status, int options);

#endif
