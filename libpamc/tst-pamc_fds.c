/* Exercise real descriptor collisions, not injected dup2 return values. */
#include "test_assert.h"
#include "tst-pamc-fixture.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <security/pam_client.h>

/* One bit per standard descriptor; the supervisor retains its own originals. */
static unsigned int closed_fds;

static void
check_closed_fds(void)
{
	for (int fd = STDIN_FILENO; fd <= STDERR_FILENO; ++fd) {
		if (closed_fds & (1U << fd)) {
			errno = 0;
			ASSERT_EQ(-1, fcntl(fd, F_GETFD));
			ASSERT_EQ(EBADF, errno);
		}
	}
}

static void
test_closed_fds(void)
{
	static const char selection[] = "fixture/echo";
	static const uint8_t payload[] = { 0x11, 0, 0x80, 0xff };
	pamc_bp_t bp = NULL;

	pamc_test_case("closed descriptors: stdin=%d stdout=%d stderr=%d",
		       !!(closed_fds & (1U << STDIN_FILENO)),
		       !!(closed_fds & (1U << STDOUT_FILENO)),
		       !!(closed_fds & (1U << STDERR_FILENO)));
	for (int fd = STDIN_FILENO; fd <= STDERR_FILENO; ++fd)
		if (closed_fds & (1U << fd))
			ASSERT_EQ(0, close(fd));

	pamc_handle_t handle = pamc_start();
	ASSERT_NE(NULL, handle);
	PAM_BP_RENEW(&bp, PAM_BPC_SELECT, sizeof(selection) - 1);
	ASSERT_NE(NULL, bp);
	memcpy(PAM_BP_WDATA(bp), selection, sizeof(selection) - 1);
	ASSERT_EQ(PAM_BPC_TRUE, pamc_converse(handle, &bp));
	ASSERT_NE(NULL, bp);
	ASSERT_EQ(PAM_BPC_OK, PAM_BP_RCONTROL(bp));
	ASSERT_EQ(0U, PAM_BP_LENGTH(bp));
	/* Active agent pipes must not occupy the caller's closed stdio slots. */
	check_closed_fds();

	PAM_BP_RENEW(&bp, PAM_BPC_OK, sizeof(payload));
	ASSERT_NE(NULL, bp);
	memcpy(PAM_BP_WDATA(bp), payload, sizeof(payload));
	ASSERT_EQ(PAM_BPC_TRUE, pamc_converse(handle, &bp));
	ASSERT_NE(NULL, bp);
	ASSERT_EQ(PAM_BPC_OK, PAM_BP_RCONTROL(bp));
	ASSERT_EQ(sizeof(payload), PAM_BP_LENGTH(bp));
	ASSERT_EQ(0, memcmp(payload, PAM_BP_RDATA(bp), sizeof(payload)));
	ASSERT_EQ(0, PAM_BP_RDATA(bp)[sizeof(payload)]);
	PAM_BP_RENEW(&bp, 0, 0);
	ASSERT_EQ(PAM_BPC_TRUE, pamc_end(&handle));
	ASSERT_EQ(NULL, handle);
	check_closed_fds();
}

int
main(int argc, char **argv)
{
	ASSERT_EQ(2, argc);
	/* Every nonempty combination of closed stdin, stdout, and stderr. */
	for (closed_fds = 1; closed_fds < (1U << (STDERR_FILENO + 1)); ++closed_fds)
		pamc_test_run(argv[1], test_closed_fds);
	return 0;
}
