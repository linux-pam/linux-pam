/*
 * Deterministic binary-prompt agent for libpamc tests.  No command-line or
 * environment configuration is used: libpamc supplies neither to agents.
 *
 * SELECT payloads are "<agent-id>/<mode>", without a terminating NUL.
 * echo/exit-failure/exit-signal acknowledge selection with an empty OK packet.
 * identity replies with a variant octet and a four-octet big-endian PID,
 * distinguishing search-path choices and reused processes, respectively.
 * Subsequent OK/DONE packets are echoed.  Further SELECT packets are allowed.
 * EOF exits successfully, unsuccessfully, or by SIGTERM according to the mode.
 * More scenarios can be added here without depending on external programs.
 */

#include "test_assert.h"

#include <errno.h>
#include <stdint.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include <security/pam_client.h>

/* Build variants distinguish search-path precedence without argv or env. */
#ifndef PAMC_TEST_VARIANT
# define PAMC_TEST_VARIANT 0
#endif

/* Independent wire framing: a big-endian uint32 length and a control octet. */
/*
 * A small fixture-only limit keeps accidental malformed requests bounded;
 * it is not a restriction imposed on real libpamc agents.
 */
enum { HEADER_BYTES = 5, MAX_PACKET_BYTES = 4096 };

/* EOF before a packet returns zero; EOF within a packet is an error. */
static int
read_packet(uint8_t *packet)
{
	size_t offset = 0;
	size_t size = HEADER_BYTES;

	while (offset < size) {
		ssize_t count = read(STDIN_FILENO, packet + offset, size - offset);

		if (count < 0 && errno == EINTR)
			continue;
		ASSERT_NE(-1, count);
		if (count == 0) {
			ASSERT_EQ(0U, offset);
			return 0;
		}
		offset += count;
		if (offset == HEADER_BYTES) {
			size = ((uint32_t) packet[0] << 24)
				| ((uint32_t) packet[1] << 16)
				| ((uint32_t) packet[2] << 8) | packet[3];
			ASSERT_LE((size_t) HEADER_BYTES, size);
			ASSERT_LE(size, (size_t) MAX_PACKET_BYTES);
		}
	}
	return 1;
}

static void
write_packet(const uint8_t *packet, size_t size)
{
	for (size_t offset = 0; offset < size;) {
		ssize_t count = write(STDOUT_FILENO, packet + offset, size - offset);

		if (count < 0 && errno == EINTR)
			continue;
		ASSERT_NE(-1, count);
		ASSERT_NE(0, count);
		offset += count;
	}
}

int
main(void)
{
	static const uint8_t selected[] = { 0, 0, 0, HEADER_BYTES, PAM_BPC_OK };
	uint8_t packet[MAX_PACKET_BYTES];
	int exit_status = EXIT_SUCCESS;
	int exit_signal = 0;
	int selected_once = 0;

	/* The smoke test sets this in the client, not in the agent. */
	ASSERT_EQ(NULL, getenv("PAMC_TEST_SENTINEL"));
	while (read_packet(packet)) {
		if (packet[HEADER_BYTES - 1] == PAM_BPC_SELECT) {
			const size_t size = PAM_BP_SIZE(packet);
			uint8_t *slash = memchr(packet + HEADER_BYTES, '/',
						size - HEADER_BYTES);

			ASSERT_NE(NULL, slash);
			const uint8_t *mode = slash + 1;
			const size_t length = packet + size - mode;
			/* Compare bounded strings; requests need not contain a NUL. */
#define MODE(name) (length == sizeof(name) - 1 \
			   && memcmp(mode, name, sizeof(name) - 1) == 0)
			exit_status = MODE("exit-failure") ? EXIT_FAILURE : EXIT_SUCCESS;
			exit_signal = MODE("exit-signal");
			if (MODE("identity")) {
				/* Five payload octets: variant, then the 32-bit PID. */
				uint8_t reply[] = { 0, 0, 0, HEADER_BYTES + 5,
					PAM_BPC_OK, PAMC_TEST_VARIANT, 0, 0, 0, 0 };
				uint32_t pid = getpid();

				for (size_t i = 0; i < 4; ++i)
					reply[HEADER_BYTES + 1 + i] = pid >> (24 - 8 * i);
				write_packet(reply, sizeof(reply));
			} else {
				ASSERT_NE(0, MODE("echo") || MODE("exit-failure")
					  || MODE("exit-signal"));
				write_packet(selected, sizeof(selected));
			}
#undef MODE
			selected_once = 1;
			continue;
		}
		ASSERT_EQ(1, selected_once);
		ASSERT_NE(0, packet[HEADER_BYTES - 1] == PAM_BPC_OK
			  || packet[HEADER_BYTES - 1] == PAM_BPC_DONE);
		write_packet(packet, PAM_BP_SIZE(packet));
	}
	/* Explicit loading without a conversation is also a valid lifecycle. */
	if (exit_signal) {
		ASSERT_NE(SIG_ERR, signal(SIGTERM, SIG_DFL));
		ASSERT_EQ(0, raise(SIGTERM));
		abort();
	}
	return exit_status;
}
