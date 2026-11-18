/*
 * Deterministic binary-prompt agent for libpamc tests.  No command-line or
 * environment configuration is used: libpamc supplies neither to agents.
 *
 * The first SELECT payload is "fixture/echo" or "fixture/exit-failure",
 * without a terminating NUL on the wire.  Both modes acknowledge selection
 * with an empty OK packet, then echo subsequent OK/DONE payloads and controls.
 * At clean EOF they exit successfully or unsuccessfully, respectively.
 * More scenarios can be added here without depending on external programs.
 */

#include "test_assert.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <security/pam_client.h>

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
	static const char echo[] = "fixture/echo";
	static const char failure[] = "fixture/exit-failure";
	static const uint8_t selected[] = { 0, 0, 0, HEADER_BYTES, PAM_BPC_OK };
	uint8_t packet[MAX_PACKET_BYTES];
	int exit_status;

	/* The smoke test sets this in the client, not in the agent. */
	ASSERT_EQ(NULL, getenv("PAMC_TEST_SENTINEL"));
	ASSERT_EQ(1, read_packet(packet));
	ASSERT_EQ(PAM_BPC_SELECT, packet[HEADER_BYTES - 1]);
	const size_t size = PAM_BP_SIZE(packet);
	if (size == HEADER_BYTES + sizeof(echo) - 1
	    && memcmp(packet + HEADER_BYTES, echo, sizeof(echo) - 1) == 0)
		exit_status = EXIT_SUCCESS;
	else {
		ASSERT_EQ(HEADER_BYTES + sizeof(failure) - 1, size);
		ASSERT_EQ(0, memcmp(packet + HEADER_BYTES, failure,
				    sizeof(failure) - 1));
		exit_status = EXIT_FAILURE;
	}
	write_packet(selected, sizeof(selected));
	while (read_packet(packet)) {
		ASSERT_NE(0, packet[HEADER_BYTES - 1] == PAM_BPC_OK
			  || packet[HEADER_BYTES - 1] == PAM_BPC_DONE);
		write_packet(packet, PAM_BP_SIZE(packet));
	}
	return exit_status;
}
