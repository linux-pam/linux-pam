/*
 * Conversations with the real pipe-based fixture.  A second target runs the
 * same cases with a test copy of pamc_converse.c plus deterministic I/O hooks.
 * Unsupported input/replies return TRUE and a FAIL packet; transport EOF
 * returns FALSE and clears the prompt.  Neither outcome may retain the request.
 */
#include "test_assert.h"
#include "tst-pamc-fixture.h"

#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <security/pam_client.h>
#ifdef PAMC_TEST_IO
# include "tst-pamc-io.h"
#endif

static pamc_bp_t
request(uint8_t control, const void *data, size_t length)
{
	pamc_bp_t bp = NULL;

	PAM_BP_RENEW(&bp, control, length);
	ASSERT_NE(NULL, bp);
	if (length)
		memcpy(PAM_BP_WDATA(bp), data, length);
	return bp;
}

static pamc_bp_t
selection(const char *mode)
{
	char text[128];

	ASSERT_LT(snprintf(text, sizeof(text), "fixture/%s", mode),
		  (int) sizeof(text));
	return request(PAM_BPC_SELECT, text, strlen(text));
}

static void
check_fail(pamc_bp_t bp)
{
	ASSERT_NE(NULL, bp);
	ASSERT_EQ(PAM_BPC_FAIL, PAM_BP_RCONTROL(bp));
	ASSERT_EQ(PAM_BP_MIN_SIZE, PAM_BP_SIZE(bp));
	ASSERT_EQ(0, PAM_BP_RDATA(bp)[0]);
}

static void
test_invalid_arguments(void)
{
	pamc_test_case("pamc_converse: invalid arguments");
	pamc_handle_t handle = pamc_start();
	pamc_bp_t bp = request(PAM_BPC_OK, NULL, 0);

	ASSERT_NE(NULL, handle);
	ASSERT_EQ(PAM_BPC_FALSE, pamc_converse(NULL, &bp));
	ASSERT_EQ(NULL, bp);
	ASSERT_EQ(PAM_BPC_FALSE, pamc_converse(handle, &bp));
	ASSERT_EQ(NULL, bp);
	ASSERT_EQ(PAM_BPC_FALSE, pamc_converse(handle, NULL));
	ASSERT_EQ(PAM_BPC_FALSE, pamc_converse(NULL, NULL));
	ASSERT_EQ(PAM_BPC_TRUE, pamc_end(&handle));
}

static void
test_unsupported_requests(void)
{
	pamc_test_case("pamc_converse: continuation without a selected agent");
	static const uint8_t invalid_controls[] = {
		0, PAM_BPC_FAIL + 1, /* Just outside the legal control range. */
		PAM_BPC_GETENV, PAM_BPC_PUTENV, PAM_BPC_TEXT, PAM_BPC_ERROR,
		PAM_BPC_PROMPT, PAM_BPC_PASS, UINT8_MAX
	};
	static const char *const invalid_selections[] = {
		"", "fixture", "/echo", "bad!id/echo", "not_installed/echo"
	};
	pamc_handle_t handle = pamc_start();
	ASSERT_NE(NULL, handle);
	/* A continuation with no current agent is unsupported, not EOF. */
	pamc_bp_t bp = request(PAM_BPC_OK, NULL, 0);
	ASSERT_EQ(PAM_BPC_TRUE, pamc_converse(handle, &bp));
	check_fail(bp);
	PAM_BP_RENEW(&bp, 0, 0);
	for (size_t i = 0; i < sizeof(invalid_controls); ++i) {
		pamc_test_case("pamc_converse: unsupported input control %#x",
			       (unsigned int) invalid_controls[i]);
		/* RENEW treats control zero as deletion, so set it after allocation. */
		bp = request(PAM_BPC_OK, NULL, 0);
		PAM_BP_WCONTROL(bp) = invalid_controls[i];
		ASSERT_EQ(PAM_BPC_TRUE, pamc_converse(handle, &bp));
		check_fail(bp);
		PAM_BP_RENEW(&bp, 0, 0);
	}
	const size_t count = sizeof(invalid_selections)
		/ sizeof(invalid_selections[0]);
	for (size_t i = 0; i < count; ++i) {
		const char *text = invalid_selections[i];
		pamc_test_case("pamc_converse: invalid selection '%s'", text);
		bp = request(PAM_BPC_SELECT, text, strlen(text));
		ASSERT_EQ(PAM_BPC_TRUE, pamc_converse(handle, &bp));
		check_fail(bp);
		PAM_BP_RENEW(&bp, 0, 0);
	}
	/* Allocate a complete header, but advertise each too-small wire size. */
	for (uint8_t size = 0; size < PAM_BP_MIN_SIZE; ++size) {
		pamc_test_case("pamc_converse: request wire size %u",
			       (unsigned int) size);
		bp = request(PAM_BPC_OK, NULL, 0);
		uint8_t *bytes = (uint8_t *) bp;
		memset(bytes, 0, sizeof(uint32_t));
		bytes[sizeof(uint32_t) - 1] = size;
		ASSERT_EQ(PAM_BPC_TRUE, pamc_converse(handle, &bp));
		check_fail(bp);
		PAM_BP_RENEW(&bp, 0, 0);
	}
	ASSERT_EQ(PAM_BPC_TRUE, pamc_end(&handle));
}

static void
test_replies(void)
{
	static const struct {
		const char *mode;
		int result;
		uint8_t control;
	} cases[] = {
		{ "eof", PAM_BPC_FALSE, 0 },
		{ "truncated-header", PAM_BPC_FALSE, 0 },
		{ "truncated-body", PAM_BPC_FALSE, 0 },
		{ "zero-control", PAM_BPC_TRUE, PAM_BPC_FAIL },
		{ "client-request", PAM_BPC_TRUE, PAM_BPC_TEXT }
	};
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
		pamc_test_case("pamc_converse: reply mode '%s'", cases[i].mode);
		pamc_handle_t handle = pamc_start();
		pamc_bp_t bp = selection(cases[i].mode);
		ASSERT_NE(NULL, handle);
		ASSERT_EQ(cases[i].result, pamc_converse(handle, &bp));
		if (cases[i].result == PAM_BPC_FALSE)
			ASSERT_EQ(NULL, bp);
		else if (cases[i].control == PAM_BPC_FAIL)
			check_fail(bp);
		else {
			static const uint8_t expected[] = { 0x11, 0, 0x80 };
			ASSERT_NE(NULL, bp);
			ASSERT_EQ(cases[i].control, PAM_BP_RCONTROL(bp));
			ASSERT_EQ(sizeof(expected), PAM_BP_LENGTH(bp));
			ASSERT_EQ(0, memcmp(expected, PAM_BP_RDATA(bp), sizeof(expected)));
			ASSERT_EQ(0, PAM_BP_RDATA(bp)[sizeof(expected)]);
			ASSERT_EQ(PAM_BPC_FALSE, PAM_BPC_FOR_CLIENT(bp));
		}
		PAM_BP_RENEW(&bp, 0, 0);
		ASSERT_EQ(PAM_BPC_TRUE, pamc_end(&handle));
	}
}

static void
test_reply_sizes(void)
{
	static const uint32_t sizes[] = {
		0, 1, 2, 3, 4, /* Every size shorter than the five-octet header. */
		5, PAM_BP_MAX_LENGTH, /* Minimum and maximum accepted wire sizes. */
		PAM_BP_MAX_LENGTH + 1, UINT32_MAX /* Reject without reading a body. */
	};
	for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); ++i) {
		pamc_test_case("pamc_converse: reply wire size %lu",
			       (unsigned long) sizes[i]);
		char mode[64];
		ASSERT_LT(snprintf(mode, sizeof(mode), "size/%lu", (unsigned long) sizes[i]),
			  (int) sizeof(mode));
		pamc_handle_t handle = pamc_start();
		pamc_bp_t bp = selection(mode);
		ASSERT_NE(NULL, handle);
		ASSERT_EQ(PAM_BPC_TRUE, pamc_converse(handle, &bp));
		if (sizes[i] < PAM_BP_MIN_SIZE || sizes[i] > PAM_BP_MAX_LENGTH)
			check_fail(bp);
		else {
			ASSERT_NE(NULL, bp);
			ASSERT_EQ(PAM_BPC_OK, PAM_BP_RCONTROL(bp));
			ASSERT_EQ(sizes[i], PAM_BP_SIZE(bp));
			for (size_t j = 0; j < PAM_BP_LENGTH(bp); ++j)
				ASSERT_EQ(0xa5, PAM_BP_RDATA(bp)[j]);
			ASSERT_EQ(0, PAM_BP_RDATA(bp)[PAM_BP_LENGTH(bp)]);
		}
		PAM_BP_RENEW(&bp, 0, 0);
		ASSERT_EQ(PAM_BPC_TRUE, pamc_end(&handle));
	}
}

static void
test_broken_pipe(void)
{
	pamc_test_case("pamc_converse: write after close-input acknowledgement");
	struct sigaction ignore = { .sa_handler = SIG_IGN }, old;
	pamc_handle_t handle = pamc_start();
	pamc_bp_t bp = selection("close-input");

	ASSERT_NE(NULL, handle);
	sigemptyset(&ignore.sa_mask);
	ASSERT_EQ(0, sigaction(SIGPIPE, &ignore, &old));
	ASSERT_EQ(PAM_BPC_TRUE, pamc_converse(handle, &bp));
	ASSERT_NE(NULL, bp);
	ASSERT_EQ(PAM_BPC_OK, PAM_BP_RCONTROL(bp));
	/* The ACK proves the agent already closed its input: no exit race. */
	PAM_BP_RENEW(&bp, PAM_BPC_OK, 0);
	ASSERT_EQ(PAM_BPC_TRUE, pamc_converse(handle, &bp));
	check_fail(bp);
	PAM_BP_RENEW(&bp, 0, 0);
	ASSERT_EQ(PAM_BPC_TRUE, pamc_end(&handle));
	ASSERT_EQ(0, sigaction(SIGPIPE, &old, NULL));
}

#ifdef PAMC_TEST_IO
static void
test_short_io(void)
{
	pamc_test_case("pamc_converse: one-byte transfers and "
		       "write/header/body EINTR");
	static const uint8_t payload[] = { 0x11, 0, 0x80, 0xff };
	pamc_handle_t handle = pamc_start();
	pamc_bp_t bp = selection("fragment");

	ASSERT_NE(NULL, handle);
	ASSERT_EQ(PAM_BPC_TRUE, pamc_converse(handle, &bp));
	PAM_BP_RENEW(&bp, PAM_BPC_OK, sizeof(payload));
	memcpy(PAM_BP_WDATA(bp), payload, sizeof(payload));
	pamc_test_io = (struct pamc_test_io) {
		.read_limit = 1, .write_limit = 1,
		.interrupt_header = 1, .interrupt_body = 1, .interrupt_write = 1
	};
	ASSERT_EQ(PAM_BPC_TRUE, pamc_converse(handle, &bp));
	ASSERT_NE(NULL, bp);
	ASSERT_EQ(PAM_BPC_OK, PAM_BP_RCONTROL(bp));
	ASSERT_EQ(sizeof(payload), PAM_BP_LENGTH(bp));
	ASSERT_EQ(0, memcmp(payload, PAM_BP_RDATA(bp), sizeof(payload)));
	ASSERT_EQ(0, PAM_BP_RDATA(bp)[sizeof(payload)]);
	/* Exactly one EINTR in each of write, header read, and body read. */
	ASSERT_EQ(3U, pamc_test_io.interruptions);
	ASSERT_EQ(PAM_BP_MIN_SIZE + sizeof(payload), pamc_test_io.read_bytes);
	ASSERT_EQ(PAM_BP_MIN_SIZE + sizeof(payload), pamc_test_io.write_bytes);
	PAM_BP_RENEW(&bp, 0, 0);
	ASSERT_EQ(PAM_BPC_TRUE, pamc_end(&handle));
}

static void
test_io_errors(void)
{
	static const struct {
		enum pamc_test_fault fault;
		const char *name;
	} faults[] = {
		{ IO_READ_ERROR, "header read EIO" },
		{ IO_READ_BODY_ERROR, "body read EIO" },
		{ IO_WRITE_ERROR, "write EIO" }
	};
	for (size_t i = 0; i < sizeof(faults) / sizeof(faults[0]); ++i) {
		pamc_test_case("pamc_converse: %s", faults[i].name);
		pamc_handle_t handle = pamc_start();
		/* EOF mode never writes a reply, avoiding SIGPIPE on early failures.
		 * For a body read failure, client-request writes its complete small
		 * packet atomically before the client can finish reading the header.
		 */
		pamc_bp_t bp = selection(faults[i].fault == IO_READ_BODY_ERROR
					? "client-request" : "eof");
		ASSERT_NE(NULL, handle);
		pamc_test_io = (struct pamc_test_io) { .fault = faults[i].fault };
		ASSERT_EQ(PAM_BPC_TRUE, pamc_converse(handle, &bp));
		check_fail(bp);
		ASSERT_EQ((enum pamc_test_fault) IO_NORMAL, pamc_test_io.fault);
		PAM_BP_RENEW(&bp, 0, 0);
		ASSERT_EQ(PAM_BPC_TRUE, pamc_end(&handle));
	}
}

static void
test_partial_write_errors(void)
{
	static const uint8_t payload[] = { 0x11, 0, 0x80, 0xff };
	static const struct {
		const char *mode;
		size_t prefix;
	} cases[] = {
		{ "short-request-header", 1 },
		{ "short-request-body", PAM_BP_MIN_SIZE + 1 }
	};

	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
		pamc_test_case("pamc_converse: EIO after %zu request bytes (%s)",
			       cases[i].prefix, cases[i].mode);
		pamc_handle_t handle = pamc_start();
		pamc_bp_t bp = selection(cases[i].mode);
		ASSERT_NE(NULL, handle);
		ASSERT_EQ(PAM_BPC_TRUE, pamc_converse(handle, &bp));
		ASSERT_NE(NULL, bp);
		ASSERT_EQ(PAM_BPC_OK, PAM_BP_RCONTROL(bp));
		PAM_BP_RENEW(&bp, PAM_BPC_OK, sizeof(payload));
		ASSERT_NE(NULL, bp);
		memcpy(PAM_BP_WDATA(bp), payload, sizeof(payload));
		/* One-byte writes reach the selected cut point exactly.  The helper
		 * independently checks the prefix received before end() closes input.
		 */
		pamc_test_io = (struct pamc_test_io) {
			.write_limit = 1, .write_error_after = cases[i].prefix,
			.fault = IO_WRITE_ERROR
		};
		ASSERT_EQ(PAM_BPC_TRUE, pamc_converse(handle, &bp));
		check_fail(bp);
		ASSERT_EQ((enum pamc_test_fault) IO_NORMAL, pamc_test_io.fault);
		ASSERT_EQ(cases[i].prefix, pamc_test_io.write_bytes);
		ASSERT_EQ(0U, pamc_test_io.read_bytes);
		PAM_BP_RENEW(&bp, 0, 0);
		pamc_test_io = (struct pamc_test_io) { 0 };
		ASSERT_EQ(PAM_BPC_TRUE, pamc_end(&handle));
	}
}
#endif

int
main(int argc, char **argv)
{
	ASSERT_EQ(2, argc);
	pamc_test_run(argv[1], test_invalid_arguments);
	pamc_test_run(argv[1], test_unsupported_requests);
	pamc_test_run(argv[1], test_replies);
	pamc_test_run(argv[1], test_reply_sizes);
	pamc_test_run(argv[1], test_broken_pipe);
#ifdef PAMC_TEST_IO
	pamc_test_run(argv[1], test_short_io);
	pamc_test_run(argv[1], test_io_errors);
	pamc_test_run(argv[1], test_partial_write_errors);
#endif
	return 0;
}
