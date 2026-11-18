/*
 * Header-only tests for the binary-prompt macros in pam_client.h.
 *
 * The calloc/free hooks track one live prompt, inject allocation failures,
 * and inspect its bytes BEFORE freeing it to verify scrubbing.  Sentinel
 * bytes around copy destinations detect writes outside the requested range.
 * Wire-format expectations are independent of the macros being tested.
 *
 * Meson builds this file with and without NDEBUG.  In debug builds each
 * invalid operation runs in a child process: only the expected assertion
 * message and the assertion hook's exit status count as success, not an
 * arbitrary failure or crash.  NDEBUG builds leave PAM_BP_ASSERT unchanged
 * and never attempt invalid copies.  The test's own ASSERT_* checks remain
 * active in both builds.
 */

#include "test_assert.h"

#include <stdint.h>
#include <string.h>

#ifndef NDEBUG
# include <errno.h>
# include <sys/wait.h>
# include <unistd.h>
#endif

/*
 * Protocol constants, not aliases for the implementation's PAM_BP_* macros:
 * four big-endian length octets followed by one control octet.
 */
#define WIRE_LENGTH_BYTES 4U
#define WIRE_HEADER_BYTES (WIRE_LENGTH_BYTES + 1U)

/* Arbitrary nonzero marker, absent from data[], for untouched bytes. */
#define SENTINEL 0xa5

/* Only one prompt is live at a time, so every free can check its scrubbing. */
static void *allocation;
static size_t allocation_size;
static size_t calloc_calls;
static size_t free_calls;
static int fail_allocation;

static void *
test_calloc(size_t nmemb, size_t size)
{
	ASSERT_EQ(NULL, allocation);
	++calloc_calls;
	if (fail_allocation)
		return NULL;

	allocation = calloc(nmemb, size);
	ASSERT_NE(NULL, allocation);
	allocation_size = nmemb * size;
	return allocation;
}

static void
test_free(void *ptr)
{
	const uint8_t *bytes = ptr;

	ASSERT_NE(NULL, ptr);
	ASSERT_EQ(allocation, ptr);
	for (size_t i = 0; i < allocation_size; ++i)
		ASSERT_EQ(0, bytes[i]);
	++free_calls;
	free(ptr);
	allocation = NULL;
	allocation_size = 0;
}

#ifndef NDEBUG
static const char *expected_assertion;

/*
 * Arbitrary status distinct from ordinary success/failure (0/1).  The parent
 * also rejects signal termination; merely crashing must not pass a case.
 */
enum { EXPECTED_ASSERTION_EXIT = 42 };

/* Stop before an invalid operation, without changing NDEBUG semantics. */
static void __attribute__((__noreturn__))
test_bp_assert(const char *message)
{
	ASSERT_NE(NULL, expected_assertion);
	ASSERT_EQ(0, strcmp(expected_assertion, message));
	/* A failed replacement must already have freed the old prompt. */
	if (strcmp(message, "out of memory for binary prompt") == 0)
		ASSERT_EQ(NULL, allocation);
	_exit(EXPECTED_ASSERTION_EXIT);
}

# define PAM_BP_ASSERT(message) test_bp_assert(message)
#endif

#define PAM_BP_CALLOC test_calloc
#define PAM_BP_FREE test_free
#include <security/pam_client.h>

/*
 * An embedded NUL prevents string operations from being an adequate copy;
 * 0x80/0xff exercise high-bit bytes.  The other distinct, nonzero bytes make
 * misplaced copies and the pre-#1051 overlong copy observable.
 */
static const uint8_t data[] = {
	0x11, 0x00, 0x80, 0x22, 0x33, 0xff, 0x44, 0x55
};

static void
check_prompt(pamc_bp_t bp, uint8_t control, size_t length)
{
	const uint8_t *bytes = (const uint8_t *) bp;
	const uint32_t size = WIRE_HEADER_BYTES + length;

	ASSERT_NE(NULL, bp);
	ASSERT_EQ(allocation, (void *) bp);
	ASSERT_EQ(WIRE_HEADER_BYTES, PAM_BP_MIN_SIZE);
	ASSERT_EQ(WIRE_HEADER_BYTES, sizeof(*bp));
	/* The extra byte is a trailing NUL, not part of the wire size. */
	ASSERT_EQ(size + 1, allocation_size);
	for (size_t i = 0; i < WIRE_LENGTH_BYTES; ++i) {
		/* Each wire octet has eight bits, most significant octet first. */
		const unsigned int shift = 8 * (WIRE_LENGTH_BYTES - i - 1);
		ASSERT_EQ((size >> shift) & UINT8_MAX, bytes[i]);
	}
	ASSERT_EQ(size, PAM_BP_SIZE(bp));
	ASSERT_EQ(length, PAM_BP_LENGTH(bp));
	ASSERT_EQ(control, bytes[WIRE_LENGTH_BYTES]);
	ASSERT_EQ(control, PAM_BP_RCONTROL(bp));
	ASSERT_EQ(control, bp->control);
	ASSERT_EQ(bytes + WIRE_HEADER_BYTES, PAM_BP_RDATA(bp));
	ASSERT_EQ((uint8_t *) bp + WIRE_HEADER_BYTES, PAM_BP_WDATA(bp));
	ASSERT_EQ(0, PAM_BP_RDATA(bp)[length]);
}

static void
test_wire_format(void)
{
	/*
	 * Distinct length octets reveal byte-order errors; the high bit also
	 * exercises unsigned decoding.  No allocation of this large size is
	 * needed.  Skip a leading sentinel to read a header at a byte offset.
	 */
	static const uint8_t bytes[] = {
		SENTINEL, 0x81, 0x23, 0x45, 0x67, PAM_BPC_SELECT
	};
	const uint32_t wire_size = 0x81234567U;

	ASSERT_EQ(wire_size, PAM_BP_SIZE(bytes + 1));
	ASSERT_EQ(wire_size - WIRE_HEADER_BYTES, PAM_BP_LENGTH(bytes + 1));
	ASSERT_EQ(PAM_BPC_SELECT, PAM_BP_RCONTROL(bytes + 1));
}

static void
test_renew(void)
{
	static const size_t lengths[] = {
		0,                              /* Empty payload. */
		1,                              /* Smallest nonempty payload. */
		/* Subtract the header so TOTAL sizes cross length-octet boundaries. */
		0xff - WIRE_HEADER_BYTES,        /* Last one-octet wire size. */
		0x100 - WIRE_HEADER_BYTES,       /* Carry into the second octet. */
		0xffff - WIRE_HEADER_BYTES,      /* Last two-octet wire size. */
		0x10000 - WIRE_HEADER_BYTES,     /* Carry into the third octet. */
		PAM_BP_MAX_LENGTH               /* Advisory size, not a hard limit. */
	};
	const size_t count = sizeof(lengths) / sizeof(lengths[0]);
	const size_t old_calloc_calls = calloc_calls;
	const size_t old_free_calls = free_calls;
	pamc_bp_t bp = NULL;

	/* Grow through length-octet boundaries, scrubbing every old prompt. */
	for (size_t i = 0; i < count; ++i) {
		PAM_BP_RENEW(&bp, PAM_BPC_OK, lengths[i]);
		check_prompt(bp, PAM_BPC_OK, lengths[i]);
		ASSERT_EQ(old_calloc_calls + i + 1, calloc_calls);
		ASSERT_EQ(old_free_calls + i, free_calls);
		for (size_t j = 0; j <= lengths[i]; ++j)
			ASSERT_EQ(0, PAM_BP_RDATA(bp)[j]);
		/* Make scrubbing necessary before the next replacement/free. */
		memset(PAM_BP_WDATA(bp), SENTINEL, lengths[i]);
	}

	/* Shrinking must also scrub and free the previous payload. */
	PAM_BP_RENEW(&bp, PAM_BPC_DONE, 0);
	check_prompt(bp, PAM_BPC_DONE, 0);
	ASSERT_EQ(old_calloc_calls + count + 1, calloc_calls);
	ASSERT_EQ(old_free_calls + count, free_calls);

	/* Control zero deletes; even a nonzero data length must be ignored. */
	PAM_BP_RENEW(&bp, 0, 1);
	ASSERT_EQ(NULL, bp);
	ASSERT_EQ(NULL, allocation);
	ASSERT_EQ(old_calloc_calls + count + 1, calloc_calls);
	ASSERT_EQ(old_free_calls + count + 1, free_calls);

	PAM_BP_RENEW(&bp, 0, 0);
	ASSERT_EQ(NULL, bp);
	ASSERT_EQ(old_calloc_calls + count + 1, calloc_calls);
	ASSERT_EQ(old_free_calls + count + 1, free_calls);
}

static void
test_fill_ranges(void)
{
	static const struct {
		size_t offset;
		size_t length;
	} ranges[] = {
		{ 0, 0 },                       /* No write at the start. */
		{ sizeof(data), 0 },            /* No write exactly at the end. */
		{ 0, sizeof(data) },            /* Whole payload. */
		{ 0, 1 },                       /* First byte only. */
		{ sizeof(data) - 1, 1 },        /* Last byte only. */
		{ 2, 3 },                       /* Interior, sentinels on both sides. */
		{ sizeof(data) - 3, 3 }         /* Partial copy ending at the boundary. */
	};
	pamc_bp_t bp = NULL;
	uint8_t expected[sizeof(data)];

	PAM_BP_RENEW(&bp, PAM_BPC_SELECT, sizeof(data));
	ASSERT_NE(NULL, bp);
	for (size_t i = 0; i < sizeof(ranges) / sizeof(ranges[0]); ++i) {
		/*
		 * Every copy takes a prefix of data[]; the three-byte cases
		 * include its NUL and high-bit byte.  All other bytes must stay put.
		 */
		memset(expected, SENTINEL, sizeof(expected));
		memcpy(expected + ranges[i].offset, data, ranges[i].length);
		memset(PAM_BP_WDATA(bp), SENTINEL, sizeof(data));
		PAM_BP_FILL(bp, ranges[i].offset, ranges[i].length, data);
		check_prompt(bp, PAM_BPC_SELECT, sizeof(data));
		ASSERT_EQ(0, memcmp(expected, PAM_BP_RDATA(bp), sizeof(expected)));
	}
	PAM_BP_RENEW(&bp, 0, 0);

	PAM_BP_RENEW(&bp, PAM_BPC_OK, 0);
	PAM_BP_FILL(bp, 0, 0, data);
	check_prompt(bp, PAM_BPC_OK, 0);
	PAM_BP_RENEW(&bp, 0, 0);
}

/*
 * result[] has one leading guard byte, sizeof(data) bytes of copy space,
 * and one trailing guard byte.  Unused copy space must also stay untouched.
 */
static void
check_extracted(const uint8_t *result, size_t source_offset, size_t length)
{
	ASSERT_EQ(SENTINEL, result[0]);
	ASSERT_EQ(0, memcmp(result + 1, data + source_offset, length));
	for (size_t i = length + 1; i < sizeof(data) + 2; ++i)
		ASSERT_EQ(SENTINEL, result[i]);
}

static void
test_extract(void)
{
	pamc_bp_t prompt = NULL;
	const uint8_t *const_prompt;
	const size_t bp_length = 3; /* A proper subrange, not the whole payload. */
	uint8_t result[sizeof(data) + 2]; /* One guard byte on each side. */

	PAM_BP_RENEW(&prompt, PAM_BPC_DONE, sizeof(data));
	ASSERT_NE(NULL, prompt);
	memcpy(PAM_BP_WDATA(prompt), data, sizeof(data));
	const_prompt = (const uint8_t *) prompt;

	/* Extract through a const source; result + 1 preserves the first guard. */
	memset(result, SENTINEL, sizeof(result));
	PAM_BP_EXTRACT(const_prompt, 0, sizeof(data), result + 1);
	check_extracted(result, 0, sizeof(data));

	/*
	 * Interior slice, leaving bytes on both sides of the source range.
	 * Also exercise the caller names prompt and bp_length with extraction.
	 */
	memset(result, SENTINEL, sizeof(result));
	PAM_BP_EXTRACT(prompt, 2, bp_length, result + 1);
	check_extracted(result, 2, bp_length);

	/* Extract the last three bytes, ending exactly at the payload boundary. */
	memset(result, SENTINEL, sizeof(result));
	PAM_BP_EXTRACT(const_prompt, sizeof(data) - bp_length, bp_length,
		       result + 1);
	check_extracted(result, sizeof(data) - bp_length, bp_length);

	/* Zero-length extraction is valid at either end and changes no bytes. */
	memset(result, SENTINEL, sizeof(result));
	PAM_BP_EXTRACT(const_prompt, 0, 0, result + 1);
	check_extracted(result, 0, 0);
	PAM_BP_EXTRACT(const_prompt, sizeof(data), 0, result + 1);
	check_extracted(result, sizeof(data), 0);
	check_prompt(prompt, PAM_BPC_DONE, sizeof(data));
	ASSERT_EQ(0, memcmp(data, PAM_BP_RDATA(prompt), sizeof(data)));
	PAM_BP_RENEW(&prompt, 0, 0);

	PAM_BP_RENEW(&prompt, PAM_BPC_OK, 0);
	PAM_BP_EXTRACT(prompt, 0, 0, result + 1);
	check_extracted(result, 0, 0);
	check_prompt(prompt, PAM_BPC_OK, 0);
	PAM_BP_RENEW(&prompt, 0, 0);
}

static void
test_fill_bp_length_shadowing(void)
{
	/* Copy only data[0..2]; the rest of the new payload must remain zero. */
	static const uint8_t expected[] = {
		0x11, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	const size_t bp_length = 3; /* Prefix containing both NUL and a high bit. */
	pamc_bp_t bp = NULL;

	/*
	 * The caller's bp_length must not be shadowed by the macro's local
	 * payload length.  Keep the source as large as the payload so the
	 * pre-#1051 overlong copy stays in bounds and fails deterministically.
	 */
	PAM_BP_RENEW(&bp, PAM_BPC_OK, sizeof(data));
	ASSERT_NE(NULL, bp);
	PAM_BP_FILL(bp, 0, bp_length, data);
	check_prompt(bp, PAM_BPC_OK, sizeof(data));
	ASSERT_EQ(0, memcmp(PAM_BP_RDATA(bp), expected, sizeof(expected)));
	PAM_BP_RENEW(&bp, 0, 0);
}

static void
test_fill_prompt_shadowing(void)
{
	/* Two untouched bytes, data[0..2], then three untouched bytes. */
	static const uint8_t expected[] = {
		SENTINEL, SENTINEL, 0x11, 0x00, 0x80, SENTINEL, SENTINEL, SENTINEL
	};
	pamc_bp_t prompt = NULL;

	/*
	 * The name prompt is essential: before #1051, the macro's local
	 * shadowed it and initialized itself from an indeterminate pointer.
	 */
	PAM_BP_RENEW(&prompt, PAM_BPC_SELECT, sizeof(data));
	ASSERT_NE(NULL, prompt);
	memset(PAM_BP_WDATA(prompt), SENTINEL, sizeof(data));
	PAM_BP_FILL(prompt, 2, 3, data);
	check_prompt(prompt, PAM_BPC_SELECT, sizeof(data));
	ASSERT_EQ(0, memcmp(PAM_BP_RDATA(prompt), expected, sizeof(expected)));
	PAM_BP_RENEW(&prompt, 0, 0);
}

static void
test_controls(void)
{
	pamc_bp_t bp = NULL;

	PAM_BP_RENEW(&bp, PAM_BPC_OK, 0);
	ASSERT_NE(NULL, bp);
	/*
	 * Only the four server-facing controls are legal for client requests;
	 * all other octet values, including the agent-only controls, are not.
	 */
	for (unsigned int control = 0; control <= UINT8_MAX; ++control) {
		int expected;

		switch (control) {
		case PAM_BPC_OK:
		case PAM_BPC_SELECT:
		case PAM_BPC_DONE:
		case PAM_BPC_FAIL:
			expected = PAM_BPC_TRUE;
			break;
		default:
			expected = PAM_BPC_FALSE;
		}
		PAM_BP_WCONTROL(bp) = (uint8_t) control;
		check_prompt(bp, control, 0);
		ASSERT_EQ(expected, PAM_BPC_FOR_CLIENT(bp));
	}
	PAM_BP_RENEW(&bp, 0, 0);
}

#ifndef NDEBUG

enum assertion_case {
	RENEW_NULL,
	RENEW_OOM,
	RENEW_REPLACE_OOM,
	FILL_PAST_END,
	FILL_OFFSET_PAST_END,
	EXTRACT_PAST_END,
	EXTRACT_OFFSET_PAST_END,
	EXTRACT_NEGATIVE_OFFSET,
	EXTRACT_NEGATIVE_LENGTH
};

static void
run_assertion_case(enum assertion_case which)
{
	pamc_bp_t bp = NULL;
	pamc_bp_t *null_bp = NULL;
	uint8_t result[sizeof(data)];

	switch (which) {
	case RENEW_NULL:
		PAM_BP_RENEW(null_bp, PAM_BPC_OK, 0);
		return;
	case RENEW_OOM:
		fail_allocation = 1;
		PAM_BP_RENEW(&bp, PAM_BPC_OK, sizeof(data));
		return;
	default:
		break;
	}

	PAM_BP_RENEW(&bp, PAM_BPC_OK, sizeof(data));
	ASSERT_NE(NULL, bp);
	memset(PAM_BP_WDATA(bp), SENTINEL, sizeof(data));

	switch (which) {
	case RENEW_REPLACE_OOM:
		fail_allocation = 1;
		PAM_BP_RENEW(&bp, PAM_BPC_OK, sizeof(data));
		break;
	case FILL_PAST_END:
		/* Two bytes starting at the last byte overrun by one byte. */
		PAM_BP_FILL(bp, sizeof(data) - 1, 2, data);
		break;
	case FILL_OFFSET_PAST_END:
		/* Even a zero-length copy must not start beyond the payload. */
		PAM_BP_FILL(bp, sizeof(data) + 1, 0, data);
		break;
	case EXTRACT_PAST_END:
		/* Two bytes starting at the last byte overrun by one byte. */
		PAM_BP_EXTRACT(bp, sizeof(data) - 1, 2, result);
		break;
	case EXTRACT_OFFSET_PAST_END:
		PAM_BP_EXTRACT(bp, sizeof(data) + 1, 0, result);
		break;
	case EXTRACT_NEGATIVE_OFFSET:
		/* Sum zero isolates the negative-offset check from the upper bound. */
		PAM_BP_EXTRACT(bp, -1, 1, result);
		break;
	case EXTRACT_NEGATIVE_LENGTH:
		/* Sum zero isolates the negative-length check from the upper bound. */
		PAM_BP_EXTRACT(bp, 1, -1, result);
		break;
	default:
		abort();
	}
}

static void
test_assertions(void)
{
	static const struct {
		enum assertion_case which;
		const char *message;
	} cases[] = {
		{ RENEW_NULL, "programming error, invalid binary prompt pointer" },
		{ RENEW_OOM, "out of memory for binary prompt" },
		{ RENEW_REPLACE_OOM, "out of memory for binary prompt" },
		{ FILL_PAST_END, "attempt to write over end of prompt" },
		{ FILL_OFFSET_PAST_END, "attempt to write over end of prompt" },
		{ EXTRACT_PAST_END, "invalid extraction from prompt" },
		{ EXTRACT_OFFSET_PAST_END, "invalid extraction from prompt" },
		{ EXTRACT_NEGATIVE_OFFSET, "invalid extraction from prompt" },
		{ EXTRACT_NEGATIVE_LENGTH, "invalid extraction from prompt" }
	};

	ASSERT_EQ(NULL, allocation);
	ASSERT_EQ(0, fflush(NULL));
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
		pid_t pid = fork();
		pid_t waited;
		int status;

		ASSERT_NE(-1, pid);
		if (pid == 0) {
			expected_assertion = cases[i].message;
			run_assertion_case(cases[i].which);
			/* Returning means the expected assertion did not happen. */
			_exit(EXIT_SUCCESS);
		}
		do {
			waited = waitpid(pid, &status, 0);
		} while (waited == -1 && errno == EINTR);
		ASSERT_EQ(pid, waited);
		ASSERT_NE(0, WIFEXITED(status));
		ASSERT_EQ(EXPECTED_ASSERTION_EXIT, WEXITSTATUS(status));
	}
}

#else /* NDEBUG */

static void
test_allocation_failure(void)
{
	pamc_bp_t bp = NULL;
	const size_t old_free_calls = free_calls;

	/*
	 * Failed renewal safely returns NULL even without assertions.  Do not
	 * attempt out-of-bounds copies when NDEBUG disables their checks.
	 */
	fail_allocation = 1;
	PAM_BP_RENEW(&bp, PAM_BPC_OK, sizeof(data));
	ASSERT_EQ(NULL, bp);
	ASSERT_EQ(NULL, allocation);
	ASSERT_EQ(old_free_calls, free_calls);

	fail_allocation = 0;
	PAM_BP_RENEW(&bp, PAM_BPC_OK, sizeof(data));
	ASSERT_NE(NULL, bp);
	memset(PAM_BP_WDATA(bp), SENTINEL, sizeof(data));
	fail_allocation = 1;
	PAM_BP_RENEW(&bp, PAM_BPC_OK, sizeof(data));
	ASSERT_EQ(NULL, bp);
	ASSERT_EQ(NULL, allocation);
	ASSERT_EQ(old_free_calls + 1, free_calls);
	fail_allocation = 0;
}
#endif

int
main(void)
{
	/*
	 * Run the deterministic shadowing regression before the old prompt
	 * self-initialization bug could be reached.
	 */
	test_fill_bp_length_shadowing();
	test_fill_prompt_shadowing();
	test_wire_format();
	test_renew();
	test_fill_ranges();
	test_extract();
	test_controls();
#ifndef NDEBUG
	test_assertions();
#else
	test_allocation_failure();
#endif
	ASSERT_EQ(NULL, allocation);
	return 0;
}
