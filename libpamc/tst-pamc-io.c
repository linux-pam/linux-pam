/*
 * Only the test copy of pamc_converse.c calls these hooks.  All other library
 * code and the real agent use normal I/O.  Caps force short transfers, and
 * one-shot faults exercise retry/error paths without scheduling-dependent
 * signals.  This file is compiled without the library's read/write renaming,
 * so ordinary libc calls do not recurse and retain sanitizer interception.
 */
#include <config.h>
#include "tst-pamc-io.h"

#include <errno.h>
#include <unistd.h>

struct pamc_test_io pamc_test_io;

ssize_t
pamc_test_read(int fd, void *buffer, size_t count)
{
	/* Five octets of header precede the body on the wire. */
	int *interrupt = pamc_test_io.read_bytes < 5
		? &pamc_test_io.interrupt_header : &pamc_test_io.interrupt_body;

	if (*interrupt) {
		*interrupt = 0;
		++pamc_test_io.interruptions;
		errno = EINTR;
		return -1;
	}
	if (pamc_test_io.fault == IO_READ_ERROR
	    || (pamc_test_io.fault == IO_READ_BODY_ERROR
		&& pamc_test_io.read_bytes >= 5)) {
		pamc_test_io.fault = IO_NORMAL;
		errno = EIO;
		return -1;
	}
	if (pamc_test_io.read_limit && count > pamc_test_io.read_limit)
		count = pamc_test_io.read_limit;
	ssize_t result = read(fd, buffer, count);
	if (result > 0)
		pamc_test_io.read_bytes += result;
	return result;
}

ssize_t
pamc_test_write(int fd, const void *buffer, size_t count)
{
	if (pamc_test_io.interrupt_write) {
		pamc_test_io.interrupt_write = 0;
		++pamc_test_io.interruptions;
		errno = EINTR;
		return -1;
	}
	if (pamc_test_io.fault == IO_WRITE_ERROR
	    && pamc_test_io.write_bytes >= pamc_test_io.write_error_after) {
		pamc_test_io.fault = IO_NORMAL;
		errno = EIO;
		return -1;
	}
	if (pamc_test_io.fault == IO_WRITE_ZERO) {
		/* One-shot: buggy retry code fails its result assertion, not a hang. */
		pamc_test_io.fault = IO_NORMAL;
		return 0;
	}
	if (pamc_test_io.write_limit && count > pamc_test_io.write_limit)
		count = pamc_test_io.write_limit;
	ssize_t result = write(fd, buffer, count);
	if (result > 0)
		pamc_test_io.write_bytes += result;
	return result;
}
