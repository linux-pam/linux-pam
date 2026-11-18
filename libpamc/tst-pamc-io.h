/* Test-only I/O hooks for a separately compiled pamc_converse.c. */
#ifndef TST_PAMC_IO_H
#define TST_PAMC_IO_H

#include <stddef.h>
#include <sys/types.h>

enum pamc_test_fault {
	IO_NORMAL, IO_READ_ERROR, IO_READ_BODY_ERROR, IO_WRITE_ERROR, IO_WRITE_ZERO
};
struct pamc_test_io {
	size_t read_limit, write_limit;
	size_t read_bytes, write_bytes;
	/* IO_WRITE_ERROR fires after this many successful bytes; zero is immediate. */
	size_t write_error_after;
	int interrupt_header, interrupt_body, interrupt_write;
	unsigned int interruptions;
	enum pamc_test_fault fault;
};
extern struct pamc_test_io pamc_test_io;
ssize_t pamc_test_read(int fd, void *buffer, size_t count);
ssize_t pamc_test_write(int fd, const void *buffer, size_t count);

#endif
