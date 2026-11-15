/* Exercise misc_conv in a fresh process for each state-mutating case. */

#include <config.h>

#include <security/pam_misc.h>
#include <string.h>
#include <unistd.h>

#include "test_assert.h"

static const unsigned char binary_data[] = { 'a', 0, 'b', 0xff };
static const unsigned char replacement_data[] = { 0xff, 0, 'c' };

enum binary_action {
	BINARY_COPY,
	BINARY_REPLACE,
	BINARY_FAIL,
	BINARY_NULL,
	BINARY_CLOSE_INPUT,
};

struct conversation {
	pamc_bp_t request;
	pamc_bp_t responses[2];
	enum binary_action action;
	int handled;
	int freed;
};

static void
usage(void)
{
	fputs("Usage: tst-misc_conv arguments|null-arguments|informational|input on|off CASE|failure CASE|binary CASE\n",
	      stderr);
	exit(EXIT_FAILURE);
}

static FILE *
temporary_file(void)
{
	FILE *file = tmpfile();

	ASSERT_NE(NULL, file);
	return file;
}

static void
redirect_file(FILE *file, int descriptor)
{
	ASSERT_EQ(0, fflush(NULL));
	ASSERT_EQ(descriptor, dup2(fileno(file), descriptor));
}

static void
check_output(FILE *file, const char *expected)
{
	ASSERT_EQ(0, fflush(NULL));
	ASSERT_EQ(0, fseek(file, 0, SEEK_SET));
	for (const char *p = expected; *p; ++p)
		ASSERT_EQ((unsigned char) *p, fgetc(file));
	ASSERT_EQ(EOF, fgetc(file));
	ASSERT_EQ(0, ferror(file));
}

static void
check_error_output(FILE *file, const char *expected)
{
#ifdef PAM_DEBUG
	char *line = NULL;
	size_t size = 0;
	int matches = 0;

	ASSERT_EQ(0, fflush(NULL));
	ASSERT_EQ(0, fseek(file, 0, SEEK_SET));
	/* Allow debug diagnostics without depending on their contents or format. */
	while (getline(&line, &size, file) >= 0)
		if (strcmp(line, expected) == 0)
			++matches;
	ASSERT_EQ(0, ferror(file));
	ASSERT_EQ(1, matches);
	free(line);
#else
	check_output(file, expected);
#endif
}

static void
check_text_response(const struct pam_response *response, const char *expected)
{
	ASSERT_EQ(0, response->resp_retcode);
	if (expected) {
		ASSERT_NE(NULL, response->resp);
		ASSERT_EQ(0, strcmp(expected, response->resp));
	} else {
		ASSERT_EQ(NULL, response->resp);
	}
}

static void
free_text_responses(struct pam_response *response, int count)
{
	for (int i = 0; i < count; ++i)
		free(response[i].resp);
	free(response);
}

static pamc_bp_t
make_binary_prompt(void)
{
	pamc_bp_t prompt = NULL;

	PAM_BP_RENEW(&prompt, PAM_BPC_OK, sizeof(binary_data));
	ASSERT_NE(NULL, prompt);
	PAM_BP_FILL(prompt, 0, sizeof(binary_data), binary_data);
	return prompt;
}

static void
check_binary_prompt(pamc_bp_t prompt, int control,
		    const unsigned char *data, size_t length)
{
	ASSERT_NE(NULL, prompt);
	ASSERT_EQ(control, PAM_BP_RCONTROL(prompt));
	ASSERT_EQ(length, PAM_BP_LENGTH(prompt));
	ASSERT_EQ(0, memcmp(data, PAM_BP_RDATA(prompt), length));
}

static int
handle_binary(void *appdata, pamc_bp_t *prompt)
{
	struct conversation *state = appdata;

	ASSERT_NE(NULL, state);
	ASSERT_NE(NULL, prompt);
	ASSERT_NE(state->request, *prompt);
	check_binary_prompt(*prompt, PAM_BPC_OK, binary_data, sizeof(binary_data));
	ASSERT_LT(state->handled, 2);
	++state->handled;
	switch (state->action) {
	case BINARY_REPLACE:
		PAM_BP_RENEW(prompt, PAM_BPC_DONE, sizeof(replacement_data));
		PAM_BP_FILL(*prompt, 0, sizeof(replacement_data), replacement_data);
		break;
	case BINARY_FAIL:
	case BINARY_NULL:
		/* The handler disposes of its in-progress packet on failure. */
		PAM_BP_RENEW(prompt, 0, 0);
		return state->action == BINARY_FAIL ? PAM_AUTH_ERR : PAM_SUCCESS;
	case BINARY_CLOSE_INPUT:
		ASSERT_EQ(0, close(STDIN_FILENO));
		break;
	case BINARY_COPY:
		break;
	}
	state->responses[state->handled - 1] = *prompt;
	return PAM_SUCCESS;
}

static void
free_binary(void *appdata, pamc_bp_t *prompt)
{
	struct conversation *state = appdata;

	ASSERT_NE(NULL, state);
	ASSERT_LT(state->freed, state->handled);
	ASSERT_NE(NULL, prompt);
	ASSERT_EQ(state->responses[state->freed], *prompt);
	PAM_BP_RENEW(prompt, 0, 0);
	ASSERT_EQ(NULL, *prompt);
	state->responses[state->freed] = NULL;
	++state->freed;
}

static void
test_arguments(void)
{
	const struct pam_message msg = { PAM_TEXT_INFO, "unused" };
	const struct pam_message *msgm = &msg;
	struct pam_response *response = NULL;

	ASSERT_EQ(PAM_CONV_ERR, misc_conv(0, &msgm, &response, NULL));
	ASSERT_EQ(PAM_CONV_ERR, misc_conv(-1, &msgm, &response, NULL));
}

static void
test_null_arguments(void)
{
	const struct pam_message msg = { PAM_TEXT_INFO, "unused" };
	const struct pam_message *msgm = &msg;
	struct pam_response *response = NULL;

	/* msgm == NULL, response == NULL */
	ASSERT_EQ(PAM_CONV_ERR, misc_conv(1, NULL, NULL, NULL));

	/* msgm == NULL, response != NULL */
	ASSERT_EQ(PAM_CONV_ERR, misc_conv(1, NULL, &response, NULL));

	/* msgm != NULL, response == NULL */
	ASSERT_EQ(PAM_CONV_ERR, misc_conv(1, &msgm, NULL, NULL));
}

static void
test_informational(void)
{
	FILE *output = temporary_file();
	FILE *error = temporary_file();
	const struct pam_message info = { PAM_TEXT_INFO, "information" };
	const struct pam_message warning = { PAM_ERROR_MSG, "error" };
	const struct pam_message empty = { PAM_TEXT_INFO, "" };
	const struct pam_message *msgm[] = { &info, &warning, &empty };
	struct pam_response *response = NULL;
	int diagnostic_fd = dup(STDERR_FILENO);

	ASSERT_LE(0, diagnostic_fd);
	redirect_file(output, STDOUT_FILENO);
	redirect_file(error, STDERR_FILENO);
	int result = misc_conv(3, msgm, &response, NULL);

	/* Keep assertion and sanitizer diagnostics visible after capturing stderr. */
	ASSERT_EQ(0, fflush(stderr));
	ASSERT_EQ(STDERR_FILENO, dup2(diagnostic_fd, STDERR_FILENO));
	ASSERT_EQ(0, close(diagnostic_fd));
	ASSERT_EQ(PAM_SUCCESS, result);
	ASSERT_NE(NULL, response);
	for (int i = 0; i < 3; ++i)
		check_text_response(&response[i], NULL);
	check_output(output, "information\n\n");
	check_error_output(error, "error\n");
	free_text_responses(response, 3);
	ASSERT_EQ(0, fclose(output));
	ASSERT_EQ(0, fclose(error));
}

static void
test_input(int style, const char *name)
{
	FILE *input = temporary_file();
	const char *expected[3] = { NULL, NULL, NULL };
	char *long_line = NULL;
	int count = 1;

	if (strcmp(name, "line") == 0) {
		ASSERT_NE(EOF, fputs("answer\n", input));
		expected[0] = "answer";
	} else if (strcmp(name, "empty") == 0) {
		ASSERT_NE(EOF, fputs("\n", input));
		expected[0] = "";
	} else if (strcmp(name, "eof") == 0) {
		/* Leave the input file empty. */
	} else if (strcmp(name, "no-newline") == 0) {
		ASSERT_NE(EOF, fputs("answer", input));
		expected[0] = "answer";
	} else if (strcmp(name, "multiple") == 0) {
		ASSERT_NE(EOF, fputs("first\nsecond\n", input));
		expected[0] = "first";
		/* The informational message between prompts needs its own entry. */
		expected[2] = "second";
		count = 3;
	} else {
		size_t limit = PAM_MISC_CONV_BUFSIZE - 1;
		size_t length = limit;

		if (strcmp(name, "below-limit") == 0)
			--length;
		else if (strcmp(name, "above-limit") == 0)
			++length;
		else if (strcmp(name, "at-limit") != 0)
			usage();
		long_line = malloc(length + 1);
		ASSERT_NE(NULL, long_line);
		memset(long_line, 'x', length);
		long_line[length] = '\0';
		ASSERT_NE(EOF, fputs(long_line, input));
		ASSERT_NE(EOF, fputs("\nnext\n", input));
		expected[0] = long_line;
		if (length < limit) {
			expected[1] = "next";
			count = 2;
		} else {
			long_line[limit] = '\0';
			expected[1] = length == limit ? "" : "x";
			expected[2] = "next";
			count = 3;
		}
	}
	ASSERT_EQ(0, fseek(input, 0, SEEK_SET));
	redirect_file(input, STDIN_FILENO);
	const struct pam_message first = { style, "prompt: " };
	const struct pam_message second = { style, "prompt: " };
	const struct pam_message third = { style, "prompt: " };
	const struct pam_message info = { PAM_TEXT_INFO, "between prompts" };
	const struct pam_message *msgm[] = { &first, &second, &third };
	struct pam_response *response = NULL;

	if (strcmp(name, "multiple") == 0)
		msgm[1] = &info;
	ASSERT_EQ(PAM_SUCCESS, misc_conv(count, msgm, &response, NULL));
	ASSERT_NE(NULL, response);
	for (int i = 0; i < count; ++i)
		check_text_response(&response[i], expected[i]);
	free_text_responses(response, count);
	free(long_line);
	ASSERT_EQ(0, fclose(input));
}

static void
test_failure(const char *name)
{
	FILE *input = temporary_file();
	const struct pam_message first = { PAM_PROMPT_ECHO_ON, "first: " };
	const struct pam_message second = { PAM_PROMPT_ECHO_OFF, "second: " };
	const struct pam_message invalid = { -1, "invalid" };
	const struct pam_message *msgm[] = { &invalid, &invalid, &invalid };
	struct pam_response *response = NULL;
	struct conversation state = { .request = NULL, .action = BINARY_CLOSE_INPUT };
	struct pam_message binary = { PAM_BINARY_PROMPT, NULL };
	int count = 1;

	ASSERT_NE(EOF, fputs("first\nsecond\n", input));
	ASSERT_EQ(0, fseek(input, 0, SEEK_SET));
	redirect_file(input, STDIN_FILENO);
	if (strcmp(name, "invalid-after-text") == 0) {
		msgm[0] = &first;
		msgm[1] = &second;
		count = 3;
	} else if (strcmp(name, "read-error") == 0) {
		ASSERT_EQ(0, close(STDIN_FILENO));
		msgm[0] = &first;
	} else if (strcmp(name, "read-error-after-response") == 0) {
		state.request = make_binary_prompt();
		binary.msg = (const char *) state.request;
		pam_binary_handler_fn = handle_binary;
		pam_binary_handler_free = free_binary;
		msgm[0] = &first;
		msgm[1] = &binary;
		msgm[2] = &second;
		count = 3;
	} else {
		if (strcmp(name, "invalid-style") != 0)
			usage();
	}
	ASSERT_EQ(PAM_CONV_ERR, misc_conv(count, msgm, &response, &state));
	if (state.request) {
		ASSERT_EQ(1, state.handled);
		ASSERT_EQ(1, state.freed);
		PAM_BP_RENEW(&state.request, 0, 0);
	}
	ASSERT_EQ(0, fclose(input));
}

static void
test_binary(const char *name)
{
	struct conversation state = { .request = make_binary_prompt(), .action = BINARY_COPY };
	const struct pam_message binary = { PAM_BINARY_PROMPT, (const char *) state.request };
	const struct pam_message invalid = { PAM_BINARY_PROMPT, NULL };
	const struct pam_message *msgm[] = { &binary, &invalid, &invalid };
	struct pam_response *response = NULL;
	int count = 1, success = 0, handled = 1, freed = 0;

	pam_binary_handler_fn = handle_binary;
	if (strcmp(name, "cleanup-default") != 0)
		pam_binary_handler_free = free_binary;
	if (strcmp(name, "copy") == 0) {
		success = 1;
	} else if (strcmp(name, "replace") == 0) {
		state.action = BINARY_REPLACE;
		success = 1;
	} else if (strcmp(name, "missing-handler") == 0) {
		pam_binary_handler_fn = NULL;
		handled = 0;
	} else if (strcmp(name, "null-payload") == 0) {
		msgm[0] = &invalid;
		handled = 0;
	} else if (strcmp(name, "handler-failure") == 0) {
		state.action = BINARY_FAIL;
	} else if (strcmp(name, "handler-null") == 0) {
		state.action = BINARY_NULL;
	} else if (strcmp(name, "cleanup-multiple") == 0) {
		msgm[1] = &binary;
		count = 3;
		handled = freed = 2;
	} else if (strcmp(name, "cleanup-custom") == 0) {
		count = 2;
		freed = 1;
	} else if (strcmp(name, "cleanup-default") == 0) {
		count = 2;
	} else {
		usage();
	}
	ASSERT_EQ(success ? PAM_SUCCESS : PAM_CONV_ERR,
		  misc_conv(count, msgm, &response, &state));
	ASSERT_EQ(handled, state.handled);
	ASSERT_EQ(freed, state.freed);
	check_binary_prompt(state.request, PAM_BPC_OK, binary_data, sizeof(binary_data));
	if (success) {
		ASSERT_NE(NULL, response);
		ASSERT_EQ(0, response[0].resp_retcode);
		pamc_bp_t reply = (pamc_bp_t) response[0].resp;

		ASSERT_EQ(state.responses[0], reply);
		ASSERT_NE(state.request, reply);
		if (state.action == BINARY_REPLACE)
			check_binary_prompt(reply, PAM_BPC_DONE, replacement_data, sizeof(replacement_data));
		else
			check_binary_prompt(reply, PAM_BPC_OK, binary_data, sizeof(binary_data));
		PAM_BP_RENEW(&reply, 0, 0);
		free(response);
	}
	PAM_BP_RENEW(&state.request, 0, 0);
}

int
main(int argc, char **argv)
{
	if (argc == 2 && strcmp(argv[1], "arguments") == 0)
		test_arguments();
	else if (argc == 2 && strcmp(argv[1], "null-arguments") == 0)
		test_null_arguments();
	else if (argc == 2 && strcmp(argv[1], "informational") == 0)
		test_informational();
	else if (argc == 4 && strcmp(argv[1], "input") == 0 &&
		 (strcmp(argv[2], "on") == 0 || strcmp(argv[2], "off") == 0))
		test_input(strcmp(argv[2], "on") == 0 ? PAM_PROMPT_ECHO_ON : PAM_PROMPT_ECHO_OFF, argv[3]);
	else if (argc == 3 && strcmp(argv[1], "failure") == 0)
		test_failure(argv[2]);
	else if (argc == 3 && strcmp(argv[1], "binary") == 0)
		test_binary(argv[2]);
	else {
		usage();
	}
	return EXIT_SUCCESS;
}
