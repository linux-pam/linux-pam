/*
   Test that pamc_list_agents() returns every agent in the search path.

   This is a regression test for the heap buffer overflow that occurred
   when the agent directory contained more than one agent.
*/

#include <config.h>

#include <security/pam_client.h>

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#define AGENT_COUNT 3

int
main(void)
{
	char dir[] = "/tmp/pamc-test-XXXXXX";
	static const char *const agents[AGENT_COUNT] = {
		"agent1@test", "agent2@test", "agent3@test"
	};
	pamc_handle_t pch;
	char **list;
	char path[256];
	int i, n;

	if (mkdtemp(dir) == NULL) {
		perror("mkdtemp");
		return 1;
	}
	for (i = 0; i < AGENT_COUNT; i++) {
		FILE *fp;

		snprintf(path, sizeof(path), "%s/%s", dir, agents[i]);
		fp = fopen(path, "w");
		if (fp == NULL) {
			perror(path);
			return 1;
		}
		fclose(fp);
	}
	if (setenv("PAMC_AGENT_PATH", dir, 1) != 0) {
		perror("setenv");
		return 1;
	}

	pch = pamc_start();
	if (pch == NULL) {
		fprintf(stderr, "pamc_start() failed\n");
		return 1;
	}
	list = pamc_list_agents(pch);
	if (list == NULL) {
		fprintf(stderr, "pamc_list_agents() failed\n");
		return 1;
	}
	for (n = 0; list[n] != NULL; n++)
		free(list[n]);
	free(list);
	pamc_end(&pch);

	if (n != AGENT_COUNT) {
		fprintf(stderr, "expected %d agents, got %d\n",
			AGENT_COUNT, n);
		return 1;
	}

	for (i = 0; i < AGENT_COUNT; i++) {
		snprintf(path, sizeof(path), "%s/%s", dir, agents[i]);
		unlink(path);
	}
	rmdir(dir);
	return 0;
}
