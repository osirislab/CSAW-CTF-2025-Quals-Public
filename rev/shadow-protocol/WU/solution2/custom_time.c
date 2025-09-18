#define _GNU_SOURCE
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

// Strict override of time()
time_t time(time_t *tloc) {
    const char *fake_time_env = getenv("FAKE_TIME");
    if (!fake_time_env) {
        fprintf(stderr, "[FATAL] FAKE_TIME not set. Aborting.\n");
        _exit(1);  // Use _exit to avoid flushing stdio buffers or atexit handlers
    }

    char *endptr = NULL;
    time_t fake_time = strtoll(fake_time_env, &endptr, 10);
    if (*endptr != '\0' || fake_time <= 0) {
        fprintf(stderr, "[FATAL] Invalid FAKE_TIME: '%s'. Must be a valid epoch time.\n", fake_time_env);
        _exit(1);
    }

    if (tloc) *tloc = fake_time;
    return fake_time;
}
