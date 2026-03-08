#ifndef RINGWALL_CORE_PROCESS_H
#define RINGWALL_CORE_PROCESS_H

#include <signal.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct {
    pid_t pid;
    int pidfd;
} rw_process_t;

[[nodiscard]] int rw_process_spawn(rw_process_t *proc, const char *path,
                                    const char *const argv[]);

[[nodiscard]] int rw_process_wait(rw_process_t *proc, int *exit_status,
                                   uint32_t timeout_ms);

[[nodiscard]] int rw_process_signal(rw_process_t *proc, int sig);

void rw_process_cleanup(rw_process_t *proc);

#endif /* RINGWALL_CORE_PROCESS_H */
