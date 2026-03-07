#ifndef WOLFGUARD_CORE_PROCESS_H
#define WOLFGUARD_CORE_PROCESS_H

#include <signal.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct {
    pid_t pid;
    int pidfd;
} wg_process_t;

[[nodiscard]] int wg_process_spawn(wg_process_t *proc, const char *path,
                                    const char *const argv[]);

[[nodiscard]] int wg_process_wait(wg_process_t *proc, int *exit_status,
                                   uint32_t timeout_ms);

[[nodiscard]] int wg_process_signal(wg_process_t *proc, int sig);

void wg_process_cleanup(wg_process_t *proc);

#endif /* WOLFGUARD_CORE_PROCESS_H */
