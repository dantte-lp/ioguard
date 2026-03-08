#define _GNU_SOURCE
#include "core/process.h"
#include <errno.h>
#include <poll.h>
#include <spawn.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

/* Check glibc version for pidfd_spawn */
#if defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 39))
#define HAVE_PIDFD_SPAWN 1
#else
#define HAVE_PIDFD_SPAWN 0
#endif

#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif

#ifndef __NR_pidfd_send_signal
#define __NR_pidfd_send_signal 424
#endif

extern char **environ;

int rw_process_spawn(rw_process_t *proc, const char *path,
                      const char *const argv[])
{
    memset(proc, 0, sizeof(*proc));
    proc->pidfd = -1;

    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);

    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);

    short flags = POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF;
    posix_spawnattr_setflags(&attr, flags);

    sigset_t empty, all;
    sigemptyset(&empty);
    sigfillset(&all);
    posix_spawnattr_setsigmask(&attr, &empty);
    posix_spawnattr_setsigdefault(&attr, &all);

    int ret;

#if HAVE_PIDFD_SPAWN
    ret = pidfd_spawn(&proc->pidfd, path, &fa, &attr,
                      (char *const *)argv, environ);
    if (ret != 0) {
        ret = -errno;
        goto cleanup;
    }
    /* pid will be obtained during waitid in rw_process_wait */
#else
    /* Fallback: posix_spawn + pidfd_open */
    pid_t pid;
    ret = posix_spawn(&pid, path, &fa, &attr,
                      (char *const *)argv, environ);
    if (ret != 0) {
        ret = -ret; /* posix_spawn returns errno directly */
        goto cleanup;
    }
    proc->pid = pid;
    proc->pidfd = (int)syscall(__NR_pidfd_open, pid, 0);
    if (proc->pidfd < 0) {
        proc->pidfd = -1; /* non-fatal */
    }
#endif

    ret = 0;

cleanup:
    posix_spawnattr_destroy(&attr);
    posix_spawn_file_actions_destroy(&fa);
    return ret;
}

int rw_process_wait(rw_process_t *proc, int *exit_status, uint32_t timeout_ms)
{
    *exit_status = -1;

    if (proc->pidfd >= 0 && timeout_ms > 0) {
        struct pollfd pfd = {.fd = proc->pidfd, .events = POLLIN};
        int ret = poll(&pfd, 1, (int)timeout_ms);
        if (ret == 0) {
            return -ETIMEDOUT;
        }
        if (ret < 0) {
            return -errno;
        }
    }

    if (proc->pidfd >= 0) {
        siginfo_t info = {0};
        int ret = waitid(P_PIDFD, (id_t)proc->pidfd, &info, WEXITED);
        if (ret < 0) {
            return -errno;
        }
        if (proc->pid == 0) {
            proc->pid = info.si_pid;
        }
        if (info.si_code == CLD_EXITED) {
            *exit_status = info.si_status;
        } else {
            *exit_status = 128 + info.si_status;
        }
        return 0;
    }

    int status;
    pid_t wpid = waitpid(proc->pid, &status, 0);
    if (wpid < 0) {
        return -errno;
    }

    if (WIFEXITED(status)) {
        *exit_status = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        *exit_status = 128 + WTERMSIG(status);
    }

    return 0;
}

int rw_process_signal(rw_process_t *proc, int sig)
{
    if (proc->pidfd >= 0) {
        int ret = (int)syscall(__NR_pidfd_send_signal, proc->pidfd, sig, nullptr, 0);
        if (ret < 0) {
            return -errno;
        }
        return 0;
    }
    if (kill(proc->pid, sig) < 0) {
        return -errno;
    }
    return 0;
}

void rw_process_cleanup(rw_process_t *proc)
{
    if (proc->pidfd >= 0) {
        close(proc->pidfd);
        proc->pidfd = -1;
    }
    proc->pid = 0;
}
