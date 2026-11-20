#include "../include/security.h"

int enable_sandbox(void) {
    int rc = -1;

    // Mandatory for unprivileged seccomp: prevent child processes from gaining privileges via setuid/setgid binaries.
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        return -1;
    }

    // Default action: Terminate the entire process on violations
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL_PROCESS);
    if (!ctx) {
        return -1;
    }

    // Simple unconditional allowed syscalls
    static const int allowed_syscalls[] = {
        // 1. Core Event Loop & Polling (io_uring + libpq async)
        SCMP_SYS(io_uring_enter),
        SCMP_SYS(poll),
        SCMP_SYS(ppoll),
        SCMP_SYS(epoll_ctl),
        SCMP_SYS(epoll_wait),
        SCMP_SYS(epoll_pwait),

        // 2. Memory & Crypto (glibc malloc/realloc + libsodium/libpq)
        SCMP_SYS(brk),
        SCMP_SYS(munmap),
        SCMP_SYS(mremap),
        SCMP_SYS(madvise),
        SCMP_SYS(getrandom),

        // 3. File, Directory & Upload Operations (confined inside chroot jail)
        SCMP_SYS(read),
        SCMP_SYS(readv),
        SCMP_SYS(pread64),
        SCMP_SYS(write),
        SCMP_SYS(writev),
        SCMP_SYS(pwrite64),
        SCMP_SYS(open),
        SCMP_SYS(openat),
        SCMP_SYS(creat),
        SCMP_SYS(close),
        SCMP_SYS(lseek),
        SCMP_SYS(fcntl),
        SCMP_SYS(dup),
        SCMP_SYS(dup2),
        SCMP_SYS(dup3),
        SCMP_SYS(stat),
        SCMP_SYS(fstat),
        SCMP_SYS(lstat),
        SCMP_SYS(newfstatat),
        SCMP_SYS(statx),
        SCMP_SYS(access),
        SCMP_SYS(faccessat),
        SCMP_SYS(faccessat2),
        SCMP_SYS(getcwd),
        SCMP_SYS(readlink),
        SCMP_SYS(readlinkat),
        SCMP_SYS(unlink),
        SCMP_SYS(unlinkat),
        SCMP_SYS(rename),
        SCMP_SYS(renameat),
        SCMP_SYS(renameat2),
        SCMP_SYS(mkdir),
        SCMP_SYS(mkdirat),
        SCMP_SYS(ftruncate),
        SCMP_SYS(fsync),
        SCMP_SYS(fdatasync),
        SCMP_SYS(getdents64),
        SCMP_SYS(pipe),
        SCMP_SYS(pipe2),

        // 4. Process Identity & Time (JWT timestamps, logging, sleep)
        SCMP_SYS(exit),
        SCMP_SYS(exit_group),
        SCMP_SYS(getpid),
        SCMP_SYS(gettid),
        SCMP_SYS(getuid),
        SCMP_SYS(geteuid),
        SCMP_SYS(getgid),
        SCMP_SYS(getegid),
        SCMP_SYS(time),
        SCMP_SYS(gettimeofday),
        SCMP_SYS(nanosleep),
        SCMP_SYS(clock_nanosleep),
        SCMP_SYS(clock_gettime),
        SCMP_SYS(clock_gettime64),

        // 5. Networking (Connected sockets only: HTTP / WebSockets / Postgres libpq)
        SCMP_SYS(send),
        SCMP_SYS(sendto),
        SCMP_SYS(sendmsg),
        SCMP_SYS(sendfile),
        SCMP_SYS(recv),
        SCMP_SYS(recvfrom),
        SCMP_SYS(recvmsg),
        SCMP_SYS(shutdown),
        SCMP_SYS(setsockopt),
        SCMP_SYS(getsockopt),
        SCMP_SYS(getsockname),
        SCMP_SYS(getpeername),

        // 6. Signals & Concurrency
        SCMP_SYS(restart_syscall),
        SCMP_SYS(sigaltstack),
        SCMP_SYS(sigreturn),
        SCMP_SYS(rt_sigreturn),
        SCMP_SYS(rt_sigaction),
        SCMP_SYS(rt_sigprocmask),
        SCMP_SYS(futex),
        SCMP_SYS(futex_time64),
    };

    for (size_t i = 0; i < sizeof(allowed_syscalls) / sizeof(allowed_syscalls[0]); i++) {
        if (allowed_syscalls[i] < 0) continue; // Skip unsupported syscalls on host architecture
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, allowed_syscalls[i], 0) < 0) {
            goto cleanup;
        }
    }

    // Conditional / Parameter-Filtered Rules

    // Disallow executable pages (Strict W^X enforcement)
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 1,
        SCMP_CMP(2, SCMP_CMP_MASKED_EQ, PROT_EXEC, 0)) < 0) goto cleanup;

    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 1,
        SCMP_CMP(2, SCMP_CMP_MASKED_EQ, PROT_EXEC, 0)) < 0) goto cleanup;

    // Gracefully handle ioctl errors without dropping the process
    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EACCES), SCMP_SYS(ioctl), 0) < 0) {
        goto cleanup;
    }

    // Activate Filter
    if (seccomp_load(ctx) < 0) {
        goto cleanup;
    }

    rc = 0;

    cleanup:
    seccomp_release(ctx);
    return rc;
}
