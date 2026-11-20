#ifndef SECURITY_H
#define SECURITY_H

#include <seccomp.h>
#include <stdio.h>
#include <sys/mman.h> // For PROT_EXEC
#include <errno.h>    // For EACCES
#include <sys/prctl.h>
#include <sys/syscall.h>

int enable_sandbox(void);

#endif
