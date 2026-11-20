# CWEB Web Framework

CWEB is a high-performance, strictly zero-copy web engine and application platform written in raw C. Its primary goals are absolute maximum throughput, minimal resource utilization, deterministic memory safety, and enterprise-grade security.

By bypassing traditional POSIX socket paradigms and `epoll` event loops in favor of modern Linux `io_uring` and kernel-space `splice(2)` data piping, CWEB is engineered to saturate bare-metal network links while consuming only a fraction of the memory overhead of traditional web runtimes.

This documentation is meant for the 1.0.x releases of the CWEB framework.

---

# Features

- **Asynchronous `io_uring` Event Loop**: Powered exclusively by Linux `io_uring`, eliminating `epoll` system call overhead, interrupt storms, and user-to-kernel context switching.
- **True Zero-Copy I/O**: Static files and file uploads are streamed directly between kernel space disk caches and network socket buffers via `splice(2)` pipes, completely bypassing user-space RAM.
- **Multi-Core Shared-Nothing Architecture**: Pre-forks dedicated worker processes per available CPU core with `SO_REUSEPORT` kernel load balancing, maximizing CPU L1/L2/L3 cache locality without mutex contention.
- **Strictly HTTP/1.1 Compliant**: Custom zero-allocation HTTP parser operating in-place with RFC 7230 compliance and built-in resistance to HTTP request smuggling.
- **Radix Tree Routing**: High-speed URL router with support for dynamic path parameters (`:param`) and composable middleware pipelines.
- **Non-Blocking PostgreSQL Multiplexing**: Native integration with PostgreSQL (`libpq`) utilizing Pipeline Mode and dynamic Row-Level Security (RLS) contexts directly from the event loop.
- **Fully Privilege-Separated by Default**: Master process binds restricted ports as `root:root` and immediately demotes worker processes to the unprivileged `nobody:nobody` user before accepting network traffic.
- **Kernel-Level Sandboxing**: Enforces strict `seccomp-bpf` syscall whitelisting per worker process, neutralizing remote code execution (RCE) vectors at the kernel barrier.
- **Anti-Slowloris Protection**: Built-in kernel-level read timeouts via `io_uring` linked timeout SQEs (`io_uring_prep_link_timeout`) that automatically terminate byte-trickling clients.
- **Zero Runtime Allocations**: Employs fixed, deterministic pre-allocated memory pools (`ConnContext`, `PipeNode`, `PGconn`) at startup, guaranteeing $O(1)$ allocation times and eliminating heap fragmentation.
- **Integrated JSON Processing**: High-speed in-buffer JSON tokenizer and streaming `JsonBuilder` designed for zero heap allocation.
- **First-Class WebSockets**: Integrated unmasked WebSocket protocol engine handling framing and continuous message streaming within the same ring. (Not tested yet)
- **Kernel Backwards Compatibility**: Dynamic runtime capability detection and graceful fallback between bleeding-edge Linux 5.19+ flags (`COOP_TASKRUN`, `SINGLE_ISSUER`) and standard `io_uring` rings on legacy kernels (Linux 5.10+).

---

# Architecture Overview

```text
                               +------------------------------------------+
                               |              MASTER PROCESS              |
                               |  - Runs as root (binds port < 1024)      |
                               |  - Raises RLIMIT_MEMLOCK limits          |
                               |  - Forks N per-CPU worker processes      |
                               +--------------------+---------------------+
                                                    |
                         +--------------------------+--------------------------+
                         |                          |                          |
                         ▼                          ▼                          ▼
            +-------------------------+ +-------------------------+ +-------------------------+
            |    WORKER PROCESS 0     | |    WORKER PROCESS 1     | |    WORKER PROCESS N     |
            |  - Drops to 'nobody'    | |  - Drops to 'nobody'    | |  - Drops to 'nobody'    |
            |  - Seccomp-BPF sandbox  | |  - Seccomp-BPF sandbox  | |  - Seccomp-BPF sandbox  |
            |  - Dedicated io_uring   | |  - Dedicated io_uring   | |  - Dedicated io_uring   |
            +------------+------------+ +------------+------------+ +------------+------------+
                         |
                         ▼
+---------------------------------------------------------------------------------------------+
|                                  WORKER INTERNALS & I/O ENGINE                              |
|                                                                                             |
|   +------------------------------------+          +-------------------------------------+   |
|   |         SUBMISSION QUEUE           |          |          COMPLETION QUEUE           |   |
|   |  - mmap'd ring in user space       |          |  - mmap'd ring in user space        |   |
|   |  - Batched submissions (512 SQEs)  |          |  - Batch CQE harvesting (8192 depth)|   |
|   +-----------------+------------------+          +------------------+------------------+   |
|                     |                                                ▲                      |
|                     ▼                                                |                      |
|   +------------------------------------------------------------------+------------------+   |
|   |                              CONNECTION CONTEXT POOL                                |   |
|   |  - Pre-allocated ConnContext array (MAX_CLIENTS = 4096)                             |   |
|   |  - Fixed 8 KB in-place request/response buffer per connection                       |   |
|   |  - Finite State Machine: ACCEPT -> READ -> ROUTE -> DB/SPLICE -> WRITE              |   |
|   +-----------------+------------------------------------------------+------------------+   |
|                     |                                                |                      |
|                     ▼                                                ▼                      |
|   +------------------------------------+          +-------------------------------------+   |
|   |        ZERO-COPY DATA PIPING       |          |      ASYNCHRONOUS POSTGRESQL        |   |
|   |  - Pre-allocated Pipe Pool (2048)  |          |  - libpq Pipeline Mode multiplexing |   |
|   |  - Kernel splice(2) disk-to-socket |          |  - Non-blocking socket polling ring |   |
|   |  - Zero user-space memory copies   |          |  - In-flight multi-statement sync   |   |
|   +------------------------------------+          +-------------------------------------+   |
+---------------------------------------------------------------------------------------------+
```

---

## Process Model

CWEB adopts a **shared-nothing, multi-process architecture**:

1. **Master Lifecycle**:
   - The master process initializes the primary listening socket with `SO_REUSEPORT` enabled.
   - It raises system limits, specifically increasing `RLIMIT_MEMLOCK` to permit `io_uring` internal kernel memory mapping.
   - It queries `sysconf(_SC_NPROCESSORS_ONLN)` and forks an isolated worker process for every available CPU core.
   - The master monitors child processes and manages clean termination signals.

2. **Worker Isolation**:
   - Each worker process executes in complete isolation without shared heap structures or cross-process mutexes.
   - Immediately following `fork()`, the worker calls `setgid()` and `setuid()` to assume the identity of the unprivileged `nobody` user.
   - The worker initializes its own dedicated `io_uring` ring (`QUEUE_DEPTH = 8192`) and allocates its private context and pipe pools.
   - Finally, the worker engages a strict `seccomp-bpf` filter that unconditionally forbids `execve`, `fork`, and unauthorized system calls.

---

## Event Loop & I/O Engine

Unlike traditional C frameworks that rely on `epoll(7)` (which requires two context switches per event—one to wait and another to perform the system call), CWEB is architected entirely around **Linux `io_uring`**:

- **Shared Ring Buffers**: The Submission Queue (SQ) and Completion Queue (CQ) are mapped directly into the process's address space via `mmap(2)`. The user application and the kernel exchange requests and completions without crossing the syscall boundary for every operation. Thus, eliminating the infamous kernel tax.
- **Batch Processing**: Requests are submitted and harvested in batches of up to 512 events (`BATCH_SIZE`), allowing a single worker to process tens of thousands of concurrent I/O operations per millisecond.
- **Asynchronous State Machine**: Each connection is tracked through an explicit non-blocking finite state machine (`ACCEPT`, `READ`, `WRITE`, `WAIT`, `SPLICE_IN`, `SPLICE_OUT`, `RESUME`, `QUEUED`, `UPLOAD_WRITE`, `UPLOAD_SPLICE_IN`, `UPLOAD_SPLICE_OUT`). When I/O is pending (such as waiting on disk reads or database query results), the connection yields control back to the state machine. Thus, attaining true asynchronous behaviour.

---

## Memory Architecture

CWEB enforces a **strict zero-allocation discipline**:

- **Pre-Allocated Memory Pools**: All connection descriptors (`ConnContext`), ring state data, and splice pipe nodes (`PipeNode`) are allocated once during worker initialization. No `malloc()` or `free()` calls take place in the hot request-response cycle.
- **In-Place Parsing**: Incoming HTTP headers, URIs, query parameters, and JSON payloads are sliced in-place using lightweight string references (`StringView` containing `char* str` and `int len`). The original input buffer is reused without intermediate string copying or dynamic memory allocation.
- **Fixed RSS Footprint**: Because heap allocations are prohibited on the hot path, a CWEB server maintains a fixed resident memory footprint (typically between 13 MB and 17 MB RSS) regardless of traffic volume or duration.

---

## Security Model

Security is built directly into CWEB's architectural foundation:

- **Privilege Demotion**: Worker processes operate without root privileges. Any compromised worker process possesses no write access to system directories, local source code, or configuration files.
- **Seccomp-BPF Sandboxing**: Every worker executes under a kernel-enforced system call filter. Disallowed syscalls trigger immediate process termination (`SCMP_ACT_KILL_PROCESS`), preventing shell spawning or privilege escalation attacks.
- **Anti-Slowloris Timeouts**: Read operations are linked to hardware timer completions in the kernel ring via `io_uring_prep_link_timeout`. Sockets that idle or trickle data are severed automatically by the kernel without application-level watchdog threads.
- **TLS Termination Architecture**: To prevent library bloat and complex OpenSSL attack surfaces inside the sandboxed engine, CWEB is designed to operate behind an edge reverse proxy or tunnel (such as Cloudflare Tunnel or Envoy) that offloads TLS termination.
