# CWEB

A high-performance, strictly zero-copy, io_uring-powered web framework written in raw C.

## Overview
CWEB is a strictly HTTP/1.1 compliant web engine designed for absolute maximum throughput and minimal resource footprint. By bypassing traditional POSIX sockets in favor of Linux `io_uring` and leveraging zero-copy `splice()` operations, CWEB is capable of saturating bare-metal network links while consuming a fraction of the memory overhead of traditional frameworks.

## Features
- **True Zero-Copy I/O**: Static files and file uploads are streamed directly between kernel space disk and network buffers via `splice`, bypassing user-space RAM entirely.
- **Asynchronous Event Loop**: Powered exclusively by Linux `io_uring`, eliminating `epoll` system call overhead and context switching.
- **Lock-Free Multi-Core**: Operates on a shared-nothing, pre-forked worker architecture maximizing CPU cache locality.
- **Strictly HTTP/1.1 Compliant**: Fully custom HTTP parser designed for zero-allocation parsing and resistance to Slowloris and Smuggling attacks.
- **Zero-Copy WebSockets**: First-class, unmasked WebSocket support built directly into the core engine.
- **Non-Blocking PostgreSQL**: Native, asynchronous integration with PostgreSQL (`libpq`) utilizing Row-Level Security (RLS) contexts directly from the event loop.
- **Kernel-Level Sandboxing**: Enforces strict `seccomp-bpf` syscall whitelisting to lock down worker processes.
- **Radix Tree Routing**: Lightning-fast URL routing with support for dynamic path parameters and middleware pipelines.


## Architectural Comparisons

CWEB was built to bypass the inherent POSIX and runtime bottlenecks found in standard industry frameworks by bringing kernel-level asynchronous I/O to a higher-level routing architecture.

- **vs. Kore (C)**: While Kore is a highly optimized C framework, it relies on the traditional `epoll()` event loop. `epoll` requires the kernel to wake the user-space process, which then must execute additional blocking syscalls (`read`, `write`, `accept`) to process I/O—each triggering a heavy user-to-kernel context switch. CWEB entirely abandons `epoll` in favor of Linux `io_uring`. By mapping Submission and Completion Queue Rings directly into user-space RAM via `mmap`, CWEB eliminates syscall overhead. Batch I/O operations are pushed into the ring without ever trapping into the kernel, allowing CWEB to handle millions of connections using fewer CPU cycles.
- **vs. Express.js (Node.js)**: Express relies on V8 and `libuv` (which abstracts `epoll`). Network I/O in Express must cross the C++ to JavaScript boundary. Data is copied from kernel buffers to C++ buffers, then translated into V8 Heap string objects, causing massive Garbage Collection (GC) pressure and destroying CPU cache locality. CWEB parses HTTP requests in-place (zero-allocation) within a strictly pre-allocated memory pool per connection. There is no heap allocation per request, zero garbage collection, and zero runtime overhead.
- **vs. .NET (Kestrel)**: Kestrel is an incredibly fast, highly optimized server using `Span<T>` to reduce memory allocations. However, it still operates within the CLR and relies on a generational garbage collector. Massive concurrent I/O inevitably leads to memory fragmentation and L3 cache thrashing. CWEB utilizes a rigid, deterministic `ConnContext` struct array. Because the memory is pooled at startup, CWEB guarantees `O(1)` memory access times and completely eliminates memory fragmentation, regardless of how many months the server runs.
- **vs. Django (Python) & Laravel (PHP)**: Django (WSGI/Gunicorn) and Laravel (PHP-FPM) utilize synchronous, blocking I/O models. A worker process is completely blocked while waiting for a PostgreSQL query to return. Furthermore, their ORMs instantiate thousands of heap objects per database row. CWEB integrates `libpq` in pure asynchronous mode directly into the `io_uring` event loop. When CWEB sends an SQL query, the context immediately yields back to the kernel. Results are processed natively via C pointers without any ORM overhead, allowing a single CWEB worker to multiplex thousands of database queries simultaneously.

## Motivation

I hate Javascript.


## System Compatibility

CWEB is highly portable across modern Linux distributions and containerized environments.

* **Linux Kernel:** CWEB requires at least **Kernel 5.7+** for zero-copy `splice` operations. On **Kernel 5.19+**, CWEB automatically engages bleeding-edge `io_uring` flags (`COOP_TASKRUN` and `SINGLE_ISSUER`) for maximum CPU efficiency. It falls back gracefully on older kernels.
* **C Standard Library (libc):** CWEB is strictly POSIX-compliant and entirely libc-agnostic. It compiles flawlessly on **glibc** (Ubuntu/Debian/Arch) as well as **musl** (Alpine Linux), making it ideal for ultra-minimalist, multi-megabyte Docker deployments.
* **Architecture:** Fully supported on x86_64 and ARM64 bare-metal servers.

## Security & Hardening

High performance is meaningless without enterprise-grade security. CWEB is hardened natively against common web vulnerabilities and denial-of-service attacks:

* **Strict Privilege Demotion:** The master process binds to the network port, forks its multi-core workers, and immediately drops privileges to the restricted `nobody` user. Even if an endpoint is compromised, the attacker cannot modify system files, alter database scripts, or deface HTML assets.
* **Kernel-Level Sandboxing (seccomp-bpf):** CWEB enforces a strict system call whitelist. If a remote code execution (RCE) vulnerability is somehow triggered within a developer's route, the kernel will instantly assassinate the worker process the moment it attempts to spawn a shell, `execve` a binary, or access unauthorized OS APIs.
* **Anti-Slowloris Protection:** Every `recv` operation in the event loop—including WebSocket tunnels—is securely bound to an `io_uring` linked timeout SQE. Malicious clients that hold connections open by trickling bytes are automatically severed by the kernel, guaranteeing the context pool is never exhausted.
* **Memory-Safe Parser:** The HTTP/1.1 parser operates entirely in-place (zero heap allocations). It strictly caps headers (`MAX_HEADERS_COUNT`) and validates syntax according to RFC 7230, neutralizing Hash Collision DoS and HTTP Request Smuggling attacks.

### Note on TLS / HTTPS
To maintain an absolutely minimal attack surface and eliminate dependency bloat (like OpenSSL runtime overhead), CWEB **does not** feature in-built TLS termination. For production environments, it is best practice to run CWEB strictly over HTTP bound to `localhost` (or a VPC subnet) and expose it to the internet using a **Cloudflare Tunnel** (`cloudflared`), which handles edge-side TLS encryption, WAF, and DDoS mitigation natively.
## Installation & Getting Started

### Prerequisites
- Linux Kernel 5.7 or newer (for `io_uring_prep_splice` support)
- GCC or Clang
- `liburing`
- `libpq` (PostgreSQL C Library)
- `libseccomp`

### Building the Framework

Clone the repository and build the shared library:
```bash
#In debian libpq-fe.h comes inside a postgresql directory which will cause compilation conflict
#run this symlink command first before compilation for no issues
ln -svf /usr/include/postgresql/* /usr/include/
make
sudo make install
make clean
```

### Writing Your First App

Create a file named `app.c`:

```c
#include <cweb.h>

HandlerState hello_world(CwebContext* ctx) {
    send_text(ctx, 200, "Hello, World!");
    return DB_DONE; // Signal that this request is fully complete
}

int main() {
    insert_route(GET, "/", hello_world);
    
    // Starts the io_uring engine and drops privileges
    return cweb_run_server(1234, NULL, 0);
}
```

Compile and run your application:
```bash
gcc app.c -lcweb -o app
sudo ./app
```
*(Note: `sudo` is required to drop privileges to the `nobody` user and configure kernel-level memory limits.)*

## Documentation

Full documentation on how to write route handlers, manage state machines (`handler_step`), establish WebSocket connections, and execute non-blocking PostgreSQL queries WILL be found in the `docs/` directory very soon.

## Benchmarking

The CWEB framework has been benchmark tested in several profiles under HTTP/1.1 and Websockets in HTTPArena. Cweb is currently one of the top 5 frameworks in websockets and top 30 in HTTP/1.1. PR link attached here. 

https://github.com/MDA2AV/HttpArena/pull/1682
