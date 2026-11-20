# Getting Started: The cweb.h Public Interface

To see a complete, production-grade web application built with CWEB, check out:
https://bitbucket.org/saadalabeed/cweb-blog/src/main/

---

## 1. Overview of cweb.h

`cweb.h` is the primary and sole public header file required to build applications with the CWEB framework. By design, CWEB maintains a clean separation between its internal execution engine and the developer-facing interface:

- **Encapsulated Engine Internals:** All low-level Linux kernel primitives—including raw `io_uring` submission and completion queues, file descriptor tables, memory-mapped rings, socket option configurations, privilege-demotion routines, and Seccomp-BPF filters—are encapsulated inside the precompiled `libcweb.so` shared library.
- **Developer Interface:** Including `cweb.h` provides complete access to high-level route definition, asynchronous state machine controls, HTTP parsing views, zero-copy response primitives, non-blocking PostgreSQL multiplexing, and in-place JSON manipulation.
- **Zero-Allocation Philosophy:** The types and macros exposed in `cweb.h` enforce a zero-allocation, pre-allocated memory model. Instead of dynamic heap allocations per request, the interface exposes fixed-size buffers, pooled contexts, and non-owning string views (`StringView`).

---

## 2. Engine Constants & Resource Limits

CWEB defines several compile-time capacity limits in `cweb.h`. These constants govern the pre-allocated memory pools established by each worker process during startup:

| Constant | Value | Description |
| :--- | :--- | :--- |
| `QUEUE_DEPTH` | `8192` | The depth of each worker's `io_uring` Submission and Completion Queue rings (must be a power of two). |
| `MAX_CLIENTS` | `4096` | The maximum number of concurrent client connections handled simultaneously by a single worker process context pool. |
| `BATCH_SIZE` | `512` | The maximum batch size of I/O events submitted to and harvested from `io_uring` in a single event loop iteration. |
| `MAX_BUFFER_SIZE` | `8192` | The fixed 8 KB memory buffer allocated per client context, utilized for in-place request parsing and HTTP response generation. |
| `MAX_PIPES` | `2048` | The total number of pre-allocated kernel pipe pairs per worker, dedicated to zero-copy `splice(2)` file streaming. |
| `MAX_PIPELINES` | `16` | The maximum number of middleware stages permitted in an execution pipeline for a given route. |
| `MAX_HEADERS_COUNT` | `64` | The maximum number of HTTP headers parsed from an incoming request. Enforces memory safety and mitigates Hash Collision DoS attacks. |
| `MAX_PATH_PARAMS` | `16` | The maximum number of dynamic path parameters (e.g. `:id`, `:slug`) that can be extracted from a single URI. |
| `DB_QUEUE_SIZE` | `4096` | The circular ring buffer capacity for queuing asynchronous PostgreSQL requests when database concurrency limits are reached. |
| `MAX_RADIX_NODES` | `2048` | The maximum node allocation limit for the routing Radix Tree across all HTTP methods. |
| `MAX_PATH_SEGMENT_LEN` | `128` | The maximum character length permitted for an individual URL path segment, preventing buffer overflow exploits during routing. |
| `MAX_MIDDLEWARES` | `8` | The maximum number of middlewares that can be assigned directly to an individual route node. |

---

## 3. Core Enumerations

### 3.1 HTTP Methods (`Method`)

CWEB indexes route handlers into nine independent Radix Trees corresponding to standard HTTP request methods:

- `GET`: Retrieve representations of resources without side effects.
- `POST`: Submit data payloads for server-side processing or resource creation.
- `PUT`: Replace or update an existing resource representation in full.
- `PATCH`: Apply partial modifications to a resource.
- `DELETE`: Remove a specified resource.
- `HEAD`: Retrieve status lines and header sections identical to GET, without the message body.
- `OPTIONS`: Query permitted communication options and HTTP methods for a URI.
- `TRACE`: Perform message loop-back tests along the request path.
- `CONNECT`: Establish two-way network tunnels (typically for HTTPS proxies).

### 3.2 Asynchronous State Machine (`HandlerState`)

Because CWEB operates asynchronously on an event loop without blocking threads, route handlers and middlewares do not return standard integers. Instead, they return a `HandlerState` that signals to the worker event loop how the connection state machine should transition:

- `DB_DONE`: Indicates that request processing has completely finished and the response headers/body are formulated in memory. The connection transitions to the write state to transmit data through `io_uring`.
- `DB_WAIT`: Indicates that the handler has dispatched an asynchronous PostgreSQL query. The worker suspends the connection, releases CPU execution back to the event loop, and awaits query completion from the database socket.
- `DB_QUEUED`: Indicates that the database connection pool is currently saturated, and the request has been placed into the internal FIFO ring buffer.
- `MW_NEXT`: Returned by a middleware handler to indicate that verification passed, directing the engine to proceed to the next middleware or final route handler in the pipeline.
- `MW_ABORT`: Returned by a middleware handler to halt the execution pipeline immediately (such as when an authentication token is invalid or missing), preventing downstream handlers from running.
- `UPLOAD_START`: Signals that an incoming request is initiating a zero-copy file upload, transitioning the connection into kernel `splice(2)` pipe streaming mode.

---

## 4. Fundamental Data Structures

### 4.1 `Header`

Represents a single parsed HTTP header line. It consists of two null-terminated string pointers (`name` and `value`) that point directly into the connection's pre-allocated memory buffer, avoiding intermediate heap allocations.

### 4.2 `StringView`

A non-owning string reference structure containing a pointer to the start of a character sequence (`char* str`) and its exact length (`int len`). `StringView` is used extensively for dynamic URL path parameters, allowing handlers to access URL tokens directly within the request URI without copying bytes or mutating source buffers.

### 4.3 `HttpRequest`

The core data structure representing a fully parsed HTTP/1.1 client request. It exposes:

- `method`: The parsed HTTP method enum.
- `path`: Null-terminated string pointing to the request URI path.
- `query_string`: Pointer to the URL query segment (the portion following `?`), or NULL if no query parameters were provided.
- `version`: Pointer to the HTTP version string (e.g. `"HTTP/1.1"`).
- `path_params`: An array of `StringView` elements containing any dynamic wildcard values extracted by the Radix Tree router.
- `num_params`: The total count of dynamic path parameters found in the URI.
- `headers`: An array of `Header` structures containing all parsed request headers.
- `num_headers`: The number of valid headers present in the headers array.
- `content_len`: The numeric value of the `Content-Length` header, representing the body size.
- `body`: Pointer to the beginning of the request payload in the connection buffer.
- `keep_alive`: Boolean flag indicating whether the client requested a persistent connection (`Connection: keep-alive`).

### 4.4 `CwebContext`

The public connection context structure passed to every route handler and middleware. It serves as the primary developer interface for inspecting request metadata, driving asynchronous state transitions, and formulating responses:

- `request`: The embedded `HttpRequest` structure containing all incoming client data.
- `db_result`: A pointer to a PostgreSQL `PGresult` structure populated upon the completion of asynchronous queries dispatched via `db_query()` or `db_query_rls()`.
- `handler_step`: An integer used to implement multi-step asynchronous database related handler state machines. When a handler yields with `DB_WAIT`, the developer must write handler_step = 1 before that, then CWEB re-invokes the handler with the updated `handler_step` upon database event completion to generate the response and send it.
- `file_fd`: The open file descriptor assigned for disk I/O during zero-copy `splice` operations.
- `file_offset`: The current byte offset for reading or writing during file transfers.
- `upload_remaining`: The remaining number of bytes left to stream during an active file upload.
- `upload_chunk_len`: The byte length of the current incoming data chunk.
- `upload_ptr`: Memory pointer tracking the current upload buffer location.
- `is_websocket`: Boolean flag indicating whether the connection has completed a WebSocket handshake and transitioned out of standard HTTP.
- `ws_payload`: Pointer to the payload of the most recently received WebSocket frame.
- `ws_opcode`: The numeric opcode of the received WebSocket frame (e.g. text or binary).

---

## 5. Routing and Middleware API

### 5.1 Function Pointer Types

- `RouteHandler`: Function pointer taking a `CwebContext*` and returning a `HandlerState`. Implements the terminal endpoint logic for a route.
- `MiddlewareHandler`: Function pointer taking a `CwebContext*` and returning a `HandlerState`. Implements pre-route validation, rate limiting, logging, or authentication checks.

### 5.2 Registration Functions

- `insert_route`: Installs a URL path and its associated `RouteHandler` into the Radix Tree corresponding to the specified `Method`. Supports static paths (`/items`) as well as dynamic wildcard segments (`/items/:id`). If route insertion fails due to capacity exhaustion or invalid syntax, the server logs an error and terminates before startup.
- `insert_middleware`: Binds a `MiddlewareHandler` to an HTTP method and path pattern. Middlewares assigned to a path will automatically execute in order before the terminal route handler is called.

---

## 6. Request Inspection & Response Generation API

### 6.1 Request Inspection

- `get_header`: Performs an in-place case-sensitive lookup across the parsed headers array for a specified header key and returns a pointer to its value string, or NULL if the header is not present.
- `get_query_param`: Searches the request query string for a specific key name and copies its decoded value into a provided destination buffer up to a specified maximum length. Returns 0 on success and -1 if the key was not found.

### 6.2 Outgoing Response Formulation

All response generation routines operate on the pre-allocated buffer of the connection context, guaranteeing that response formatting never triggers runtime heap allocation:

- `add_header`: Appends a custom HTTP header key-value pair to the pending response header list.
- `send_text`: Formats a standard HTTP response containing a status code, status reason phrase, `Content-Type: text/html` (or text/plain), `Content-Length`, custom headers, and the text body payload.
- `send_json`: Formats an HTTP response with `Content-Type: application/json`, matching headers, and the provided JSON string payload.
- `send_error`: Emits a standardized error response containing the specified HTTP status code and a human-readable plain text error message.
- `send_file`: Prepares a zero-copy static file response. It opens the target file on disk, retrieves its exact byte size via `fstat`, writes HTTP headers into memory, and primes the connection for kernel-space `splice(2)` transmission directly from the page cache to the client socket.

---

## 7. WebSocket Protocol API

- `upgrade_to_websocket`: Reads the client's `Sec-WebSocket-Key` header, computes the SHA-1/Base64 accept key in compliance with RFC 6455, formats an `HTTP/1.1 101 Switching Protocols` response, and flags the context as an active WebSocket connection.
- `send_ws_text`: Packages a text message inside an unmasked server WebSocket frame (opcode 0x1 with FIN bit set) and stages it for immediate transmission across the `io_uring` ring.

---

## 8. Relational Database & RLS API

CWEB integrates non-blocking PostgreSQL connectivity directly into the event loop via `libpq`:

- `RlsVariable`: A key-value struct representing PostgreSQL session configuration variables (e.g. setting `request.jwt.claim.user_id`).
- `db_query`: Dispatches an asynchronous parameterized SQL query with parameter binding. It immediately yields control with `DB_WAIT` while the query executes in the database background.
- `db_query_rls`: Dispatches an asynchronous query inside a transactional pipeline that dynamically assumes a specified database role (e.g. `authenticated` or `anon`) and injects an array of `RlsVariable` session parameters before executing the target SQL statement. This provides native Row-Level Security (RLS) tenant isolation.
- `queue_db_request`: Places a connection context into the circular database wait queue when all active database connections are busy, guaranteeing that client requests are not dropped during database spikes.

---

## 9. JSON Builder & Parser API

To maintain high performance without linking heavy third-party JSON libraries, `cweb.h` provides an in-place, zero-allocation JSON streaming builder and tokenizer:

### 9.1 `JsonBuilder`
A lightweight tracking structure containing a target memory buffer pointer, remaining capacity counter, and a boolean separator state.

- `json_begin`: Initializes a `JsonBuilder` instance across a pre-allocated character buffer and emits the opening object bracket (`{`).
- `json_add_str`: Appends an escaped string key-value pair to the active JSON object.
- `json_add_int`: Appends an integer key-value pair to the active JSON object.
- `json_add_bool`: Appends a boolean key-value pair (`true` or `false`) to the active JSON object.
- `json_end`: Emits the closing object bracket (`}`) and null-terminates the formatted JSON string.

### 9.2 In-Place JSON Token Extraction
- `json_extract_str`: Scans an input JSON string for a given key and extracts its string value into an output buffer.
- `json_extract_int`: Scans an input JSON string for a given key and parses its numerical value into a 64-bit integer.
- `json_extract_bool`: Scans an input JSON string for a given key and parses its boolean state.
- `json_escape_string`: Sanitizes string characters according to RFC 8259, converting quotes, control characters, and backslashes into valid JSON escape sequences.
- `json_unescape_string`: Reverses escape sequences within a string in-place.

---

## 10. Server Lifecycle API

### The Server Runner: `cweb_run_server(port, db_url, db_conns_per_cpu_core)`

The master entrypoint function that transitions the application from configuration to execution:

- **Port Binding:** Configures a TCP socket on the specified port with `SO_REUSEPORT` enabled.
- **Resource Configuration:** Automatically configures process limits (`RLIMIT_NOFILE` and `RLIMIT_MEMLOCK`) required for unprivileged `io_uring` ring creation.
- **Multi-Process Forking:** Detects the host's physical CPU core count and forks dedicated worker processes per core.
- **Privilege Separation:** Automatically demotes worker process credentials to the unprivileged `nobody:nobody` user.
- **Sandboxing:** Engages Seccomp-BPF system call filtering on all workers before accepting network traffic.
- **Event Loop Execution:** Initializes `io_uring` rings, allocates context and pipe pools, connects to PostgreSQL (if `db_url` is non-NULL), and runs the asynchronous request processing loop until termination signals are received.
- **System Daemonization:** You can daemonize the server and run it in the background, having logs in dedicated files and quick restart feature upon any accidental crash.
