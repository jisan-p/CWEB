#include "../include/server.h"
#include "../include/pool.h"
#include "../include/router.h"
#include "../include/database.h"
#include "../include/security.h"
#include <stdio.h>

static volatile int is_running = 1;
static struct io_uring ring;
static struct io_uring_params params;

static struct __kernel_timespec slowloris_ts = { .tv_sec = 5, .tv_nsec = 0 }; // slowloris DDOS protection

static void handle_sig(int sig) {
    (void)sig;
    is_running = 0;
}

static void die(const char* msg) {
    int err = errno;
    fprintf(stderr, "[%d] %s\n", err, msg);
    exit(1);
}

static void set_non_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    flags |= O_NONBLOCK;
    fcntl(fd, F_SETFL, flags);
}

static inline uint64_t pack_ctx_data(const ConnContext *ctx) {
    if (!ctx) return 0ULL;
    return ((uint64_t)ctx->generation << 32) | (uint64_t)ctx->pool_idx;
}

static inline ConnContext* unpack_ctx_data(uint64_t user_data) {
    if (user_data == 0ULL) return NULL; // Timeout CQE (generation 0 is reserved)
    uint32_t idx = (uint32_t)(user_data & 0xFFFFFFFFULL);
    uint32_t gen = (uint32_t)(user_data >> 32);

    ConnContext *ctx = get_context_by_index(idx);
    if (!ctx || !ctx->in_use || ctx->generation != gen) {
        return NULL; // Stale CQE from a released or reused connection!
    }
    return ctx;
}

static inline void set_sqe_ctx(struct io_uring_sqe* sqe, const ConnContext* ctx) {
    io_uring_sqe_set_data64(sqe, ctx ? pack_ctx_data(ctx) : 0ULL);
}

static int ensure_sqe_space(struct io_uring *ring, unsigned int needed) {
    if (io_uring_sq_space_left(ring) < needed) {
        int ret = io_uring_submit(ring);
        if (ret < 0 && ret != -EBUSY) {
            fprintf(stderr, "io_uring_submit() failed: %s\n", strerror(-ret));
        }
    }
    return (io_uring_sq_space_left(ring) >= needed) ? 0 : -1;
}

static struct io_uring_sqe* get_sqe_safe(struct io_uring *ring) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe) {
        io_uring_submit(ring);
        sqe = io_uring_get_sqe(ring);
        if (!sqe) {
            fprintf(stderr, "CRITICAL: io_uring SQ ring exhausted after submit\n");
            return NULL;
        }
    }
    return sqe;
}

static void close_and_release_ctx(struct io_uring* ring, ConnContext* ctx) {
    if (!ctx || !ctx->in_use || ctx->state == ACCEPT) return; // guards server_ctx

    // close any opened file
    if (ctx->pub.file_fd >= 0) {
        close(ctx->pub.file_fd);
        ctx->pub.file_fd = -1; // hard reset
    }

    // sanitize and return pipes
    if (ctx->pipe_fd) {
        if (ctx->pipe_bytes > 0) {
            // drain the pipe
            close(ctx->pipe_fd->fds[0]);
            close(ctx->pipe_fd->fds[1]);
            if (pipe2(ctx->pipe_fd->fds, O_NONBLOCK | O_CLOEXEC) < 0) {
                ctx->pipe_fd->fds[0] = -1;
                ctx->pipe_fd->fds[1] = -1;
            }
            ctx->pipe_bytes = 0;
        }
        release_pipe(ctx->pipe_fd);
        ctx->pipe_fd = NULL;
    }

    // free db result
    if (ctx->pub.db_result) {
        PQclear(ctx->pub.db_result);
        ctx->pub.db_result = NULL;
    }

    // return db_conn and wake queued context
    if (ctx->db_conn) {
        ConnContext* queued_ctx = release_db_conn(ctx->db_conn);
        ctx->db_conn = NULL;

        if (queued_ctx && queued_ctx->in_use) {
            queued_ctx->state = RESUME;
            struct io_uring_sqe* nop_sqe = get_sqe_safe(ring);
            if (nop_sqe) {
                io_uring_prep_nop(nop_sqe);
                set_sqe_ctx(nop_sqe, queued_ctx);
            }
        }
    }

    // close client socket and release context to pool
    if (ctx->fd >= 0) {
        close(ctx->fd);
        ctx->fd = -1; // hard reset
    }
    release_context(ctx);
}

static int prep_linked_recv(struct io_uring *ring, ConnContext *ctx, void *buf, size_t len) {
    if (ensure_sqe_space(ring, 2) == -1) {
        close_and_release_ctx(ring, ctx);
        return -1;
    }
    struct io_uring_sqe *read_sqe = get_sqe_safe(ring);
    struct io_uring_sqe *timeout_sqe = get_sqe_safe(ring);
    if (!read_sqe || !timeout_sqe) return -1;

    io_uring_prep_recv(read_sqe, ctx->fd, buf, len, 0);
    read_sqe->flags |= IOSQE_IO_LINK;
    set_sqe_ctx(read_sqe, ctx);

    io_uring_prep_link_timeout(timeout_sqe, &slowloris_ts, 0);
    set_sqe_ctx(timeout_sqe, NULL);
    return 0;
}

static int prep_linked_splice(struct io_uring *ring, ConnContext *ctx,
                                int fd_in, int64_t off_in,
                                int fd_out, int64_t off_out,
                                unsigned int nbytes, unsigned int splice_flags) {
    if (ensure_sqe_space(ring, 2) == -1) {
        close_and_release_ctx(ring, ctx);
        return -1;
    }
    struct io_uring_sqe *sqe = get_sqe_safe(ring);
    struct io_uring_sqe *timeout_sqe = get_sqe_safe(ring);
    if (!sqe || !timeout_sqe) return -1;

    io_uring_prep_splice(sqe, fd_in, off_in, fd_out, off_out, nbytes, splice_flags);
    sqe->flags |= IOSQE_IO_LINK;
    set_sqe_ctx(sqe, ctx);

    io_uring_prep_link_timeout(timeout_sqe, &slowloris_ts, 0);
    set_sqe_ctx(timeout_sqe, NULL);
    return 0;
}

HandlerState execute_pipeline(ConnContext* ctx) {
    while (ctx->pipeline_index < ctx->pipeline_count) { // call all middleware functions first
        HandlerState status;
        status = ctx->pipeline[ctx->pipeline_index]((CwebContext *)ctx);

        if (status == MW_NEXT) {
            ctx->pipeline_index++;
            ctx->pub.handler_step = 0; // each new middleware function call has a fresh state machine
            continue;
        }
        else if (status == DB_WAIT) return DB_WAIT; // if middleware queries database and has to wait, must wait
        else if (status == DB_QUEUED) return DB_QUEUED; // if middleware query is queued
        else if (status == MW_ABORT) return DB_DONE; // middleware rejected the request and already wrote the http message accordingly
        else if (status == DB_DONE) return DB_DONE; // MW_ABORT, DB_DONE both exits the pipeline
        else { // fallback
            fprintf(stderr, "Middleware returned something unrecognizable\n");
            send_error((CwebContext *)ctx, 500, "Middleware Error");
            return DB_DONE; // break pipeline
        }
    }
    return ctx->handler((CwebContext *)ctx); // all middlewares done executing, execute the main routehandler now
}

int run_server_loop(struct io_uring *ring, int server_fd) {
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    // bootstraping
    struct io_uring_sqe *sqe = get_sqe_safe(ring);
    if (!sqe) return -1;
    ConnContext *server_ctx = acquire_context(server_fd, ACCEPT);
    if (!server_ctx) return -1;

    io_uring_prep_accept(sqe, server_fd, (struct sockaddr*)&client_addr, &client_addr_len, 0);
    set_sqe_ctx(sqe, server_ctx);
    io_uring_submit(ring);

    EventTask batch[BATCH_SIZE];

    // event loop
    while (is_running) {
        // wait for at least 1 event, while submitting any pending SQEs
        int err = io_uring_submit_and_wait(ring, 1);
        if (err < 0) {
            if (err == -EINTR) continue; // SIGINT/SIGTERM caught! Re-checks `is_running` and exits cleanly.
            fprintf(stderr, "io_uring_submit_and_wait() failed: %s\n", strerror(-err));
            break;
        }

        struct io_uring_cqe *cqe;
        unsigned head;
        int count = 0;

        // drain BATCH_SIZE events instantly
        io_uring_for_each_cqe(ring, head, cqe) {
            batch[count].user_data = io_uring_cqe_get_data64(cqe);
            batch[count].res = cqe->res;
            count++;

            if (count == BATCH_SIZE) break;
        }

        // cqe's should be immune to backpressure now
        io_uring_cq_advance(ring, count);

        // process BATCH_SIZE amount of events at own pace now
        for (int i = 0; i < count; i++) {
            ConnContext* ctx = unpack_ctx_data(batch[i].user_data);
            int res = batch[i].res;

            if (!ctx) continue; // timeout CQE

            if (res < 0) {
                // FIX: never close server_fd and release server_ctx
                if (ctx->state == ACCEPT) {
                    if (res != -EAGAIN && res != -EINTR && res != -ECONNABORTED) {
                        fprintf(stderr, "accept() failed: %s\n", strerror(-res));
                    }
                    client_addr_len = sizeof(client_addr);
                    struct io_uring_sqe* retry_accept = get_sqe_safe(ring);
                    if (!retry_accept) {
                        continue;
                    }
                    io_uring_prep_accept(retry_accept, server_fd, (struct sockaddr*)&client_addr, &client_addr_len, 0);
                    set_sqe_ctx(retry_accept, ctx);
                    continue;
                }

                if (res != -ECANCELED && res != -ETIME && res != -ECONNRESET && res != -EPIPE) {
                    fprintf(stderr, "Async operation failed for state %d: %s\n", ctx->state, strerror(-res));
                }
                close_and_release_ctx(ring, ctx);
                continue;
            }

            // Routing the State
            switch (ctx->state) {

                case ACCEPT: {
                    // res contains the new client socket file descriptor
                    int client_fd = res;
                    // printf("New client connected: fd %d\n", client_fd);

                    // A: Immediately prepare a new accept operation for the next client
                    struct io_uring_sqe *new_accept_sqe = get_sqe_safe(ring);
                    if (!new_accept_sqe) {
                        close(client_fd);
                        break;
                    }
                    client_addr_len = sizeof(client_addr); // hard reset as kernel mutates it
                    io_uring_prep_accept(new_accept_sqe, server_fd, (struct sockaddr*)&client_addr, &client_addr_len, 0);
                    // Reuse the listening socket context for the next accept
                    set_sqe_ctx(new_accept_sqe, ctx);

                    // B: Prepare a recv operation for this new client
                    ConnContext *read_ctx = acquire_context(client_fd, READ);
                    if (!read_ctx) { // drop connection
                        printf("Context pool is filled, dropping client fd %d\n", client_fd);
                        close(client_fd);
                        break;
                    }

                    prep_linked_recv(ring, read_ctx, read_ctx->buffer, MAX_BUFFER_SIZE - 1);
                    break;
                }

                case READ: {
                    if (ctx->ws_from_nop) {
                        ctx->ws_from_nop = false;
                    }
                    else if (res == 0) {
                        close_and_release_ctx(ring, ctx);
                        break;
                    }
                    else {
                        ctx->bytes_read += (size_t)res;
                    }

                    char *data = ctx->buffer;
                    data[ctx->bytes_read] = '\0'; // Null-terminating the data [CRITICAL]

                    ssize_t total_expected = scan_buffer(ctx->buffer);

                    if (total_expected == -1) {
                        if (ctx->bytes_read >= MAX_BUFFER_SIZE - 1) {
                            char* response = "HTTP/1.1 431 Payload Too Large\r\nContent-Length: 0\r\n\r\n";
                            ctx->state = WRITE;
                            ctx->pub.request.keep_alive = false;
                            struct io_uring_sqe *write_sqe = get_sqe_safe(ring);
                            if (!write_sqe) {
                                close_and_release_ctx(ring, ctx);
                                break;
                            }
                            io_uring_prep_send(write_sqe, ctx->fd, response, strlen(response), 0);
                            set_sqe_ctx(write_sqe, ctx);
                            break;
                        }
                    }

                    if (total_expected == -1 || ctx->bytes_read < (size_t)total_expected) {
                        char* more = ctx->buffer + ctx->bytes_read;
                        size_t available_space = MAX_BUFFER_SIZE - ctx->bytes_read - 1;
                        prep_linked_recv(ring, ctx, more, available_space);
                        break;
                    }

                    ctx->current_req_len = (size_t)total_expected;

                    err = parse(ctx->buffer, &ctx->pub.request, ctx->current_req_len);
                    if (err == -1) {
                        printf("Bad request from fd %d\n", ctx->fd);
                        close_and_release_ctx(ring, ctx);
                        break;
                    }

                    if (!ctx->pub.request.body ||
                        (size_t)(ctx->pub.request.body - ctx->buffer) + ctx->pub.request.content_len <= ctx->bytes_read) {
                        ctx->ws_saved_byte = (uint8_t)ctx->buffer[ctx->current_req_len];
                    ctx->buffer[ctx->current_req_len] = '\0';
                        }

                        if (ctx->pub.request.method == OPTIONS) {
                            add_header((CwebContext *)ctx, "Access-Control-Allow-Origin", "*");
                            add_header((CwebContext *)ctx, "Access-Control-Allow-Methods", "GET, POST, PATCH, PUT, DELETE, OPTIONS");
                            add_header((CwebContext *)ctx, "Access-Control-Allow-Headers", "Content-Type, Authorization");

                            send_text((CwebContext *)ctx, 204, "");
                            ctx->state = WRITE;
                            struct io_uring_sqe *write_sqe = get_sqe_safe(ring);
                            if (!write_sqe) {
                                close_and_release_ctx(ring, ctx);
                                break;
                            }
                            io_uring_prep_send(write_sqe, ctx->fd, ctx->response_ptr, ctx->response_len, 0);
                            set_sqe_ctx(write_sqe, ctx);
                            continue;
                        }

                        ctx->handler = search_route(ctx->pub.request.method, ctx->pub.request.path, ctx);
                        if (!ctx->handler) {
                            char* response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
                            ctx->state = WRITE;
                            struct io_uring_sqe *write_sqe = get_sqe_safe(ring);
                            if (!write_sqe) {
                                close_and_release_ctx(ring, ctx);
                                break;
                            }
                            io_uring_prep_send(write_sqe, ctx->fd, response, strlen(response), 0);
                            set_sqe_ctx(write_sqe, ctx);
                            break;
                        }

                        ctx->state = WRITE;
                        HandlerState status = execute_pipeline(ctx);

                        if (status != UPLOAD_START && ctx->pub.request.body &&
                            ctx->bytes_read < (size_t)(ctx->pub.request.body - ctx->buffer) + ctx->pub.request.content_len) {
                            ctx->pub.request.keep_alive = false;
                            }

                            if (status == UPLOAD_START) {
                                if (ctx->pub.file_fd < 0) {
                                    close_and_release_ctx(ring, ctx);
                                    break;
                                }
                                if (ctx->pub.upload_remaining == 0 || ctx->pub.upload_remaining > ctx->pub.request.content_len) {
                                    ctx->pub.upload_remaining = ctx->pub.request.content_len;
                                }
                                ctx->pub.upload_chunk_len = 0;
                                ctx->pub.upload_ptr = NULL;

                                if (ctx->pub.request.body) {
                                    size_t body_offset = (size_t)(ctx->pub.request.body - ctx->buffer);
                                    if (ctx->bytes_read > body_offset) {
                                        size_t available_in_buf = ctx->bytes_read - body_offset;
                                        if (available_in_buf > ctx->pub.upload_remaining) {
                                            ctx->pub.upload_chunk_len = ctx->pub.upload_remaining;
                                            ctx->pub.request.keep_alive = false;
                                        } else {
                                            ctx->pub.upload_chunk_len = available_in_buf;
                                        }
                                        ctx->pub.upload_ptr = ctx->pub.request.body;
                                    }
                                }

                                if (ctx->pub.upload_remaining == 0) {
                                    close(ctx->pub.file_fd);
                                    ctx->pub.file_fd = -1;
                                    ctx->bytes_read = 0;
                                    if (ctx->pub.handler_step == 1) {
                                        char size_str[32];
                                        snprintf(size_str, sizeof(size_str), "%lld", (long long)ctx->pub.file_offset);
                                        send_text((CwebContext *)ctx, 200, size_str);
                                    } else {
                                        send_text((CwebContext *)ctx, 200, "Upload complete");
                                    }
                                    ctx->state = WRITE;
                                    struct io_uring_sqe* write_sqe = get_sqe_safe(ring);
                                    if (!write_sqe) {
                                        close_and_release_ctx(ring, ctx);
                                        break;
                                    }
                                    io_uring_prep_send(write_sqe, ctx->fd, ctx->response_ptr, ctx->response_len, 0);
                                    set_sqe_ctx(write_sqe, ctx);
                                }
                                else if (ctx->pub.upload_chunk_len > 0) {
                                    ctx->state = UPLOAD_WRITE;
                                    struct io_uring_sqe* write_sqe = get_sqe_safe(ring);
                                    if (!write_sqe) {
                                        close_and_release_ctx(ring, ctx);
                                        break;
                                    }
                                    io_uring_prep_write(write_sqe, ctx->pub.file_fd, ctx->pub.upload_ptr, ctx->pub.upload_chunk_len, (ctx->pub.handler_step == 1) ? 0 : ctx->pub.file_offset);
                                    set_sqe_ctx(write_sqe, ctx);
                                }
                                else if (ctx->pub.upload_chunk_len == 0 && ctx->pub.upload_remaining > 0) {
                                    ctx->state = UPLOAD_SPLICE_IN;
                                    ctx->pipe_fd = acquire_pipe();
                                    if (!ctx->pipe_fd) { close_and_release_ctx(ring, ctx); break; }
                                    size_t to_splice = (ctx->pub.upload_remaining > MAX_BUFFER_SIZE) ? MAX_BUFFER_SIZE : ctx->pub.upload_remaining;
                                    prep_linked_splice(ring, ctx, ctx->fd, -1, ctx->pipe_fd->fds[1], -1, to_splice, 0);
                                }
                                break;
                            }

                            if (status == DB_WAIT) {
                                ctx->state = WAIT;
                                int pg_fd = PQsocket(ctx->db_conn);
                                struct io_uring_sqe *sqe = get_sqe_safe(ring);
                                if (!sqe) {
                                    close_and_release_ctx(ring, ctx);
                                    break;
                                }
                                io_uring_prep_poll_add(sqe, pg_fd, POLLIN);
                                set_sqe_ctx(sqe, ctx);
                                break;
                            }
                            else if (status == DB_QUEUED) {
                                ctx->state = QUEUED;
                                break;
                            }

                            // FAST-PATH BATCHING FOR PIPELINED SYNCHRONOUS HTTP/1.1 REQUESTS:
                            // If more pipelined requests are already in ctx->buffer and this was a synchronous
                            // response (no file splice, no websocket upgrade), batch all ready responses into
                            // a single contiguous send buffer!
                            if (ctx->pub.request.keep_alive &&
                                ctx->pub.file_fd == -1 &&
                                !ctx->pub.is_websocket &&
                                ctx->bytes_read > ctx->current_req_len &&
                                ctx->response_ptr > ctx->buffer) {

                                char *batch_start = ctx->response_ptr;
                            size_t batch_len  = ctx->response_len;
                            size_t req_offset = 0;

                            while (ctx->pub.request.keep_alive && ctx->bytes_read > req_offset + ctx->current_req_len) {
                                // Restore clobbered byte at boundary of next request
                                ctx->buffer[req_offset + ctx->current_req_len] = (char)ctx->ws_saved_byte;
                                req_offset += ctx->current_req_len;

                                char *next_req = ctx->buffer + req_offset;
                                size_t unread  = ctx->bytes_read - req_offset;

                                // Temporarily null-terminate end of unread input for scan_buffer
                                char saved_end = ctx->buffer[ctx->bytes_read];
                                ctx->buffer[ctx->bytes_read] = '\0';
                                ssize_t next_expected = scan_buffer(next_req);
                                ctx->buffer[ctx->bytes_read] = saved_end;

                                if (next_expected <= 0 || unread < (size_t)next_expected) {
                                    break; // Partial trailing request; will be shifted in WRITE
                                }

                                // Ensure enough space after batch_start + batch_len for next response
                                char *next_out_start = batch_start + batch_len;
                                if ((size_t)(next_out_start - ctx->buffer) + 512 >= MAX_BUFFER_SIZE) {
                                    break;
                                }

                                // Trick init_http_response_buf into writing right at next_out_start!
                                size_t saved_bytes_read = ctx->bytes_read;
                                ctx->current_req_len = (size_t)next_expected;

                                memset(&ctx->pub.request, 0, sizeof(HttpRequest));
                                ctx->res_header_count = 0;
                                ctx->pipeline_count   = 0;
                                ctx->pipeline_index   = 0;
                                ctx->pub.handler_step = 0;

                                if (parse(next_req, &ctx->pub.request, (size_t)next_expected) == -1) {
                                    ctx->bytes_read = saved_bytes_read;
                                    break;
                                }

                                ctx->ws_saved_byte = (uint8_t)next_req[next_expected];
                                next_req[next_expected] = '\0';

                                RouteHandler next_h = search_route(ctx->pub.request.method, ctx->pub.request.path, ctx);
                                if (!next_h) {
                                    next_req[next_expected] = (char)ctx->ws_saved_byte;
                                    ctx->bytes_read = saved_bytes_read;
                                    break;
                                }
                                ctx->handler = next_h;

                                // Set ctx->bytes_read temporarily so init_http_response_buf's (bytes_read + 1)
                                // points exactly to next_out_start!
                                ctx->bytes_read = (size_t)(next_out_start - ctx->buffer) - 1;
                                ctx->current_req_len = 1;

                                HandlerState st = execute_pipeline(ctx);
                                ctx->bytes_read = saved_bytes_read;
                                ctx->current_req_len = (size_t)next_expected;

                                if (st != DB_DONE || ctx->pub.file_fd != -1 || ctx->pub.is_websocket) {
                                    break;
                                }

                                batch_len += ctx->response_len;
                            }

                            // Total bytes consumed across all batched requests in this pass:
                            ctx->current_req_len += req_offset;
                            ctx->response_ptr = batch_start;
                            ctx->response_len = batch_len;
                                }

                                // Prepare the send operation (DB_DONE)
                                ctx->state = WRITE;
                                struct io_uring_sqe *write_sqe = get_sqe_safe(ring);
                                if (!write_sqe) {
                                    close_and_release_ctx(ring, ctx);
                                    break;
                                }
                                io_uring_prep_send(write_sqe, ctx->fd, ctx->response_ptr, ctx->response_len, 0);
                                set_sqe_ctx(write_sqe, ctx);
                                break;
                }

                case WAIT: {
                    // Read the raw bytes from the Postgres socket into libpq's internal buffer
                    if (PQconsumeInput(ctx->db_conn) == 0) {
                        fprintf(stderr, "PQconsumeInput failed: %s\n", PQerrorMessage(ctx->db_conn));
                        close_and_release_ctx(ring, ctx);
                        break;
                    }

                    // Check if the entire result has arrived
                    if (PQisBusy(ctx->db_conn)) {
                        // Not finished yet! Re-arm the poll and go back to sleep.
                        struct io_uring_sqe *sqe = get_sqe_safe(ring);
                        if (!sqe) {
                            close_and_release_ctx(ring, ctx);
                            break;
                        }
                        io_uring_prep_poll_add(sqe, PQsocket(ctx->db_conn), POLLIN);
                        set_sqe_ctx(sqe, ctx);
                        break;
                    }

                    // pipeline extractor
                    if (ctx->pub.db_result) PQclear(ctx->pub.db_result);
                    ctx->pub.db_result = NULL;
                    PGresult *res;

                    while (1) {
                        res = PQgetResult(ctx->db_conn);

                        if (!res) {
                            // In pipeline mode, NULL separates queries.
                            // If we have fully exited the pipeline, NULL means we are done!
                            if (PQpipelineStatus(ctx->db_conn) == PQ_PIPELINE_OFF) break;
                            continue;
                        }

                        ExecStatusType status = PQresultStatus(res);

                        if (status == PGRES_PIPELINE_SYNC) {
                            // The batch has finished processing
                            PQclear(res);
                            PQexitPipelineMode(ctx->db_conn); // This turns the pipeline OFF
                            continue;
                        }

                        // Explicitly ignore the RLS wrappers!
                        const char *cmd = PQcmdStatus(res);
                        if (cmd && (!strcmp(cmd, "BEGIN") || !strcmp(cmd, "COMMIT"))) {
                            PQclear(res);
                            continue;
                        }

                        // Keep the actual data (or a fatal error), discard the pipeline query messages
                        if (status == PGRES_TUPLES_OK || status == PGRES_FATAL_ERROR || status == PGRES_COMMAND_OK) {
                            if (ctx->pub.db_result) PQclear(ctx->pub.db_result); // Free previous just in case
                            ctx->pub.db_result = res;
                        }
                        else {
                            PQclear(res);
                        }
                    }

                    // RE-CALL THE pipeline executor! It will resume at case 1:
                    HandlerState status = execute_pipeline(ctx);

                    if (status == DB_WAIT) {
                        ctx->state = WAIT;
                        struct io_uring_sqe *sqe = get_sqe_safe(ring);
                        if (!sqe) {
                            close_and_release_ctx(ring, ctx);
                            break;
                        }
                        io_uring_prep_poll_add(sqe, PQsocket(ctx->db_conn), POLLIN);
                        set_sqe_ctx(sqe, ctx);
                        break;
                    }
                    else if (status == DB_QUEUED) {
                        ctx->state = QUEUED;
                        break;
                    }
                    else if (status == DB_DONE) {
                        if (ctx->pub.db_result) {
                            PQclear(ctx->pub.db_result);
                            ctx->pub.db_result = NULL;
                        }
                        if (ctx->db_conn) {
                            ConnContext* queued_ctx = release_db_conn(ctx->db_conn);
                            ctx->db_conn = NULL;
                            if (queued_ctx && queued_ctx->in_use) {
                                queued_ctx->state = RESUME;
                                struct io_uring_sqe *nop_sqe = get_sqe_safe(ring);
                                if (nop_sqe) {
                                    io_uring_prep_nop(nop_sqe);
                                    set_sqe_ctx(nop_sqe, queued_ctx);
                                }
                            }
                        }
                        if (ctx->pub.request.body && ctx->bytes_read < (size_t)(ctx->pub.request.body - ctx->buffer) + ctx->pub.request.content_len) {
                            ctx->pub.request.keep_alive = false;
                        }
                        ctx->state = WRITE;
                        struct io_uring_sqe *write_sqe = get_sqe_safe(ring);
                        if (!write_sqe) {
                            close_and_release_ctx(ring, ctx);
                            break;
                        }
                        io_uring_prep_send(write_sqe, ctx->fd, ctx->response_ptr, ctx->response_len, 0);
                        set_sqe_ctx(write_sqe, ctx);
                    }
                    break;
                }

                case WRITE: {
                    if (res <= 0) {
                        close_and_release_ctx(ring, ctx);
                        break;
                    }

                    // Handle partial network sends
                    if (res > 0 && (size_t)res < ctx->response_len) {
                        ctx->response_ptr += res;
                        ctx->response_len -= res;

                        struct io_uring_sqe *write_sqe = get_sqe_safe(ring);
                        if (!write_sqe) {
                            close_and_release_ctx(ring, ctx);
                            break;
                        }
                        io_uring_prep_send(write_sqe, ctx->fd, ctx->response_ptr, ctx->response_len, 0);
                        set_sqe_ctx(write_sqe, ctx);
                        break; // Return to event loop to wait for the rest
                    }

                    // HTTP headers were successfully sent.
                    ctx->response_ptr = NULL;
                    ctx->response_len = 0;

                    if (ctx->pub.file_fd != -1) {
                        // We have a file to send!
                        ctx->state = SPLICE_IN;
                        // acquire a pipe
                        ctx->pipe_fd = acquire_pipe();
                        if (!ctx->pipe_fd) { close_and_release_ctx(ring, ctx); break; } // drop connection
                        struct io_uring_sqe *sqe = get_sqe_safe(ring);
                        if (!sqe) {
                            close_and_release_ctx(ring, ctx);
                            break;
                        }
                        // Splice from File to Pipe-Write
                        io_uring_prep_splice(sqe, ctx->pub.file_fd, ctx->pub.file_offset, ctx->pipe_fd->fds[1], -1, ctx->file_size - (size_t)ctx->pub.file_offset, SPLICE_F_MOVE);
                        set_sqe_ctx(sqe, ctx);
                        break;
                    }

                    // check for websocket
                    if (ctx->pub.is_websocket) {
                        if (ctx->ws_frame_len == 0) {
                            // Initial 101 Switching Protocols handshake just completed!
                            ctx->state = WS_READ;
                            ctx->bytes_read = 0;
                            prep_linked_recv(ring, ctx, ctx->buffer, MAX_BUFFER_SIZE - 1);
                            break;
                        }

                        // Restore the byte clobbered by '\0'
                        ctx->buffer[ctx->ws_frame_len] = (char)ctx->ws_saved_byte;

                        size_t consumed = ctx->ws_frame_len;
                        size_t remaining = (ctx->bytes_read > consumed) ? (ctx->bytes_read - consumed) : 0;

                        if (remaining > 0) {
                            memmove(ctx->buffer, ctx->buffer + consumed, remaining);
                        }
                        ctx->bytes_read = remaining;
                        ctx->ws_frame_len = 0;
                        ctx->pub.ws_payload = NULL;
                        ctx->pub.ws_payload_len = 0;
                        ctx->state = WS_READ;

                        if (remaining > 0) {
                            // Pass res = 0 to NOP, so WS_READ doesn't add to bytes_read
                            ctx->ws_from_nop = true; // WS_READ helper
                            struct io_uring_sqe *nop_sqe = get_sqe_safe(ring);
                            if (!nop_sqe) { close_and_release_ctx(ring, ctx); break; }
                            io_uring_prep_nop(nop_sqe);
                            set_sqe_ctx(nop_sqe, ctx);
                        }
                        else {
                            prep_linked_recv(ring, ctx, ctx->buffer, MAX_BUFFER_SIZE - 1);
                        }
                        break;
                    }

                    // if (ctx->pub.request.keep_alive) {
                    //     // Wipe the slate clean for the next request on this exact same socket
                    //
                    //     ctx->state = READ;
                    //     reset_context(ctx);
                    //
                    //     // Tell io_uring to wait for the browser's next message!
                    //     prep_linked_recv(ring, ctx, ctx->buffer, MAX_BUFFER_SIZE - 1);
                    // }
                    if (ctx->pub.request.keep_alive) {
                        size_t consumed = ctx->current_req_len;
                        size_t remaining = (consumed > 0 && ctx->bytes_read > consumed) ? (ctx->bytes_read - consumed) : 0;

                        if (remaining > 0) {
                            // Restore first byte of the next pipelined request if clobbered by body '\0'
                            ctx->buffer[consumed] = (char)ctx->ws_saved_byte;
                            memmove(ctx->buffer, ctx->buffer + consumed, remaining);
                        }

                        ctx->state = READ;
                        reset_context(ctx);
                        ctx->bytes_read = remaining;

                        if (remaining > 0) {
                            // Next pipelined request is already in RAM! Trigger READ immediately via NOP
                            ctx->ws_from_nop = true;
                            struct io_uring_sqe *nop_sqe = get_sqe_safe(ring);
                            if (!nop_sqe) {
                                close_and_release_ctx(ring, ctx);
                                break;
                            }
                            io_uring_prep_nop(nop_sqe);
                            set_sqe_ctx(nop_sqe, ctx);
                        }
                        else {
                            // Buffer is empty; wait for the client's next TCP packet
                            prep_linked_recv(ring, ctx, ctx->buffer, MAX_BUFFER_SIZE - 1);
                        }
                    }
                    else {
                        // The browser is done
                        close_and_release_ctx(ring, ctx);
                    }
                    break;
                }

                case SPLICE_IN: {
                    if (res <= 0) {
                        close_and_release_ctx(ring, ctx);
                        break;
                    }

                    // update the file_offset
                    ctx->pub.file_offset += (off_t)res; // NULL (old debian) vs dangling (modern arch) pointer found during backward compatibility
                    // track how many bytes kernel dumped into the pipe
                    ctx->pipe_bytes = res;
                    ctx->state = SPLICE_OUT;
                    struct io_uring_sqe *sqe = get_sqe_safe(ring);
                    if (!sqe) {
                        close_and_release_ctx(ring, ctx);
                        break;
                    }
                    // Splice from Pipe-Read to Socket
                    io_uring_prep_splice(sqe, ctx->pipe_fd->fds[0], -1, ctx->fd, -1, ctx->pipe_bytes, SPLICE_F_MOVE);
                    set_sqe_ctx(sqe, ctx);
                    break;
                }

                case SPLICE_OUT: {
                    if (res <= 0) {
                        close_and_release_ctx(ring, ctx);
                        break;
                    }

                    // Deduct what was actually written to the socket
                    ctx->pipe_bytes -= res;

                    if (ctx->pipe_bytes > 0) {
                        // Partial network write! The pipe still has data.
                        // Re-submit SPLICE_OUT for the remaining bytes in the pipe.
                        struct io_uring_sqe *sqe = get_sqe_safe(ring);
                        if (!sqe) {
                            close_and_release_ctx(ring, ctx);
                            break;
                        }
                        io_uring_prep_splice(sqe, ctx->pipe_fd->fds[0], -1, ctx->fd, -1, ctx->pipe_bytes, SPLICE_F_MOVE);
                        set_sqe_ctx(sqe, ctx);
                        break;
                    }

                    if ((size_t)ctx->pub.file_offset < ctx->file_size) {
                        // The file was too big for one pipe buffer. We must loop back!
                        ctx->state = SPLICE_IN;
                        struct io_uring_sqe *sqe = get_sqe_safe(ring);
                        if (!sqe) {
                            close_and_release_ctx(ring, ctx);
                            break;
                        }
                        // Splice from File to Pipe-Write
                        io_uring_prep_splice(sqe, ctx->pub.file_fd, ctx->pub.file_offset, ctx->pipe_fd->fds[1], -1, ctx->file_size - (size_t)ctx->pub.file_offset, SPLICE_F_MOVE);
                        set_sqe_ctx(sqe, ctx);
                        break;
                    }

                    if (ctx->pub.request.keep_alive) {
                        // Release the pipe and close the opened file
                        if (ctx->pub.file_fd >= 0) close(ctx->pub.file_fd);
                        if (ctx->pipe_fd) { release_pipe(ctx->pipe_fd); ctx->pipe_fd = NULL; }

                        size_t consumed = ctx->current_req_len;
                        size_t remaining = (consumed > 0 && ctx->bytes_read > consumed) ? (ctx->bytes_read - consumed) : 0;

                        if (remaining > 0) {
                            // Restore first byte of the next pipelined request if clobbered by body '\0'
                            ctx->buffer[consumed] = (char)ctx->ws_saved_byte;
                            memmove(ctx->buffer, ctx->buffer + consumed, remaining);
                        }

                        // Wipe the slate clean for the next request on this exact same socket
                        ctx->state = READ;
                        reset_context(ctx);
                        ctx->bytes_read = remaining;

                        if (remaining > 0) {
                            // Next pipelined request is already in RAM! Trigger READ immediately via NOP
                            ctx->ws_from_nop = true;
                            struct io_uring_sqe *nop_sqe = get_sqe_safe(ring);
                            if (!nop_sqe) {
                                close_and_release_ctx(ring, ctx);
                                break;
                            }
                            io_uring_prep_nop(nop_sqe);
                            set_sqe_ctx(nop_sqe, ctx);
                        }
                        else {
                            // Tell io_uring to wait for the browser's next message!
                            // Buffer is empty; wait for the client's next TCP packet
                            prep_linked_recv(ring, ctx, ctx->buffer, MAX_BUFFER_SIZE - 1);
                        }
                    }
                    else {
                        // File is completely sent!
                        close_and_release_ctx(ring, ctx);
                    }
                    break;
                }

                case UPLOAD_WRITE: {
                    if (res <= 0) {
                        close_and_release_ctx(ring, ctx);
                        break;
                    }

                    // kernel has dumped res bytes to disk
                    size_t written = (size_t)res;
                    ctx->pub.file_offset += (off_t)written;

                    // Track the RAM chunk pointers
                    ctx->pub.upload_ptr += written;

                    // guarding upload_chunk_len and upload_remaining against size_t underflow
                    ctx->pub.upload_chunk_len = (written >= ctx->pub.upload_chunk_len) ? 0 : (ctx->pub.upload_chunk_len - written);
                    ctx->pub.upload_remaining = (written >= ctx->pub.upload_remaining) ? 0 : (ctx->pub.upload_remaining - written);

                    if (ctx->pub.upload_chunk_len > 0) {
                        // Disk didn't write the full RAM chunk. Re-queue the rest of it!
                        struct io_uring_sqe *write_sqe = get_sqe_safe(ring);
                        if (!write_sqe) {
                            close_and_release_ctx(ring, ctx);
                            break;
                        }
                        io_uring_prep_write(write_sqe, ctx->pub.file_fd, ctx->pub.upload_ptr, ctx->pub.upload_chunk_len, (ctx->pub.handler_step == 1) ? 0 : ctx->pub.file_offset); // offset logic for /dev/null byte chunk uploads
                        set_sqe_ctx(write_sqe, ctx);
                        break;
                    }

                    // RAM chunk fully flushed! Move on to checking if upload is done or if we need to splice
                    if (ctx->pub.upload_remaining == 0) { // file upload complete
                        close(ctx->pub.file_fd);
                        ctx->pub.file_fd = -1; // reset
                        ctx->bytes_read = 0; // reset
                        // respond amount of bytes uploaded if handler step is 1
                        if (ctx->pub.handler_step == 1) {
                            char size_str[32];
                            snprintf(size_str, sizeof(size_str), "%lld", (long long)ctx->pub.file_offset);
                            send_text((CwebContext *)ctx, 200, size_str);
                        }
                        // respond with upload complete otherwise
                        else {
                            send_text((CwebContext *)ctx, 200, "Upload complete");
                        }

                        ctx->state = WRITE;
                        struct io_uring_sqe *write_sqe = get_sqe_safe(ring);
                        if (!write_sqe) {
                            close_and_release_ctx(ring, ctx);
                            break;
                        }
                        io_uring_prep_send(write_sqe, ctx->fd, ctx->response_ptr, ctx->response_len, 0);
                        set_sqe_ctx(write_sqe, ctx);
                    }
                    else if (ctx->pub.upload_remaining > 0) { // some bytes are left
                        ctx->state = UPLOAD_SPLICE_IN;

                        // acquire a pipe
                        ctx->pipe_fd = acquire_pipe();
                        if (!ctx->pipe_fd) { close_and_release_ctx(ring, ctx); break; } // drop connection

                        // Splice from network socket to Pipe-Write
                        size_t to_splice = (ctx->pub.upload_remaining > MAX_BUFFER_SIZE) ? MAX_BUFFER_SIZE : ctx->pub.upload_remaining;
                        prep_linked_splice(ring, ctx, ctx->fd, -1, ctx->pipe_fd->fds[1], -1, to_splice, 0);
                    }

                    break;
                }

                case UPLOAD_SPLICE_IN: {
                    if (res <= 0) {
                        close_and_release_ctx(ring, ctx);
                        break;
                    }

                    // Track bytes pulled from network into the pipe
                    ctx->pipe_bytes = (size_t)res;
                    ctx->state = UPLOAD_SPLICE_OUT;
                    // Splice from Pipe-Read to file_fd
                    prep_linked_splice(ring, ctx, ctx->pipe_fd->fds[0], -1, ctx->pub.file_fd, (ctx->pub.handler_step == 1) ? -1 : ctx->pub.file_offset, ctx->pipe_bytes, 0); // -1 needed for /dev/null file upload
                    break;
                }

                case UPLOAD_SPLICE_OUT: {
                    if (res <= 0) {
                        close_and_release_ctx(ring, ctx);
                        break;
                    }

                    // kernel has dumped res bytes to disk
                    size_t written = (size_t)res;
                    ctx->pub.file_offset += (off_t)written;
                    // guarding upload_remaining and pipe_bytes from size_t underflow
                    ctx->pub.upload_remaining = (written >= ctx->pub.upload_remaining) ? 0 : (ctx->pub.upload_remaining - written);
                    ctx->pipe_bytes = (written >= ctx->pipe_bytes) ? 0 : (ctx->pipe_bytes - written);

                    if (ctx->pipe_bytes > 0) {
                        // Pipe still has data! Re-submit UPLOAD_SPLICE_OUT.
                        prep_linked_splice(ring, ctx, ctx->pipe_fd->fds[0], -1, ctx->pub.file_fd, (ctx->pub.handler_step == 1) ? -1 : ctx->pub.file_offset, ctx->pipe_bytes, 0); // -1 needed for /dev/null file upload
                        break;
                    }

                    // pipe is fully drained
                    if (ctx->pub.upload_remaining == 0) { // file upload complete
                        close(ctx->pub.file_fd);
                        ctx->pub.file_fd = -1; // reset
                        ctx->bytes_read = 0; // reset
                        if (ctx->pipe_fd) { release_pipe(ctx->pipe_fd); ctx->pipe_fd = NULL; }
                        // respond amount of bytes uploaded if handler step is 1
                        if (ctx->pub.handler_step == 1) {
                            char size_str[32];
                            snprintf(size_str, sizeof(size_str), "%lld", (long long)ctx->pub.file_offset);
                            send_text((CwebContext *)ctx, 200, size_str);
                        }
                        // respond with upload complete otherwise
                        else {
                            send_text((CwebContext *)ctx, 200, "Upload complete");
                        }

                        ctx->state = WRITE;
                        struct io_uring_sqe *write_sqe = get_sqe_safe(ring);
                        if (!write_sqe) {
                            close_and_release_ctx(ring, ctx);
                            break;
                        }
                        io_uring_prep_send(write_sqe, ctx->fd, ctx->response_ptr, ctx->response_len, 0);
                        set_sqe_ctx(write_sqe, ctx);
                    }
                    else if (ctx->pub.upload_remaining > 0) { // some bytes are left
                        ctx->state = UPLOAD_SPLICE_IN;

                        // Splice from network socket to Pipe-Write
                        size_t to_splice = (ctx->pub.upload_remaining > MAX_BUFFER_SIZE) ? MAX_BUFFER_SIZE : ctx->pub.upload_remaining;
                        prep_linked_splice(ring, ctx, ctx->fd, -1, ctx->pipe_fd->fds[1], -1, to_splice, 0);
                    }
                    break;
                }

                case RESUME: {
                    HandlerState status = execute_pipeline(ctx);
                    if (status == DB_WAIT) {
                        ctx->state = WAIT;
                        struct io_uring_sqe *sqe = get_sqe_safe(ring);
                        if (!sqe) {
                            close_and_release_ctx(ring, ctx);
                            break;
                        }
                        io_uring_prep_poll_add(sqe, PQsocket(ctx->db_conn), POLLIN);
                        set_sqe_ctx(sqe, ctx);
                        break;
                    }
                    else if (status == DB_QUEUED) {
                        ctx->state = QUEUED;
                        break;
                    }
                    else if (status == DB_DONE) {
                        if (ctx->pub.db_result) {
                            PQclear(ctx->pub.db_result);
                            ctx->pub.db_result = NULL;
                        }
                        if (ctx->db_conn) {
                            ConnContext* queued_ctx = release_db_conn(ctx->db_conn);
                            ctx->db_conn = NULL;
                            if (queued_ctx && queued_ctx->in_use) {
                                queued_ctx->state = RESUME;
                                struct io_uring_sqe *nop_sqe = get_sqe_safe(ring);
                                if (nop_sqe) {
                                    io_uring_prep_nop(nop_sqe);
                                    set_sqe_ctx(nop_sqe, queued_ctx);
                                }
                            }
                        }
                        if (ctx->pub.request.body && ctx->bytes_read < (size_t)(ctx->pub.request.body - ctx->buffer) + ctx->pub.request.content_len) {
                            ctx->pub.request.keep_alive = false;
                        }
                        ctx->state = WRITE;
                        struct io_uring_sqe *write_sqe = get_sqe_safe(ring);
                        if (!write_sqe) {
                            close_and_release_ctx(ring, ctx);
                            break;
                        }
                        io_uring_prep_send(write_sqe, ctx->fd, ctx->response_ptr, ctx->response_len, 0);
                        set_sqe_ctx(write_sqe, ctx);
                    }
                    break;
                }

                case QUEUED:
                    // Do nothing
                    break;

                case WS_READ: {
                    if (ctx->ws_from_nop) {
                        ctx->ws_from_nop = false;
                    }
                    else if (res <= 0) {
                        close_and_release_ctx(ring, ctx);
                        break;
                    }
                    else {
                        ctx->bytes_read += (size_t)res;
                    }

                    uint8_t *data = (uint8_t*)ctx->buffer;

                    // Minimum 2-byte header
                    if (ctx->bytes_read < 2) {
                        prep_linked_recv(ring, ctx, ctx->buffer + ctx->bytes_read, MAX_BUFFER_SIZE - ctx->bytes_read);
                        break;
                    }

                    uint8_t opcode = data[0] & 0x0F;
                    uint8_t mask_bit = (data[1] >> 7) & 1;
                    uint64_t payload_len = data[1] & 0x7F;

                    if (!mask_bit) {
                        close_and_release_ctx(ring, ctx); break; // Clients MUST mask frames
                    }

                    size_t header_len = 2;

                    if (payload_len == 126) {
                        header_len = 4;
                        if (ctx->bytes_read < header_len) {
                            prep_linked_recv(ring, ctx, ctx->buffer + ctx->bytes_read, MAX_BUFFER_SIZE - ctx->bytes_read);
                            break;
                        }
                        payload_len = (data[2] << 8) | data[3];
                    }
                    else if (payload_len == 127) {
                        header_len = 10;
                        if (ctx->bytes_read < header_len) {
                            prep_linked_recv(ring, ctx, ctx->buffer + ctx->bytes_read, MAX_BUFFER_SIZE - ctx->bytes_read);
                            break;
                        }
                        payload_len = 0;
                        for (int i = 0; i < 8; i++) {
                            payload_len = (payload_len << 8) | data[2 + i];
                        }
                    }

                    // Prevent Impossible Buffer DoS (CWEB only handles frames up to ~8 KB)
                    if (payload_len >= MAX_BUFFER_SIZE || header_len + 4 + payload_len >= MAX_BUFFER_SIZE) {
                        close_and_release_ctx(ring, ctx); break;
                    }

                    // Wait for the full payload + 4-byte mask to arrive
                    if (ctx->bytes_read < header_len + 4 + payload_len) {
                        prep_linked_recv(ring, ctx, ctx->buffer + ctx->bytes_read, MAX_BUFFER_SIZE - ctx->bytes_read);
                        break;
                    }

                    uint8_t masking_key[4];
                    memcpy(masking_key, data + header_len, 4);
                    uint8_t *payload = data + header_len + 4;

                    for (size_t i = 0; i < payload_len; i++) {
                        payload[i] ^= masking_key[i % 4];
                    }

                    if (opcode == 8) { // CLOSE Frame: echo close frame then close
                        ctx->pub.is_websocket = false; // So WRITE closes the socket after sending close frame
                        ctx->pub.request.keep_alive = false;
                        uint8_t *out = (uint8_t*)ctx->buffer;
                        out[0] = 0x88;
                        out[1] = 0x00;
                        ctx->response_ptr = ctx->buffer;
                        ctx->response_len = 2;
                        ctx->state = WRITE;
                        struct io_uring_sqe *write_sqe = get_sqe_safe(ring);
                        if (!write_sqe) { close_and_release_ctx(ring, ctx); break; }
                        io_uring_prep_send(write_sqe, ctx->fd, ctx->response_ptr, ctx->response_len, 0);
                        set_sqe_ctx(write_sqe, ctx);
                        break;
                    }
                    else if (opcode == 9) { // PING Frame -> Automatic PONG (opcode 10)
                        ctx->ws_frame_len = header_len + 4 + (size_t)payload_len;
                        ctx->ws_saved_byte = payload[payload_len];
                        ctx->pub.ws_payload = (char*)payload;
                        ctx->pub.ws_payload_len = (size_t)payload_len;
                        ctx->pub.ws_opcode = 10; // PONG
                        send_ws_text((CwebContext*)ctx, ctx->pub.ws_payload);
                        ctx->state = WRITE;
                        struct io_uring_sqe *write_sqe = get_sqe_safe(ring);
                        if (!write_sqe) { close_and_release_ctx(ring, ctx); break; }
                        io_uring_prep_send(write_sqe, ctx->fd, ctx->response_ptr, ctx->response_len, 0);
                        set_sqe_ctx(write_sqe, ctx);
                        break;
                    }
                    else if (opcode == 1 || opcode == 2) { // TEXT or BINARY Frame
                        ctx->ws_frame_len = header_len + 4 + (size_t)payload_len;
                        ctx->ws_saved_byte = payload[payload_len];
                        payload[payload_len] = '\0';

                        ctx->pub.ws_payload = (char*)payload;
                        ctx->pub.ws_payload_len = (size_t)payload_len;
                        ctx->pub.ws_opcode = opcode;

                        HandlerState status = execute_pipeline(ctx);

                        if (status == DB_WAIT) {
                            ctx->state = WAIT;
                            int pg_fd = PQsocket(ctx->db_conn);
                            struct io_uring_sqe *sqe = get_sqe_safe(ring);
                            if (!sqe) {
                                close_and_release_ctx(ring, ctx);
                                break;
                            }
                            io_uring_prep_poll_add(sqe, pg_fd, POLLIN);
                            set_sqe_ctx(sqe, ctx);
                            break;
                        }
                        else if (status == DB_QUEUED) {
                            ctx->state = QUEUED;
                            break;
                        }

                        // Fast-path batching for pipelined WebSocket frames (echo-ws-pipeline):
                        if (ctx->bytes_read > ctx->ws_frame_len && ctx->response_ptr > ctx->buffer) {
                            char *batch_start = ctx->response_ptr;
                            size_t batch_len  = ctx->response_len;
                            size_t frame_off  = 0;

                            while (ctx->bytes_read > frame_off + ctx->ws_frame_len) {
                                ctx->buffer[frame_off + ctx->ws_frame_len] = (char)ctx->ws_saved_byte;
                                frame_off += ctx->ws_frame_len;

                                uint8_t *f_data = (uint8_t*)(ctx->buffer + frame_off);
                                size_t avail    = ctx->bytes_read - frame_off;
                                if (avail < 2) break;

                                uint8_t f_op   = f_data[0] & 0x0F;
                                uint8_t f_mask = (f_data[1] >> 7) & 1;
                                uint64_t f_len = f_data[1] & 0x7F;
                                if (!f_mask || (f_op != 1 && f_op != 2)) break;

                                size_t f_hdr = 2;
                                if (f_len == 126) {
                                    f_hdr = 4;
                                    if (avail < f_hdr) break;
                                    f_len = ((uint64_t)f_data[2] << 8) | f_data[3];
                                } else if (f_len == 127) {
                                    f_hdr = 10;
                                    if (avail < f_hdr) break;
                                    f_len = 0;
                                    for (int b = 0; b < 8; b++) f_len = (f_len << 8) | f_data[2 + b];
                                }

                                size_t this_frame_len = f_hdr + 4 + (size_t)f_len;
                                if (avail < this_frame_len) break;

                                char *next_out = batch_start + batch_len;
                                if ((size_t)(next_out - ctx->buffer) + f_len + 8 >= MAX_BUFFER_SIZE) break;

                                uint8_t mkey[4];
                                memcpy(mkey, f_data + f_hdr, 4);
                                uint8_t *f_payload = f_data + f_hdr + 4;
                                for (size_t k = 0; k < f_len; k++) f_payload[k] ^= mkey[k % 4];

                                ctx->ws_saved_byte = f_payload[f_len];
                                f_payload[f_len] = '\0';
                                ctx->pub.ws_payload = (char*)f_payload;
                                ctx->pub.ws_payload_len = (size_t)f_len;
                                ctx->pub.ws_opcode = f_op;

                                size_t saved_br = ctx->bytes_read;
                                ctx->bytes_read = (size_t)(next_out - ctx->buffer) - 1;
                                ctx->ws_frame_len = 0;

                                HandlerState st = execute_pipeline(ctx);
                                ctx->bytes_read = saved_br;
                                ctx->ws_frame_len = this_frame_len;

                                if (st != DB_DONE) break;
                                batch_len += ctx->response_len;
                            }

                            ctx->ws_frame_len += frame_off;
                            ctx->response_ptr = batch_start;
                            ctx->response_len = batch_len;
                        }

                        ctx->state = WRITE;
                        struct io_uring_sqe *write_sqe = get_sqe_safe(ring);
                        if (!write_sqe) {
                            close_and_release_ctx(ring, ctx);
                            break;
                        }
                        io_uring_prep_send(write_sqe, ctx->fd, ctx->response_ptr, ctx->response_len, 0);
                        set_sqe_ctx(write_sqe, ctx);
                    }
                    else { close_and_release_ctx(ring, ctx); break; }

                    break;
                }
            }
        }

        // Flush all SQEs prepared during this batch in one single syscall
        io_uring_submit(ring);
    }

    release_context(server_ctx);
    return 0;
}

int cweb_run_server(int port, const char* db_url, int db_conns_per_cpu_core) {
    // handle signals
    signal(SIGINT, handle_sig);
    signal(SIGTERM, handle_sig);
    signal(SIGPIPE, SIG_IGN); // ignore sigpipe to avoid crash because of a client's bad internet

    // allocate resource (max open fds)
    struct rlimit rl;
    rl.rlim_cur = 65535; // Soft limit
    rl.rlim_max = 65535; // Hard limit
    setrlimit(RLIMIT_NOFILE, &rl);

    // allocate resource (unlimited memory for io_uring) -> requires root privileges
    struct rlimit rl_mem;
    rl_mem.rlim_cur = RLIM_INFINITY;
    rl_mem.rlim_max = RLIM_INFINITY;
    setrlimit(RLIMIT_MEMLOCK, &rl_mem);

    int err;

    // Detect exact CPUs allowed --cpuset-cpus (cgroup-aware!)
    int num_cores = 0;
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    if (sched_getaffinity(0, sizeof(cpuset), &cpuset) == 0) {
        num_cores = CPU_COUNT(&cpuset);
    }
    if (num_cores <= 0) {
        num_cores = (int)sysconf(_SC_NPROCESSORS_ONLN);
        if (num_cores <= 0) num_cores = 1;
    }

    printf("Server started with %d Workers on Port %d...\n", num_cores, port);
    fflush(stdout);

    // The forking engine (Multiprocessing)
    for (int i = 0; i < num_cores; i++) {
        if (fork() == 0) { // child workers
            int fd = socket(AF_INET, SOCK_STREAM, 0);
            if (fd < 0) die("socket() failed");

            int val = 1;
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
            setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val)); // kernel load balancing in same port

            struct sockaddr_in addr = {};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port); // port
            addr.sin_addr.s_addr = htonl(0); // 0.0.0.0
            err = bind(fd, (const struct sockaddr*)&addr, sizeof(addr));
            if (err) die("bind() failed");

            err = listen(fd, SOMAXCONN);
            if (err) die("listen() failed");

            set_non_blocking(fd); // The server is now non-blocking

            // initialize the database connection if db_url mentioned in the parameters
            // connecting to database before dropping privileges
            err = db_init(db_url, db_conns_per_cpu_core);
            if (err == -1) die("db_init() failed");

            // set workers to nobody user (privilege seperation)
            struct passwd* pw = getpwnam("nobody");
            if (!pw) die("getpwnam() failed"); // if nobody user does not exist

            // conditional jailing worker logic based on docker container requirements
            if (!getenv("CWEB_NO_CHROOT")) { // for CWEB_NO_CHROOT = 1, workers wont be jailed
                // jail workers to the current working application directory
                if (chroot(".") != 0) die("chroot() failed");
                if (chdir("/") != 0) die("chdir() failed");
            }

            // drop privileges
            if (setgroups(0, NULL) != 0) die("setgroups() failed");

            if (setgid(pw->pw_gid) != 0) die("setgid() failed");
            if (setuid(pw->pw_uid) != 0) die("setuid() failed");

            // privilege drop verification
            if (setuid(0) == 0) die("Worker privilege drop failed");

            // Compatibility guards for older Linux headers (< 5.19 / < 6.0)
            #ifndef IORING_SETUP_COOP_TASKRUN
            #define IORING_SETUP_COOP_TASKRUN (1U << 8)
            #endif

            #ifndef IORING_SETUP_SINGLE_ISSUER
            #define IORING_SETUP_SINGLE_ISSUER (1U << 12)
            #endif

            // params struct must not have garbage memory, otherwise kernel might reject
            memset(&params, 0, sizeof(params));
            // create the ring in a disabled state (Requires linux 5.10+)
            #ifdef IORING_RESTRICTION_SQE_OP
            params.flags = IORING_SETUP_R_DISABLED;
            #endif
            // assigning certain flags to reduce kernel overhead and shrink attack surface
            // Kernel 5.19+ high performance flags (can fail in lower version systems)
            params.flags |= IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_COOP_TASKRUN;
            // initialize the ring
            err = io_uring_queue_init_params(QUEUE_DEPTH, &ring, &params);
            if (err) {
                // Fallback for older Kernels (5.10+ to 5.18)
                printf("High performance io_uring failed. Falling back to standard io_uring...\n");
                memset(&params, 0, sizeof(params));
                #ifdef IORING_RESTRICTION_SQE_OP
                params.flags = IORING_SETUP_R_DISABLED;
                #endif
                err = io_uring_queue_init_params(QUEUE_DEPTH, &ring, &params);
                if (err) {
                    // Fallback for even older kernels (5.7 - 5.9)
                    printf("Restricted secured io_uring failed. Falling back to standard io_uring...\n");
                    memset(&params, 0, sizeof(params));
                    err = io_uring_queue_init_params(QUEUE_DEPTH, &ring, &params);
                    if (err) die("io_uring_queue_init_params() failed");
                }
            }

            #ifdef IORING_RESTRICTION_SQE_OP
            if (params.flags & IORING_SETUP_R_DISABLED) {
                static const uint8_t allowed_ops[] = {
                    IORING_OP_ACCEPT, IORING_OP_RECV, IORING_OP_SEND,
                    IORING_OP_WRITE, IORING_OP_SPLICE, IORING_OP_LINK_TIMEOUT,
                    IORING_OP_POLL_ADD, IORING_OP_NOP, IORING_OP_ASYNC_CANCEL
                };
                size_t num_ops = sizeof(allowed_ops) / sizeof(allowed_ops[0]);
                struct io_uring_restriction restrictions[sizeof(allowed_ops) / sizeof(allowed_ops[0])];
                memset(restrictions, 0, sizeof(restrictions));

                for (size_t j = 0; j < num_ops; j++) {
                    restrictions[j].opcode = IORING_RESTRICTION_SQE_OP;
                    restrictions[j].sqe_op = allowed_ops[j];
                }

                // Direct syscall bypasses missing wrapper symbols in Debian 11's liburing 0.7
                int res = syscall(__NR_io_uring_register, ring.ring_fd,
                                  IORING_REGISTER_RESTRICTIONS, restrictions, (unsigned int)num_ops);
                if (res < 0) {
                    io_uring_queue_exit(&ring);
                    die("io_uring_register_restrictions() failed");
                }

                // Enable the ring; restrictions are now locked and permanently enforced
                res = syscall(__NR_io_uring_register, ring.ring_fd,
                              IORING_REGISTER_ENABLE_RINGS, NULL, 0);
                if (res < 0) {
                    io_uring_queue_exit(&ring);
                    die("io_uring_enable_rings() failed");
                }
            }
            #endif

            // initialize the context pool
            ConnContext* pool = create_ctx_pool();
            if (!pool) die("create_ctx_pool() failed");

            // initialize the pipe pool
            PipeNode* pipe_pool = pipe_pool_init();
            if (!pipe_pool) die("pipe_pool_init() failed");

            // initiate kernel lockdown
            err = enable_sandbox();
            if (err == -1) {
                die("Sandbox initialization failed. Check the security module");
            }
            // run the server
            err = run_server_loop(&ring, fd);

            io_uring_queue_exit(&ring);
            db_free(db_conns_per_cpu_core);
            pipe_pool_free(pipe_pool);
            free_ctx_pool(pool);
            radix_pool_free();
            close(fd);
            exit(0); // clean exit
        }
    }

    // master process waits here forever
    while (wait(NULL) > 0);

    return 0;
}
