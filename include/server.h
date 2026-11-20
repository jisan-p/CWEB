#ifndef SERVER_H
#define SERVER_H

#include "cweb.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <signal.h>
#include <sched.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <liburing.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/sendfile.h>
#include <sys/resource.h>
#include <netinet/ip.h>
#include <libpq-fe.h>
#include <pwd.h>
#include <grp.h>

#include "parser.h"

typedef enum {
    ACCEPT, READ, WRITE, WAIT, SPLICE_IN, SPLICE_OUT, RESUME, QUEUED, WS_READ, UPLOAD_WRITE, UPLOAD_SPLICE_IN,
    UPLOAD_SPLICE_OUT
} State;

typedef struct ConnContext ConnContext; // forward declaration

typedef struct {
    // ConnContext* ctx;
    uint64_t user_data; // Packed [32 bit generation | 32 bit pool_idx], 0 = timeout CQE
    int res;
} EventTask;

typedef struct {
    int fds[2];
    bool in_use;
} PipeNode;

typedef struct {
    char key[64];
    char value[192];
} HttpHeader; // 256 bytes per HttpHeader cache line aligned

struct ConnContext{
    CwebContext pub; // public visible fields for the developer

    int fd; // file descriptor of the server/client
    State state; // current state of the connection
    bool in_use;
    uint32_t pool_idx; // 0 ... (MAX_CLIENTS - 1)
    uint32_t generation; // updated on acquire/release on stale CQE detection
    char buffer[MAX_BUFFER_SIZE]; // pointer to the buffer
    size_t current_req_len; // required for pipelining
    char* response_ptr;
    size_t bytes_read;
    size_t response_len;
    HttpHeader response_headers[MAX_RES_HEADERS_COUNT];
    int res_header_count;
    size_t file_size;
    PipeNode* pipe_fd; // for io_uring_prep_splice
    size_t pipe_bytes;
    RouteHandler handler;
    PGconn* db_conn; // database connection pointer
    MiddlewareHandler pipeline[MAX_PIPELINES]; // pipeline array of middlewares
    int pipeline_count;
    int pipeline_index;
    uint8_t ws_saved_byte; // saves the byte clobbered by the null terminator
    size_t ws_frame_len; // required for pipelining
    bool ws_from_nop; // to handle res == 0 edgecase
};

HandlerState execute_pipeline(ConnContext* ctx);
int run_server_loop(struct io_uring *ring, int server_fd);

#endif
