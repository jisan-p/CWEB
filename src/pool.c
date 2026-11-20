#include "../include/pool.h"

static ConnContext* ctx_pool_base = NULL;
static ConnContext* free_list[MAX_CLIENTS];
static int free_list_top = -1;
static PipeNode* pipe_pool_base = NULL;
static PipeNode* pipe_list[MAX_PIPES];
static int pipe_list_top = -1;

ConnContext* create_ctx_pool() {
    if (ctx_pool_base) return NULL; // double initialization guard

    free_list_top = -1; // explicit assignment of free_list_top to solidify global assumption

    ConnContext* pool = calloc(MAX_CLIENTS, sizeof(ConnContext));
    if (!pool) {
        fprintf(stderr, "Memory allocation failed for context pool\n");
        return NULL;
    }

    for (size_t i = 0; i < MAX_CLIENTS; i++) {
        // Leave calloc pages un-faulted (0 RSS) until acquired.
        // stack pushing in reverse order
        free_list[++free_list_top] = &pool[MAX_CLIENTS - 1 - i];
    }

    ctx_pool_base = pool; // setting the base pool for double initialization check
    return pool;
}

int free_ctx_pool(ConnContext* pool) {
    if (!pool || pool != ctx_pool_base) return -1;

    for (size_t i = 0; i < MAX_CLIENTS; i++) {
        if (pool[i].in_use) {
            if (pool[i].fd >= 0) close(pool[i].fd);
            if (pool[i].pub.file_fd >= 0) close(pool[i].pub.file_fd);
        }
    }

    free(pool);
    ctx_pool_base = NULL;
    free_list_top = -1;
    return 0;
}

void reset_context(ConnContext* ctx) {
    if (!ctx) return;

    // clear the request field
    memset(&ctx->pub.request, 0, sizeof(HttpRequest));

    // reset per request fields (excludes fd, state, in_use, pool_idx, generation)
    ctx->bytes_read = 0;
    ctx->pub.file_fd = -1;
    ctx->pub.file_offset = 0;
    ctx->pub.upload_remaining = 0;
    ctx->pub.upload_chunk_len = 0;
    ctx->pub.upload_ptr = NULL;
    ctx->pipe_fd = NULL;
    ctx->pipe_bytes = 0;
    ctx->file_size = 0;
    ctx->handler = NULL;
    ctx->db_conn = NULL;
    ctx->pub.db_result = NULL;
    ctx->pub.handler_step = 0;
    ctx->pipeline_count = 0;
    ctx->pipeline_index = 0;
    ctx->res_header_count = 0;
    ctx->response_ptr = NULL;
    ctx->response_len = 0;
    ctx->current_req_len = 0;
    ctx->pub.is_websocket = false;
    ctx->pub.ws_payload = NULL;
    ctx->pub.ws_opcode = 0;
    ctx->pub.ws_payload_len = 0;
    ctx->ws_frame_len = 0;
    ctx->ws_saved_byte = 0;
    ctx->ws_from_nop = false;
}

ConnContext* acquire_context(int client_fd, State state) {
    if (!ctx_pool_base || free_list_top < 0) {
        fprintf(stderr, "Acquisition failed. Context pool filled\n");
        return NULL;
    }

    // pop top element
    ConnContext* ctx = free_list[free_list_top--];

    if (ctx->in_use) { // prevents acquiring contexts already in use by the server
        fprintf(stderr, "Acquisition failed. Context already in use.\n");
        return NULL;
    }

    reset_context(ctx); // new context must be reset

    // explicit assignments
    ctx->fd = client_fd;
    ctx->state = state;
    ctx->pool_idx = (uint32_t)(ctx - ctx_pool_base);
    ctx->in_use = true;

    ctx->generation++;
    if (ctx->generation == 0) ctx->generation = 1; // enforcing wrapping around to 1, not 0

    return ctx;
}

int release_context(ConnContext* ctx) {
    if (!ctx || !ctx_pool_base) return -1;

    // out of bounds check
    if (ctx < ctx_pool_base || ctx >= (ctx_pool_base + MAX_CLIENTS)) return -1;

    // duplicate release check
    if (!ctx->in_use) {
        fprintf(stderr, "Context release failed. Context not in use\n");
        return -1;
    }

    // stack overflow check
    if (free_list_top >= MAX_CLIENTS -1) {
        fprintf(stderr, "Context free list stack overflow\n");
        return -1;
    }

    // properly release the context
    ctx->in_use = false;
    ctx->fd = -1;
    ctx->generation++;
    if (ctx->generation == 0) ctx->generation = 1; // enforcing wrapping around to 1, not 0

    // push back to stack
    free_list[++free_list_top] = ctx;

    return 0;
}

ConnContext* get_context_by_index(uint32_t index) {
    if (!ctx_pool_base || index >= MAX_CLIENTS) return NULL;

    return &ctx_pool_base[index];
}

PipeNode* pipe_pool_init() {
    if (pipe_pool_base) return NULL; // double initialization guard

    pipe_list_top = -1; // explicit assignment of free_list_top to solidify global assumption

    PipeNode* pool = calloc(MAX_PIPES, sizeof(PipeNode));
    if (!pool) {
        fprintf(stderr, "Memory allocation failed for pipe pool\n");
        return NULL;
    }

    for (size_t i = 0; i < MAX_PIPES; i++) {
        // pre initializing pipe endpoints
        pool[i].fds[0] = -1;
        pool[i].fds[1] = -1;
        pool[i].in_use = false;

        // create the pipe with safe failure exit pathway
        int err = pipe2(pool[i].fds, O_NONBLOCK | O_CLOEXEC);
        if (err == -1) {
            for (size_t j = 0; j < i; j++) {
                if (pool[j].fds[0] >= 0) close(pool[j].fds[0]);
                if (pool[j].fds[1] >= 0) close(pool[j].fds[1]);

                pool[j].fds[0] = -1;
                pool[j].fds[1] = -1;
            }

            pipe_list_top = -1;
            free(pool);
            return NULL;
        }

        // push onto stack
        pipe_list[++pipe_list_top] = &pool[i];
    }

    pipe_pool_base = pool; // setting the base pool for double initialization check
    return pool;
}

PipeNode* acquire_pipe() {
    if (!pipe_pool_base || pipe_list_top < 0) {
        fprintf(stderr, "Acquisition failed. Pipe pool is filled\n");
        return NULL;
    }

    PipeNode* node = pipe_list[pipe_list_top--];
    if (node->in_use) {
        fprintf(stderr, "Acquisition failed. Pipe already in use\n");
        return NULL;
    }

    node->in_use = true;
    return node;
}

int release_pipe(PipeNode* pipe) {
    if (!pipe || !pipe_pool_base) return -1;

    if (pipe < pipe_pool_base || pipe >= (pipe_pool_base + MAX_PIPES)) return -1;

    if (!pipe->in_use) {
        fprintf(stderr, "Pipe release failed. Pipe already in use\n");
        return -1;
    }

    if (pipe_list_top >= MAX_PIPES - 1) {
        fprintf(stderr, "Pipe node list stack overflow\n");
        return -1;
    }

    pipe->in_use = false;
    pipe_list[++pipe_list_top] = pipe;
    return 0;
}

int pipe_pool_free(PipeNode* pool) {
    if (!pool || pool != pipe_pool_base) return -1;

    for (size_t i = 0; i < MAX_PIPES; i++) {
        if (pool[i].fds[0] >= 0) close(pool[i].fds[0]);
        if (pool[i].fds[1] >= 0) close(pool[i].fds[1]);

        pool[i].in_use = false;
    }

    free(pool);
    pipe_pool_base = NULL;
    pipe_list_top = -1;
    return 0;
}
