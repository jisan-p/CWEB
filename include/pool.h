#ifndef POOL_H
#define POOL_H

#include "server.h"

// ConnContext* create_ctx_pool();
// int free_ctx_pool(ConnContext* pool);
//
// PipeNode* pipe_pool_init();
// int pipe_pool_free(PipeNode* pool);

ConnContext* create_ctx_pool(void);
int free_ctx_pool(ConnContext* pool);
void reset_context(ConnContext* ctx);
ConnContext* acquire_context(int client_fd, State state);
int release_context(ConnContext* ctx);
ConnContext* get_context_by_index(uint32_t index);

PipeNode* pipe_pool_init(void);
int pipe_pool_free(PipeNode* pool);
PipeNode* acquire_pipe(void);
int release_pipe(PipeNode* pipe);

#endif
