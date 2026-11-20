#ifndef ROUTER_H
#define ROUTER_H

#include "cweb.h"

#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "parser.h"
#include "server.h"

// creating a radix tree to store endpoints
typedef struct RadixNode{
    char path_segment[MAX_PATH_SEGMENT_LEN];
    RouteHandler handler; // NULL for branch, function pointer for leaf node (endpoint)
    struct RadixNode** children; // Array of pointers to the child nodes
    size_t num_children; // Number of children of a node
    bool is_dynamic; // false for static endpoints, true for wildcards like /:id
    MiddlewareHandler middlewares[MAX_MIDDLEWARES]; // array of middleware function pointers
    int mw_count; // middleware count
} RadixNode;

RadixNode* radix_pool_init(void);
int radix_pool_free(void);
RadixNode* create_node(const char* segment);
RouteHandler search_route(Method method, char* path, ConnContext* ctx);

#endif
