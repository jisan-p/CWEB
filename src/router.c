#include "../include/router.h"

RadixNode* node_pool = NULL;
RadixNode* node_root[9]; // 9 trees for 9 HTTP method enums (GET .. CONNECT)
size_t node_pool_idx = 0;

RadixNode* radix_pool_init(void) {
    RadixNode* pool = calloc(MAX_RADIX_NODES, sizeof(RadixNode));
    if (!pool) {
        fprintf(stderr, "Failed to allocate memory for Radix Node Pool\n");
        return NULL;
    }
    return pool;
}

int radix_pool_free(void) {
    if (node_pool) {
        // Free dynamically reallocated children arrays for every created node
        for (size_t i = 0; i < node_pool_idx; i++) {
            if (node_pool[i].children) {
                free(node_pool[i].children);
                node_pool[i].children = NULL;
            }
        }
        free(node_pool);
        node_pool = NULL;
    }
    for (int i = 0; i < 9; i++) {
        node_root[i] = NULL;
    }
    node_pool_idx = 0;
    return 0;
}

RadixNode* create_node(const char* segment) {
    if (!segment) {
        fprintf(stderr, "create_node: segment cannot be NULL\n");
        return NULL;
    }

    if (!node_pool || node_pool_idx >= MAX_RADIX_NODES) {
        fprintf(stderr, "Radix Node Pool filled or uninitialized\n");
        return NULL;
    }

    if (strlen(segment) >= MAX_PATH_SEGMENT_LEN) {
        fprintf(stderr, "Segment way too large to store\n");
        return NULL;
    }

    RadixNode* node = &node_pool[node_pool_idx++];
    memset(node, 0, sizeof(RadixNode));
    strcpy(node->path_segment, segment);
    node->num_children = 0;
    node->mw_count = 0;
    node->children = NULL;
    node->handler = NULL;
    node->is_dynamic = false;

    return node;
}

static void init_router_if_needed(void) {
    if (node_pool) return;

    node_pool = radix_pool_init();
    if (!node_pool) {
        fprintf(stderr, "radix_pool_init() failed\n");
        exit(1);
    }

    // Initialize the radix tree roots for all supported HTTP methods
    for (int i = 0; i < 9; i++) {
        node_root[i] = create_node("ROOT");
        if (!node_root[i]) {
            fprintf(stderr, "create_node() failed for root %d\n", i);
            exit(1);
        }
    }
}

int insert_route(Method method, char *path, RouteHandler handler) {
    if (!path || !handler) {
        fprintf(stderr, "insert_route: path and handler cannot be NULL\n");
        exit(1);
    }
    if (method < GET || method > CONNECT) {
        fprintf(stderr, "insert_route: invalid HTTP method %d\n", method);
        exit(1);
    }

    init_router_if_needed();

    char* path_copy = strdup(path);
    if (!path_copy) {
        fprintf(stderr, "Failed to allocate memory for path\n");
        exit(1);
    }

    RadixNode* current = node_root[method];
    char* save_ptr = NULL;
    char* token = strtok_r(path_copy, "/", &save_ptr);

    while (token) {
        bool exists = false;
        for (size_t i = 0; i < current->num_children; i++) {
            if (strcmp(token, current->children[i]->path_segment) == 0) {
                current = current->children[i];
                exists = true;
                break;
            }
        }

        if (!exists) {
            // Allocate space for child pointer before taking a node from pool
            RadixNode** temp = realloc(current->children, (current->num_children + 1) * sizeof(RadixNode*));
            if (!temp) {
                fprintf(stderr, "realloc() failed for route children\n");
                free(path_copy);
                exit(1);
            }
            current->children = temp;

            RadixNode* node = create_node(token);
            if (!node) {
                fprintf(stderr, "create_node() failed\n");
                free(path_copy);
                exit(1);
            }

            if (token[0] == ':') {
                node->is_dynamic = true;
            }

            current->children[current->num_children++] = node;
            current = node;
        }

        token = strtok_r(NULL, "/", &save_ptr);
    }

    current->handler = handler;
    free(path_copy);
    return 0;
}

int insert_middleware(Method method, char* path, MiddlewareHandler handler) {
    if (!path || !handler) {
        fprintf(stderr, "insert_middleware: path and handler cannot be NULL\n");
        exit(1);
    }
    if (method < GET || method > CONNECT) {
        fprintf(stderr, "insert_middleware: invalid HTTP method %d\n", method);
        exit(1);
    }

    init_router_if_needed();

    char* path_copy = strdup(path);
    if (!path_copy) {
        fprintf(stderr, "Failed to allocate memory for path\n");
        exit(1);
    }

    RadixNode* current = node_root[method];
    char* save_ptr = NULL;
    char* token = strtok_r(path_copy, "/", &save_ptr);

    while (token) {
        bool exists = false;
        for (size_t i = 0; i < current->num_children; i++) {
            if (strcmp(token, current->children[i]->path_segment) == 0) {
                current = current->children[i];
                exists = true;
                break;
            }
        }

        if (!exists) {
            RadixNode** temp = realloc(current->children, (current->num_children + 1) * sizeof(RadixNode*));
            if (!temp) {
                fprintf(stderr, "realloc() failed for middleware children\n");
                free(path_copy);
                exit(1);
            }
            current->children = temp;

            RadixNode* node = create_node(token);
            if (!node) {
                fprintf(stderr, "create_node() failed\n");
                free(path_copy);
                exit(1);
            }

            if (token[0] == ':') {
                node->is_dynamic = true;
            }

            current->children[current->num_children++] = node;
            current = node;
        }

        token = strtok_r(NULL, "/", &save_ptr);
    }

    if (current->mw_count >= MAX_MIDDLEWARES) {
        fprintf(stderr, "No more middleware insertion possible (max %d)\n", MAX_MIDDLEWARES);
        free(path_copy);
        exit(1);
    }

    current->middlewares[current->mw_count++] = handler;
    free(path_copy);
    return 0;
}

static int insert_pipeline(RadixNode* current, ConnContext* ctx) {
    if (!current || !ctx) return 0;

    for (int k = 0; k < current->mw_count; k++) {
        if (ctx->pipeline_count >= MAX_PIPELINES) {
            fprintf(stderr, "Pipeline limit exceeded (max %d)\n", MAX_PIPELINES);
            return -1;
        }
        ctx->pipeline[ctx->pipeline_count++] = current->middlewares[k];
    }
    return 0;
}

RouteHandler search_route(Method method, char* path, ConnContext* ctx) {
    if (!path || !ctx) return NULL;

    // Validate method enum (0..8) and ensure root exists
    if (method < GET || method > CONNECT || !node_root[method]) {
        return NULL;
    }

    RadixNode* current = node_root[method];

    // Root middlewares apply hierarchically to all requests on this method
    if (insert_pipeline(current, ctx) == -1) {
        return NULL;
    }

    const char* p = path;

    while (*p) {
        // Skip consecutive slashes
        while (*p == '/') p++;
        if (*p == '\0') break;

        const char* seg_start = p;
        const char* slash = strchr(seg_start, '/');
        size_t seg_len = slash ? (size_t)(slash - seg_start) : strlen(seg_start);

        bool matched = false;

        // 1. Static match
        for (size_t i = 0; i < current->num_children; i++) {
            RadixNode* child = current->children[i];
            if (!child->is_dynamic) {
                if (strlen(child->path_segment) == seg_len &&
                    strncmp(seg_start, child->path_segment, seg_len) == 0) {
                    current = child;
                matched = true;
                break;
                    }
            }
        }

        // 2. Dynamic wildcard match (:param)
        if (!matched) {
            for (size_t i = 0; i < current->num_children; i++) {
                RadixNode* child = current->children[i];
                if (child->is_dynamic) {
                    // Bounds check before writing path_params[]
                    if (ctx->pub.request.num_params >= MAX_PATH_PARAMS) {
                        return NULL;
                    }

                    ctx->pub.request.path_params[ctx->pub.request.num_params].str = (char*)seg_start;
                    ctx->pub.request.path_params[ctx->pub.request.num_params].len = (int)seg_len;
                    ctx->pub.request.num_params++;

                    current = child;
                    matched = true;
                    break;
                }
            }
        }

        if (!matched) {
            return NULL;
        }

        // Insert pipeline for current matching node
        if (insert_pipeline(current, ctx) == -1) {
            return NULL;
        }

        p = slash ? slash + 1 : seg_start + seg_len;
    }

    return current->handler;
}
