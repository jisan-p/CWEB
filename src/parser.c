#include "../include/parser.h"

// lookup table for the HTTP methods
static struct {
    char* methodString;
    Method methodEnum;
} methodTable[] = {
    {"GET", GET},
    {"POST", POST},
    {"PUT", PUT},
    {"PATCH", PATCH},
    {"DELETE", DELETE},
    {"HEAD", HEAD},
    {"OPTIONS", OPTIONS},
    {"TRACE", TRACE},
    {"CONNECT", CONNECT},
};

#define METHOD_TABLE_LEN (sizeof(methodTable) / sizeof(methodTable[0]))

// Helper: Case-insensitive check if a header line starts with `prefix`
static bool header_starts_with(const char *line, const char *prefix, size_t prefix_len) {
    return strncasecmp(line, prefix, prefix_len) == 0;
}

ssize_t scan_buffer(char* buffer) {
    char* header_end = strstr(buffer, "\r\n\r\n");
    if (!header_end) return -1;

    size_t header_len = (size_t)(header_end - buffer) + 4;
    size_t content_len = 0;
    bool is_chunked = false;

    char* line = strstr(buffer, "\r\n");
    while (line && line < header_end) {
        line += 2;
        if (line >= header_end) break;

        if (header_starts_with(line, "Content-Length:", 15)) {
            char* val = line + 15;
            while (val < header_end && (*val == ' ' || *val == '\t')) val++;
            if (val >= header_end || *val < '0' || *val > '9') return -1;

            char* endptr = NULL;
            errno = 0;
            unsigned long long parsed = strtoull(val, &endptr, 10);
            // Allow at best 1 GB of payload in case of file uploads
            if (errno != 0 || endptr == val || parsed > (1ULL << 30)) {
                return -1;
            }
            content_len = (size_t)parsed;
        }
        else if (header_starts_with(line, "Transfer-Encoding:", 18)) {
            char* line_end = strstr(line, "\r\n");
            if (line_end && line_end <= header_end) {
                char saved = *line_end;
                *line_end = '\0';
                if (strcasestr(line + 18, "chunked")) {
                    is_chunked = true;
                }
                *line_end = saved;
            }
        }
        line = strstr(line, "\r\n");
    }

    if (is_chunked) {
        // Walk the chunked stream to verify the terminal "0\r\n\r\n" has arrived
        char* p = header_end + 4;
        size_t buf_len = strlen(buffer);
        char* buf_end = buffer + buf_len;

        while (p < buf_end) {
            char* crlf = strstr(p, "\r\n");
            if (!crlf) return -1; // Need more data for chunk size line

            char* endptr = NULL;
            errno = 0;
            unsigned long chunk_size = strtoul(p, &endptr, 16);
            if (errno != 0 || endptr == p || (endptr != crlf && *endptr != ';')) {
                return -1; // Malformed chunk size
            }
            if (chunk_size > MAX_BUFFER_SIZE) return -1;

            p = crlf + 2; // Move to chunk data
            if ((size_t)(buf_end - p) < chunk_size + 2) {
                return -1; // Full chunk data + trailing \r\n not yet received
            }
            if (p[chunk_size] != '\r' || p[chunk_size + 1] != '\n') {
                return -1; // Missing \r\n after chunk data
            }
            p += chunk_size + 2;

            if (chunk_size == 0) {
                // Terminal 0-length chunk + trailing \r\n completely received!
                return (ssize_t)(p - buffer);
            }
        }
        return -1; // Terminal chunk not yet reached
    }

    // If the full request fits in RAM buffer, wait for the whole body before dispatching.
    // If it exceeds MAX_BUFFER_SIZE - 1, it is a large streaming upload: dispatch as soon as headers arrive!
    if (header_len + content_len > MAX_BUFFER_SIZE - 1) {
        return (ssize_t)header_len;
    }
    return (ssize_t)(header_len + content_len);
}

int parse(char* buffer, HttpRequest* request, size_t size) {
    if (!buffer || !request || size < 4) return -1;

    request->method = UNKNOWN;
    request->content_len = 0;
    request->body = NULL;
    request->num_params = 0;
    request->num_headers = 0;
    request->keep_alive = true; // HTTP/1.1 defaults to Connection: Keep-Alive
    request->query_string = NULL;

    bool is_chunked = false;

    // loop through every byte in the buffer
    size_t idx = 0;
    char* method = buffer;
    char* path = "";
    while (idx < size) {
        if (buffer[idx] == ' ') { // First space of the buffer, got the method
            buffer[idx] = '\0';
            path = &buffer[idx + 1];
            break;
        }
        idx++;
    }

    // set the method in the request
    for (size_t i = 0; i < METHOD_TABLE_LEN; i++) {
        if (strcasecmp(method, methodTable[i].methodString) == 0) {
            request->method = methodTable[i].methodEnum;
            break;
        }
    }

    char* version = "";
    while (idx < size) {
        if (buffer[idx] == ' ') { // Second space of the buffer, got the path
            buffer[idx] = '\0';
            version = &buffer[idx + 1];
            break;
        }
        idx++;
    }

    // set the path in the request
    request->path = path;

    // Intercept Query Parameters
    char* question_mark = strchr(path, '?');
    if (question_mark) {
        *question_mark = '\0'; // Truncate the path string here!
        request->query_string = question_mark + 1; // Point to the start of the query parameters
    }

    char* headerName = "";
    char* headerValue = "";
    while (idx < (size - 1)) {
        if (buffer[idx] == '\r' && buffer[idx + 1] == '\n') { // First \r\n of the buffer, got the version
            buffer[idx] = '\0';
            buffer[idx + 1] = '\0';
            headerName = &buffer[idx + 2];
            break;
        }
        idx++;
    }

    // set the version in the request
    request->version = version;

    // Handle requests with zero headers (request line followed immediately by \r\n\r\n)
    if (idx + 3 < size && buffer[idx + 2] == '\r' && buffer[idx + 3] == '\n') {
        buffer[idx + 2] = '\0';
        buffer[idx + 3] = '\0';
        if (idx + 4 < size) {
            request->body = &buffer[idx + 4];
        }
        return 0;
    }

    int is_last_header = 0;
    while (1) {
        // security
        if (idx >= size) return -1; // stop parsing bad http request

        while (idx < size) {
            if (buffer[idx] == ':') { // String up to the colon is the name of the http header
                // SECURITY: RFC 7230 - No whitespace allowed between header name and colon!
                if (idx > 0 && buffer[idx - 1] == ' ') return -1;

                buffer[idx] = '\0';
                idx++;
                while (idx < size && (buffer[idx] == ' ' || buffer[idx] == '\t')) idx++; // skip OWS after ':'
                headerValue = &buffer[idx];
                break;
            }
            idx++;
        }

        if (request->num_headers >= MAX_HEADERS_COUNT) return -1; // buffer overflow protection

        // set the header name in the request
        request->headers[request->num_headers].name = headerName;

        while (idx < (size - 3)) {
            if (buffer[idx] == '\r' && buffer[idx + 1] == '\n') { // String up to the \r\n is the headerValue
                buffer[idx] = '\0';
                buffer[idx + 1] = '\0';

                if (buffer[idx + 2] == '\r' && buffer[idx + 3] == '\n') {
                    // End of the http request headers
                    buffer[idx + 2] = '\0';
                    buffer[idx + 3] = '\0';
                    request->headers[request->num_headers].value = headerValue;
                    is_last_header = 1;
                }

                headerName = &buffer[idx + 2];
                break;
            }
            idx++;
        }

        // set the header value in the request
        request->headers[request->num_headers].value = headerValue;

        // populate content_len or check for chunked Transfer-Encoding
        if (strcasecmp(request->headers[request->num_headers].name, "Content-Length") == 0) {
            request->content_len = (size_t)strtoull(headerValue, NULL, 10);
        }
        else if (strcasecmp(request->headers[request->num_headers].name, "Transfer-Encoding") == 0 &&
            strcasestr(headerValue, "chunked")) {
            is_chunked = true;
            }

            // HTTP/1.1 defaults to keep-alive. We only close if they explicitly ask to.
            if (strcasecmp(request->headers[request->num_headers].name, "Connection") == 0 &&
                strcasecmp(headerValue, "close") == 0) {
                request->keep_alive = false;
                }

                request->num_headers++;

            if (is_last_header) {
                char* body_start = (idx + 4 <= size) ? &buffer[idx + 4] : NULL;
                request->body = body_start;

                // De-chunk Transfer-Encoding: chunked body in-place
                if (is_chunked && body_start && body_start < buffer + size) {
                    char* src = body_start;
                    char* dst = body_start;
                    char* end = buffer + size;
                    size_t total_decoded = 0;

                    while (src < end) {
                        char* crlf = strstr(src, "\r\n");
                        if (!crlf || crlf >= end) return -1;
                        unsigned long chunk_size = strtoul(src, NULL, 16);
                        src = crlf + 2;
                        if (chunk_size == 0) break;
                        if ((size_t)(end - src) < chunk_size + 2) return -1;
                        memmove(dst, src, chunk_size);
                        dst += chunk_size;
                        total_decoded += chunk_size;
                        src += chunk_size + 2;
                    }
                    *dst = '\0';
                    request->body = body_start;
                    request->content_len = total_decoded;
                }

                break; // Breaks the outer while(1) loop
            }
    }

    return 0;
}
