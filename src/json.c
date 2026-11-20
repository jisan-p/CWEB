#include "../include/json.h"

// jsmn.h function bodies
JSMN_API int jsmn_parse(jsmn_parser *parser, const char *js, const size_t len,
                        jsmntok_t *tokens, const unsigned int num_tokens) {
    int r;
    int i;
    jsmntok_t *token;
    int count = parser->toknext;

    for (; parser->pos < len && js[parser->pos] != '\0'; parser->pos++) {
        char c;
        jsmntype_t type;

        c = js[parser->pos];
        switch (c) {
            case '{':
            case '[':
                count++;
                if (tokens == NULL) {
                    break;
                }
                token = jsmn_alloc_token(parser, tokens, num_tokens);
                if (token == NULL) {
                    return JSMN_ERROR_NOMEM;
                }
                if (parser->toksuper != -1) {
                    jsmntok_t *t = &tokens[parser->toksuper];
                    #ifdef JSMN_STRICT
                    /* In strict mode an object or array can't become a key */
                    if (t->type == JSMN_OBJECT) {
                        return JSMN_ERROR_INVAL;
                    }
                    #endif
                    t->size++;
                    #ifdef JSMN_PARENT_LINKS
                    token->parent = parser->toksuper;
                    #endif
                }
                token->type = (c == '{' ? JSMN_OBJECT : JSMN_ARRAY);
                token->start = parser->pos;
                parser->toksuper = parser->toknext - 1;
                break;
            case '}':
            case ']':
                if (tokens == NULL) {
                    break;
                }
                type = (c == '}' ? JSMN_OBJECT : JSMN_ARRAY);
                #ifdef JSMN_PARENT_LINKS
                if (parser->toknext < 1) {
                    return JSMN_ERROR_INVAL;
                }
                token = &tokens[parser->toknext - 1];
                for (;;) {
                    if (token->start != -1 && token->end == -1) {
                        if (token->type != type) {
                            return JSMN_ERROR_INVAL;
                        }
                        token->end = parser->pos + 1;
                        parser->toksuper = token->parent;
                        break;
                    }
                    if (token->parent == -1) {
                        if (token->type != type || parser->toksuper == -1) {
                            return JSMN_ERROR_INVAL;
                        }
                        break;
                    }
                    token = &tokens[token->parent];
                }
                #else
                for (i = parser->toknext - 1; i >= 0; i--) {
                    token = &tokens[i];
                    if (token->start != -1 && token->end == -1) {
                        if (token->type != type) {
                            return JSMN_ERROR_INVAL;
                        }
                        parser->toksuper = -1;
                        token->end = parser->pos + 1;
                        break;
                    }
                }
                /* Error if unmatched closing bracket */
                if (i == -1) {
                    return JSMN_ERROR_INVAL;
                }
                for (; i >= 0; i--) {
                    token = &tokens[i];
                    if (token->start != -1 && token->end == -1) {
                        parser->toksuper = i;
                        break;
                    }
                }
                #endif
                break;
                case '\"':
                    r = jsmn_parse_string(parser, js, len, tokens, num_tokens);
                    if (r < 0) {
                        return r;
                    }
                    count++;
                    if (parser->toksuper != -1 && tokens != NULL) {
                        tokens[parser->toksuper].size++;
                    }
                    break;
                case '\t':
                case '\r':
                case '\n':
                case ' ':
                    break;
                case ':':
                    parser->toksuper = parser->toknext - 1;
                    break;
                case ',':
                    if (tokens != NULL && parser->toksuper != -1 &&
                        tokens[parser->toksuper].type != JSMN_ARRAY &&
                        tokens[parser->toksuper].type != JSMN_OBJECT) {
                        #ifdef JSMN_PARENT_LINKS
                        parser->toksuper = tokens[parser->toksuper].parent;
                    #else
                    for (i = parser->toknext - 1; i >= 0; i--) {
                        if (tokens[i].type == JSMN_ARRAY || tokens[i].type == JSMN_OBJECT) {
                            if (tokens[i].start != -1 && tokens[i].end == -1) {
                                parser->toksuper = i;
                                break;
                            }
                        }
                    }
                    #endif
                        }
                        break;
                        #ifdef JSMN_STRICT
                        /* In strict mode primitives are: numbers and booleans */
                        case '-':
                        case '0':
                        case '1':
                        case '2':
                        case '3':
                        case '4':
                        case '5':
                        case '6':
                        case '7':
                        case '8':
                        case '9':
                        case 't':
                        case 'f':
                        case 'n':
                            /* And they must not be keys of the object */
                            if (tokens != NULL && parser->toksuper != -1) {
                                const jsmntok_t *t = &tokens[parser->toksuper];
                                if (t->type == JSMN_OBJECT ||
                                    (t->type == JSMN_STRING && t->size != 0)) {
                                    return JSMN_ERROR_INVAL;
                                    }
                            }
                            #else
                            /* In non-strict mode every unquoted value is a primitive */
                            default:
                                #endif
                                r = jsmn_parse_primitive(parser, js, len, tokens, num_tokens);
                                if (r < 0) {
                                    return r;
                                }
                                count++;
                                if (parser->toksuper != -1 && tokens != NULL) {
                                    tokens[parser->toksuper].size++;
                                }
                                break;

                                #ifdef JSMN_STRICT
                                /* Unexpected char in strict mode */
                                default:
                                    return JSMN_ERROR_INVAL;
                                    #endif
        }
    }

    if (tokens != NULL) {
        for (i = parser->toknext - 1; i >= 0; i--) {
            /* Unmatched opened object or array */
            if (tokens[i].start != -1 && tokens[i].end == -1) {
                return JSMN_ERROR_PART;
            }
        }
    }

    return count;
                        }

JSMN_API void jsmn_init(jsmn_parser *parser) {
    parser->pos = 0;
    parser->toknext = 0;
    parser->toksuper = -1;
}

int json_begin(JsonBuilder *jb, char *buffer, size_t size) {
    if (!jb || !buffer || size < 2) {
        fprintf(stderr, "JSON buffer overflow or invalid arguments\n");
        return -1;
    }
    jb->remaining = size;
    jb->buffer = buffer;
    *jb->buffer = '{';
    jb->buffer++;
    jb->remaining--;
    jb->is_first = true;
    return 0;
}

int json_add_str(JsonBuilder *jb, const char *key, const char *value) {
    if (!jb || !jb->buffer || !key || !value) return -1;
    const char *comma = jb->is_first ? "" : ", ";
    int written = snprintf(jb->buffer, jb->remaining, "%s\"%s\": \"%s\"", comma, key, value);
    if (written < 0 || (size_t)written >= jb->remaining) return -1;
    jb->buffer += written;
    jb->remaining -= (size_t)written;
    jb->is_first = false;
    return 0;
}

int json_add_int(JsonBuilder *jb, const char *key, int value) {
    if (!jb || !jb->buffer || !key) return -1;
    const char *comma = jb->is_first ? "" : ", ";
    int written = snprintf(jb->buffer, jb->remaining, "%s\"%s\": %d", comma, key, value);
    if (written < 0 || (size_t)written >= jb->remaining) return -1;
    jb->buffer += written;
    jb->remaining -= (size_t)written;
    jb->is_first = false;
    return 0;
}

int json_add_bool(JsonBuilder *jb, const char *key, bool value) {
    if (!jb || !jb->buffer || !key) return -1;
    const char *comma = jb->is_first ? "" : ", ";
    const char *bool_str = value ? "true" : "false";
    int written = snprintf(jb->buffer, jb->remaining, "%s\"%s\": %s", comma, key, bool_str);
    if (written < 0 || (size_t)written >= jb->remaining) return -1;
    jb->buffer += written;
    jb->remaining -= (size_t)written;
    jb->is_first = false;
    return 0;
}

int json_end(JsonBuilder *jb) {
    if (!jb || !jb->buffer || jb->remaining < 2) return -1;
    *jb->buffer = '}';
    jb->buffer[1] = '\0';
    jb->buffer++;
    jb->remaining--;
    return 0;
}

int json_extract_str(const char *json, const char *key, char *out_buffer, size_t out_size) {
    if (!json || !key || !out_buffer || out_size == 0) return -1;

    jsmn_parser p;
    jsmntok_t t[128];
    jsmn_init(&p);
    int r = jsmn_parse(&p, json, strlen(json), t, 128);
    if (r < 0) {
        fprintf(stderr, "Invalid JSON or too many tokens\n");
        return -1;
    }

    size_t target_key_len = strlen(key);
    for (int i = 1; i + 1 < r; i++) {
        if (t[i].type == JSMN_STRING && t[i].size == 1) {
            int key_len = t[i].end - t[i].start;
            if (key_len >= 0 && (size_t)key_len == target_key_len &&
                strncmp(json + t[i].start, key, (size_t)key_len) == 0) {
                jsmntok_t *val_tok = &t[i + 1];
            if (val_tok->type != JSMN_STRING) {
                return -1; // Type mismatch: value is not a string
            }
            int val_len = val_tok->end - val_tok->start;
            if (val_len < 0 || (size_t)val_len >= out_size) {
                fprintf(stderr, "Buffer size exceeded\n");
                return -1;
            }
            memcpy(out_buffer, json + val_tok->start, (size_t)val_len);
            out_buffer[val_len] = '\0';
            return 0;
                }
        }
    }
    return -1;
}

int json_extract_int(const char *json, const char *key, long long *out_val) {
    if (!json || !key || !out_val) return -1;

    jsmn_parser p;
    jsmntok_t t[128];
    jsmn_init(&p);
    int r = jsmn_parse(&p, json, strlen(json), t, 128);
    if (r < 0) {
        fprintf(stderr, "Invalid JSON or too many tokens\n");
        return -1;
    }

    size_t target_key_len = strlen(key);
    for (int i = 1; i + 1 < r; i++) {
        if (t[i].type == JSMN_STRING && t[i].size == 1) {
            int key_len = t[i].end - t[i].start;
            if (key_len >= 0 && (size_t)key_len == target_key_len &&
                strncmp(json + t[i].start, key, (size_t)key_len) == 0) {
                jsmntok_t *val_tok = &t[i + 1];
            if (val_tok->type != JSMN_PRIMITIVE) {
                return -1; // Type mismatch: value is not a primitive
            }
            int val_len = val_tok->end - val_tok->start;
            if (val_len <= 0 || val_len >= 32) {
                fprintf(stderr, "Number invalid or too massive\n");
                return -1;
            }
            char temp[33];
            memcpy(temp, json + val_tok->start, (size_t)val_len);
            temp[val_len] = '\0';

            char *endptr = NULL;
            errno = 0;
            long long parsed = strtoll(temp, &endptr, 10);
            if (errno != 0 || endptr == temp || *endptr != '\0') {
                return -1; // Not a valid integer (e.g., null, true, or float)
            }
            *out_val = parsed;
            return 0;
                }
        }
    }
    return -1;
}

int json_extract_bool(const char *json, const char *key, bool *out_val) {
    if (!json || !key || !out_val) return -1;

    jsmn_parser p;
    jsmntok_t t[128];
    jsmn_init(&p);
    int r = jsmn_parse(&p, json, strlen(json), t, 128);
    if (r < 0) {
        fprintf(stderr, "Invalid JSON or too many tokens\n");
        return -1;
    }

    size_t target_key_len = strlen(key);
    for (int i = 1; i + 1 < r; i++) {
        if (t[i].type == JSMN_STRING && t[i].size == 1) {
            int key_len = t[i].end - t[i].start;
            if (key_len >= 0 && (size_t)key_len == target_key_len &&
                strncmp(json + t[i].start, key, (size_t)key_len) == 0) {
                jsmntok_t *val_tok = &t[i + 1];
            if (val_tok->type != JSMN_PRIMITIVE) {
                return -1;
            }
            int val_len = val_tok->end - val_tok->start;
            if (val_len == 4 && strncmp(json + val_tok->start, "true", 4) == 0) {
                *out_val = true;
                return 0;
            } else if (val_len == 5 && strncmp(json + val_tok->start, "false", 5) == 0) {
                *out_val = false;
                return 0;
            } else {
                fprintf(stderr, "Invalid value for boolean\n");
                return -1;
            }
                }
        }
    }
    return -1;
}

void json_escape_string(const char* src, char* dest, size_t max_len) {
    if (!src || !dest || max_len == 0) return;

    size_t i = 0, j = 0;
    while (src[i] != '\0' && j + 1 < max_len) {
        switch (src[i]) {
            case '"':  if (j + 2 < max_len) { dest[j++] = '\\'; dest[j++] = '"'; } else goto done; break;
            case '\\': if (j + 2 < max_len) { dest[j++] = '\\'; dest[j++] = '\\'; } else goto done; break;
            case '\n': if (j + 2 < max_len) { dest[j++] = '\\'; dest[j++] = 'n'; } else goto done; break;
            case '\r': if (j + 2 < max_len) { dest[j++] = '\\'; dest[j++] = 'r'; } else goto done; break;
            case '\t': if (j + 2 < max_len) { dest[j++] = '\\'; dest[j++] = 't'; } else goto done; break;
            default:
                if ((unsigned char)src[i] >= 0x20) {
                    dest[j++] = src[i];
                }
                break;
        }
        i++;
    }
    done:
    dest[j] = '\0';
}

void json_unescape_string(char* str) {
    if (!str) return;
    size_t read = 0, write = 0;
    while (str[read] != '\0') {
        if (str[read] == '\\' && str[read + 1] != '\0') {
            read++;
            switch (str[read]) {
                case '"':  str[write++] = '"'; break;
                case '\\': str[write++] = '\\'; break;
                case 'n':  str[write++] = '\n'; break;
                case 'r':  str[write++] = '\r'; break;
                case 't':  str[write++] = '\t'; break;
                default:   str[write++] = str[read]; break;
            }
        } else {
            str[write++] = str[read];
        }
        read++;
    }
    str[write] = '\0';
}
