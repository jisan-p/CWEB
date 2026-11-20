#ifndef PARSER_H
#define PARSER_H

#include "cweb.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <limits.h>
#include <errno.h>

ssize_t scan_buffer(char* buffer); // Checking for full HTTP request
int parse(char* buffer, HttpRequest* request, size_t size);

#endif
