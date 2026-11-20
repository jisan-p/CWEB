CC = gcc
CFLAGS = -Wall -Wextra -std=gnu99 -O3 -fPIC -D_GNU_SOURCE
LDFLAGS = -shared -luring -lpq -lseccomp

SRC_DIR = src
INC_DIR = include
OBJ_DIR = obj
LIB_NAME = libcweb.so

# Find all .c files in the src directory
SRCS = $(wildcard $(SRC_DIR)/*.c)
# Convert .c filenames to .o inside the obj directory
OBJS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))

all: $(LIB_NAME)

# Link the object files into the shared library
$(LIB_NAME): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

# Compile .c files into .o files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -I$(INC_DIR) -c $< -o $@

# Create the object directory if it doesn't exist
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

install: $(LIB_NAME)
	cp $(LIB_NAME) /usr/lib/
	cp $(INC_DIR)/cweb.h /usr/include/
	ldconfig

clean:
	rm -rf $(OBJ_DIR) $(LIB_NAME)

.PHONY: all clean install
