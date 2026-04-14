CC ?= cc
STRIP ?= strip
BIN_DIR ?= bin
TARGET ?= $(BIN_DIR)/scoutless-linux-amd64
SCOUT_SRC := $(wildcard *.c)
ifeq ($(strip $(SCOUT_SRC)),)
$(error SCOUT_SRC empty: no .c files found in current directory)
endif
CFLAGS_COMMON ?= -O2 -pipe -Wall -Wextra -Werror -D_GNU_SOURCE -std=c11
CFLAGS_ASAN ?= -g -O1 -pipe -Wall -Wextra -Werror -D_GNU_SOURCE -std=c11 -fsanitize=address -fsanitize=undefined -fno-omit-frame-pointer
CFLAGS_UBSAN ?= -g -O1 -pipe -Wall -Wextra -Werror -D_GNU_SOURCE -std=c11 -fsanitize=undefined -fno-omit-frame-pointer
CFLAGS_TSAN ?= -g -O0 -pipe -Wall -Wextra -Werror -D_GNU_SOURCE -std=c11 -fsanitize=thread -fno-omit-frame-pointer -fno-optimize-sibling-calls
LDFLAGS_COMMON ?=
LDFLAGS_ASAN ?= -fsanitize=address -fsanitize=undefined
LDFLAGS_UBSAN ?= -fsanitize=undefined
LDFLAGS_TSAN ?= -fsanitize=thread
STRIP_FLAGS ?= -s
.PHONY: all asan ubsan tsan clean
all: $(TARGET)
asan: $(BIN_DIR)/scoutless-asan
ubsan: $(BIN_DIR)/scoutless-ubsan
tsan: $(BIN_DIR)/scoutless-tsan
$(BIN_DIR):
	mkdir -p $@
$(TARGET): $(SCOUT_SRC) | $(BIN_DIR)
	$(CC) $(CFLAGS_COMMON) -o $@ $(filter %.c,$^) $(LDFLAGS_COMMON)
	$(STRIP) $(STRIP_FLAGS) $@ || true
$(BIN_DIR)/scoutless-asan: $(SCOUT_SRC) | $(BIN_DIR)
	$(CC) $(CFLAGS_ASAN) -o $@ $(filter %.c,$^) $(LDFLAGS_ASAN)
$(BIN_DIR)/scoutless-ubsan: $(SCOUT_SRC) | $(BIN_DIR)
	$(CC) $(CFLAGS_UBSAN) -o $@ $(filter %.c,$^) $(LDFLAGS_UBSAN)
$(BIN_DIR)/scoutless-tsan: $(SCOUT_SRC) | $(BIN_DIR)
	$(CC) $(CFLAGS_TSAN) -o $@ $(filter %.c,$^) $(LDFLAGS_TSAN)
clean:
	rm -f $(BIN_DIR)/scoutless-linux-amd64 $(BIN_DIR)/scoutless-asan $(BIN_DIR)/scoutless-ubsan $(BIN_DIR)/scoutless-tsan
