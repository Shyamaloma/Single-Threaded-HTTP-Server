EXEC    = httpserver
O_FILES = httpserver.o
H_FILES = listener_socket.h iowrapper.h debug.h protocol.h
C_FILES = $(O_FILES:%.o=%.c)

CC      = clang
CFLAGS  = -Wall -Werror -Wextra -pedantic
FORMAT  = clang-format

.PHONY: all
all: $(EXEC)

$(EXEC): $(O_FILES) asgn2_helper_funcs.a
	$(CC) $^ asgn2_helper_funcs.a -o $@

%.o: %.c $(H_FILES)
	$(CC) $(CFLAGS) -c $<

.PHONY: clean
clean:
	rm -f $(EXEC) $(O_FILES)

.PHONY: format
format:
	$(FORMAT) -i -style=file $(C_FILES) $(H_FILES)

