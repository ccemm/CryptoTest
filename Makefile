# Define the compiler
CC ?= gcc

# Compiler flags (warnings, debugging symbols)
CFLAGS = -Wall -Wextra -g

# OpenSSL libraries required for the server
LIBS = -lssl -lcrypto

# Default target when you just type 'make'
all: server client

# Build the server (requires OpenSSL flags)
server: server.c
	$(CC) $(CFLAGS) server.c -o server $(LIBS)

# Build the client (add $(LIBS) here too if your client also uses OpenSSL)
client: client.c
	$(CC) $(CFLAGS) client.c -o client

# Clean up built executables
clean:
	rm -f server client *.o

# Phony targets don't represent actual files
.PHONY: all clean