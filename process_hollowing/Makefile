# Makefile — process_hollowing BOF (x64 only)
#
# Builds a COFF object file (.o) consumable by Sliver's COFFLoader.
#
# Prereqs:
#   brew install mingw-w64
#
# Usage:
#   make            # build process_hollowing.x64.o
#   make clean      # remove build artifacts
#   make rebuild    # clean + build

CC      = x86_64-w64-mingw32-gcc
CFLAGS  = -c -masm=intel -fPIC -Wall -Wextra -O2
SRCDIR  = src
TARGET  = process_hollowing.x64.o
SRC     = $(SRCDIR)/process_hollowing.c
HDRS   := $(wildcard $(SRCDIR)/*.h)

.PHONY: all clean rebuild

all: $(TARGET)

$(TARGET): $(SRC) $(HDRS)
	$(CC) $(CFLAGS) -o $@ $(SRC)

rebuild: clean all

clean:
	rm -f $(TARGET)