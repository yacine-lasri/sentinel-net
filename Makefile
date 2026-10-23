# SentinelNet — Makefile

CC      := gcc
CFLAGS  := -Wall -Wextra -Wpedantic -O2 -g -Iinclude
LDFLAGS := -lpcap -lpthread

TARGET  := sentinelnet
SRCDIR  := src
BUILDDIR:= build

SRCS := $(SRCDIR)/main.c     \
        $(SRCDIR)/capture.c  \
        $(SRCDIR)/parser.c   \
        $(SRCDIR)/detector.c \
        $(SRCDIR)/stats.c    \
        $(SRCDIR)/logger.c

OBJS := $(patsubst $(SRCDIR)/%.c, $(BUILDDIR)/%.o, $(SRCS))

.PHONY: all clean run list

all: $(BUILDDIR) logs $(TARGET)

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

logs:
	mkdir -p logs

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "Build OK → ./$(TARGET)"

$(BUILDDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILDDIR) $(TARGET) logs/*.log

list: all
	./$(TARGET) --list
