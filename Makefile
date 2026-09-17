# SPDX-License-Identifier: LGPL-3.0-or-later

CC ?= gcc
AR ?= ar
CFLAGS_OPT ?= -O2 -DNDEBUG

# Detect architecture
UNAME_M := $(shell uname -m)

# Set architecture-specific include path
ifeq ($(UNAME_M),x86_64)
    ARCH_INCLUDE = -I./include/arch/x86
    CFLAGS_ARCH = -DGUNWINDER_X86
else ifeq ($(UNAME_M),aarch64)
    ARCH_INCLUDE = -I./include/arch/arm64
    CFLAGS_ARCH = -DGUNWINDER_ARM64
else
    $(error Unsupported architecture: $(UNAME_M))
endif

CFLAGS_common = -I./include -I./include/gunwinder $(CFLAGS_ARCH) \
	$(ARCH_INCLUDE) -fPIC $(CFLAGS_OPT) $(DEBUG_FLAGS)

ifeq ($(V),1)
Q =
else
Q = @
endif

SRCS = $(wildcard src/*.c)
OBJS = $(patsubst src/%.c,obj/%.o,$(SRCS))

TOOL_SRCS = $(wildcard tools/*.c)
TOOL_BINS = $(patsubst tools/%.c,bin/%,$(TOOL_SRCS))

STATIC_LIB = lib/libgunwinder.a
SHARED_LIB = lib/libgunwinder.so

all: $(STATIC_LIB) $(SHARED_LIB) $(TOOL_BINS)

tests: all
	$(Q)bin/test_zero_size_func_lookup
	$(Q)bin/cfi_stress
	$(Q)bin/test_symbol_resolution

obj/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(Q)echo "  CC      $@"
	$(Q)$(CC) $(CFLAGS_common) -c $< -o $@

$(STATIC_LIB): $(OBJS) Makefile
	@mkdir -p $(dir $@)
	$(Q)echo "  AR      $@"
	$(Q)$(AR) rcs $@ $(OBJS)

$(SHARED_LIB): $(OBJS) Makefile
	@mkdir -p $(dir $@)
	$(Q)echo "  CC      $@"
	$(Q)$(CC) -shared -Wl,-soname,libgunwinder.so -o $@ $(OBJS)

bin/%: tools/%.c $(STATIC_LIB)
	@mkdir -p $(dir $@)
	$(Q)echo "  CC      $@"
	$(Q)$(CC) $(CFLAGS_common) $< -o $@ $(STATIC_LIB) -lelf -ldw -lssl -lcrypto -liberty -lm -pthread


install: all
	@mkdir -p $(DESTDIR)/usr/lib
	@mkdir -p $(DESTDIR)/usr/include/gunwinder
	@cp $(STATIC_LIB) $(DESTDIR)/usr/lib/
	@cp $(SHARED_LIB) $(DESTDIR)/usr/lib/
	@cp include/gunwinder/*.h $(DESTDIR)/usr/include/gunwinder/

clean:
	@echo "  CLEAN"
	$(Q)rm -rf obj lib bin

.PHONY: all clean install tests
