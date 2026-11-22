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

LDLIBS_common = -lelf -ldw -lzstd -lssl -lcrypto -liberty -lm -pthread -ldl

SRCS = $(wildcard src/*.c)
OBJS = $(patsubst src/%.c,obj/%.o,$(SRCS))

# libdeep.c is a shared-library fixture for test_stable_fp_miss_reload (no
# main): it is built as bin/libdeep.so, not as an executable.
TOOL_SRCS = $(filter-out tools/libdeep.c,$(wildcard tools/*.c))
TOOL_BINS = $(patsubst tools/%.c,bin/%,$(TOOL_SRCS))

STATIC_LIB = lib/libgunwinder.a
SHARED_LIB = lib/libgunwinder.so

all: $(STATIC_LIB) $(SHARED_LIB) $(TOOL_BINS) bin/libdeep.so

TEST_BINS = bin/test_zero_size_func_lookup bin/cfi_stress \
	bin/test_symbol_resolution bin/test_stable_fp_miss_reload

# Every test tool, one after another; the first failure stops the run.
tests: all
	$(Q)set -e; for t in $(TEST_BINS); do echo "  TEST    $$t"; $$t; done

# -MMD: an object also depends on the headers it includes, so a changed
# struct rebuilds every object that lays it out.
obj/%.o: src/%.c Makefile
	@mkdir -p $(dir $@)
	$(Q)echo "  CC      $@"
	$(Q)$(CC) $(CFLAGS_common) -MMD -MP -c $< -o $@

-include $(OBJS:.o=.d)

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
	$(Q)$(CC) $(CFLAGS_common) $< -o $@ $(STATIC_LIB) $(LDLIBS_common)

# The instance check races the maps read: both are wrapped (see the test).
bin/test_identity_race: tools/test_identity_race.c $(STATIC_LIB)
	@mkdir -p $(dir $@)
	$(Q)echo "  CC      $@"
	$(Q)$(CC) $(CFLAGS_common) $< -o $@ $(STATIC_LIB) -Wl,--wrap=gu_get_maps_info,--wrap=fopen $(LDLIBS_common)

# One allocation can be made to fail (see the test).
bin/test_debuginfo_mem: tools/test_debuginfo_mem.c $(STATIC_LIB)
	@mkdir -p $(dir $@)
	$(Q)echo "  CC      $@"
	$(Q)$(CC) $(CFLAGS_common) $< -o $@ $(STATIC_LIB) -Wl,--wrap=realloc $(LDLIBS_common)

bin/libdeep.so: tools/libdeep.c
	@mkdir -p $(dir $@)
	$(Q)echo "  CC      $@"
	$(Q)$(CC) $(CFLAGS_common) -shared $< -o $@


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
