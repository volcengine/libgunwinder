# SPDX-License-Identifier: LGPL-3.0-or-later

CC ?= gcc
CXX ?= c++
AR ?= ar
INSTALL ?= install
PKG_CONFIG ?= pkg-config
CFLAGS_OPT ?= -O2 -DNDEBUG

PREFIX ?= /usr
LIBDIR ?= $(PREFIX)/lib
INCLUDEDIR ?= $(PREFIX)/include
PKGCONFIGDIR ?= $(LIBDIR)/pkgconfig

VERSION ?= 1.0.0
LIB_MAJOR ?= 1

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
SHARED_LIB_SONAME = $(SHARED_LIB).$(LIB_MAJOR)
SHARED_LIB_REAL = $(SHARED_LIB).$(VERSION)
PKG_CONFIG_FILE = lib/libgunwinder.pc

LIBS = -lelf -ldw -lssl -lcrypto -lm -pthread
TOOLS_LIBS = $(LIBS) -liberty

all: $(STATIC_LIB) $(SHARED_LIB) $(TOOL_BINS)

tests: all
	$(Q)bin/test_zero_size_func_lookup
	$(Q)bin/test_public_regs
	$(Q)CXX="$(CXX)" sh tests/cxx_header_smoke.sh

install-smoke: all
	$(Q)sh tests/install_pkg_config_smoke.sh

obj/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(Q)echo "  CC      $@"
	$(Q)$(CC) $(CFLAGS_common) -c $< -o $@

$(STATIC_LIB): $(OBJS) Makefile
	@mkdir -p $(dir $@)
	$(Q)echo "  AR      $@"
	$(Q)$(AR) rcs $@ $(OBJS)

$(SHARED_LIB_REAL): $(OBJS) Makefile
	@mkdir -p $(dir $@)
	$(Q)echo "  CC      $@"
	$(Q)$(CC) -shared -Wl,-soname,$(notdir $(SHARED_LIB_SONAME)) -o $@ $(OBJS) $(LIBS)

$(SHARED_LIB_SONAME): $(SHARED_LIB_REAL)
	$(Q)ln -sf $(notdir $(SHARED_LIB_REAL)) $@

$(SHARED_LIB): $(SHARED_LIB_SONAME)
	$(Q)ln -sf $(notdir $(SHARED_LIB_SONAME)) $@

$(PKG_CONFIG_FILE): FORCE Makefile
	@mkdir -p $(dir $@)
	$(Q)echo "  GEN     $@"
	$(Q){ \
		echo 'prefix=$(PREFIX)'; \
		echo 'libdir=$(LIBDIR)'; \
		echo 'includedir=$(INCLUDEDIR)'; \
		echo ''; \
		echo 'Name: libgunwinder'; \
		echo 'Description: Linux userspace stack unwinding library'; \
		echo 'Version: $(VERSION)'; \
		echo 'Libs: -L$${libdir} -lgunwinder'; \
		if command -v $(PKG_CONFIG) >/dev/null 2>&1 && \
			$(PKG_CONFIG) --exists libdw libelf openssl; then \
			echo 'Requires.private: libdw libelf openssl'; \
			echo 'Libs.private: -lm -pthread'; \
		else \
			echo 'Libs.private: $(LIBS)'; \
		fi; \
		echo 'Cflags: -I$${includedir}'; \
	} > $@

bin/%: tools/%.c $(STATIC_LIB)
	@mkdir -p $(dir $@)
	$(Q)echo "  CC      $@"
	$(Q)$(CC) $(CFLAGS_common) $< -o $@ $(STATIC_LIB) $(TOOLS_LIBS)


install: all $(PKG_CONFIG_FILE)
	@mkdir -p $(DESTDIR)$(LIBDIR)
	@mkdir -p $(DESTDIR)$(INCLUDEDIR)/gunwinder
	@mkdir -p $(DESTDIR)$(PKGCONFIGDIR)
	$(Q)$(INSTALL) -m 0644 $(STATIC_LIB) $(DESTDIR)$(LIBDIR)/
	$(Q)$(INSTALL) -m 0755 $(SHARED_LIB_REAL) $(DESTDIR)$(LIBDIR)/
	$(Q)ln -sf $(notdir $(SHARED_LIB_REAL)) $(DESTDIR)$(LIBDIR)/$(notdir $(SHARED_LIB_SONAME))
	$(Q)ln -sf $(notdir $(SHARED_LIB_SONAME)) $(DESTDIR)$(LIBDIR)/$(notdir $(SHARED_LIB))
	$(Q)$(INSTALL) -m 0644 include/gunwinder/*.h $(DESTDIR)$(INCLUDEDIR)/gunwinder/
	$(Q)$(INSTALL) -m 0644 $(PKG_CONFIG_FILE) $(DESTDIR)$(PKGCONFIGDIR)/

clean:
	@echo "  CLEAN"
	$(Q)rm -rf obj lib bin

FORCE:

.PHONY: all clean install install-smoke tests FORCE
