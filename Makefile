# Use Clang to compile the common files.
CC = clang

# Package config.
PKG_CONF = pkg-config

ifeq ($(shell which $(PKG_CONF)),)
$(error "Package config not found. Please install it on server.")
endif

# Directories.
BUILD_DIR := build
SRC_DIR := src
MODULES_DIR := modules

COMMON_DIR := $(MODULES_DIR)/common
LIBBPF_DIR := $(MODULES_DIR)/libbpf

# Common source and build directories.
COMMON_BUILD_DIR := $(COMMON_DIR)/build
COMMON_SRC_DIR := $(COMMON_DIR)/src

# LibBPF source directory.
LIBBPF_SRC_DIR := $(LIBBPF_DIR)/src
LIBBPF_OBJS_DIR := $(LIBBPF_SRC_DIR)/staticobjs

# LibBPF objects.
LIBBPF_OBJS = $(LIBBPF_OBJS_DIR)/bpf_prog_linfo.o $(LIBBPF_OBJS_DIR)/bpf.o $(LIBBPF_OBJS_DIR)/btf_dump.o
LIBBPF_OBJS += $(LIBBPF_OBJS_DIR)/btf.o $(LIBBPF_OBJS_DIR)/gen_loader.o $(LIBBPF_OBJS_DIR)/hashmap.o
LIBBPF_OBJS += $(LIBBPF_OBJS_DIR)/libbpf_errno.o $(LIBBPF_OBJS_DIR)/libbpf_probes.o $(LIBBPF_OBJS_DIR)/libbpf.o
LIBBPF_OBJS += $(LIBBPF_OBJS_DIR)/linker.o $(LIBBPF_OBJS_DIR)/netlink.o $(LIBBPF_OBJS_DIR)/nlattr.o
LIBBPF_OBJS += $(LIBBPF_OBJS_DIR)/relo_core.o $(LIBBPF_OBJS_DIR)/ringbuf.o $(LIBBPF_OBJS_DIR)/str_error.o
LIBBPF_OBJS += $(LIBBPF_OBJS_DIR)/strset.o $(LIBBPF_OBJS_DIR)/xsk.o

# Common objects.
COMMON_OBJS := $(COMMON_BUILD_DIR)/utils.o $(COMMON_BUILD_DIR)/cmd_line.o $(COMMON_BUILD_DIR)/config.o

# Source and out files.
AF_XDP_SRC := af_xdp.c
AF_XDP_OUT := af_xdp.o

SEQ_SRC := sequence.c
SEQ_OUT := sequence.o

CMD_LINE_SRC := cmd_line.c
CMD_LINE_OUT := cmd_line.o

# Main object files.
MAIN_OBJS := $(BUILD_DIR)/$(AF_XDP_OUT) $(BUILD_DIR)/$(SEQ_OUT) $(BUILD_DIR)/$(CMD_LINE_OUT)

MAIN_SRC := main.c
MAIN_OUT := pcktbatch

# Global and main flags.
GLOBAL_FLAGS := -O2 -g
MAIN_FLAGS := -pthread -lelf -lz

# Chains.
all: mk_build af_xdp sequence cmd_line main

# Creates the build directory if it doesn't already exist.
mk_build:
	mkdir -p $(BUILD_DIR)

# Build LibBPF objects.
libbpf:
	$(MAKE) -C $(LIBBPF_SRC_DIR)

# Build and install the Packet Batch common submodule (this includes libyaml).
common:
	$(MAKE) -C $(COMMON_DIR)/

common_install:
	$(MAKE) -C $(COMMON_DIR)/ install

# The AF_XDP file.
af_xdp: mk_build
	$(CC) -I $(COMMON_SRC_DIR) -I $(LIBBPF_SRC_DIR) $(GLOBAL_FLAGS) -c -o $(BUILD_DIR)/$(AF_XDP_OUT) $(SRC_DIR)/$(AF_XDP_SRC) 

# The sequence file.
sequence: mk_build
	$(CC) -I $(COMMON_SRC_DIR) -I $(LIBBPF_SRC_DIR) $(GLOBAL_FLAGS) -c -o $(BUILD_DIR)/$(SEQ_OUT) $(SRC_DIR)/$(SEQ_SRC)

# The command line file.
cmd_line: mk_build
	$(CC) $(GLOBAL_FLAGS) -c -o $(BUILD_DIR)/$(CMD_LINE_OUT) $(SRC_DIR)/$(CMD_LINE_SRC)

# The main program.
main: mk_build af_xdp sequence cmd_line $(COMMON_OBJS)
	$(CC) -I $(COMMON_SRC_DIR) -I $(LIBBPF_SRC_DIR) $(GLOBAL_FLAGS) $(MAIN_FLAGS) -o $(BUILD_DIR)/$(MAIN_OUT) $(shell $(PKG_CONF) --libs json-c) $(COMMON_OBJS) $(LIBBPF_OBJS) $(MAIN_OBJS) $(SRC_DIR)/$(MAIN_SRC)

# Cleanup (remove build files).
clean:
	$(MAKE) -C $(LIBBPF_SRC_DIR)/ clean
	$(MAKE) -C $(COMMON_DIR)/ clean
	rm -f $(BUILD_DIR)/*.o
	rm -f $(BUILD_DIR)/$(MAIN_OUT)

# Install executable to $PATH.
install:
	cp $(BUILD_DIR)/$(MAIN_OUT) /usr/bin/$(MAIN_OUT)

.PHONY:

.DEFAULT: all