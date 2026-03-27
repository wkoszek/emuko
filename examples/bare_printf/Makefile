# Detect RISC-V cross-compiler.
# Prefer the bare-metal toolchain; fall back to the Linux one.
ifneq ($(shell command -v riscv64-unknown-elf-gcc 2>/dev/null),)
CROSS := riscv64-unknown-elf-
else ifneq ($(shell command -v riscv64-elf-gcc 2>/dev/null),)
CROSS := riscv64-elf-
else ifneq ($(shell command -v riscv64-linux-gnu-gcc 2>/dev/null),)
CROSS := riscv64-linux-gnu-
else
$(error No RISC-V cross-compiler found. \
  macOS: brew install riscv64-elf-gcc \
  Linux: apt install gcc-riscv64-linux-gnu)
endif

CC      := $(CROSS)gcc
OBJDUMP := $(CROSS)objdump

CFLAGS  := -march=rv64gc -mabi=lp64d -mcmodel=medany -O0 -std=c99 \
           -ffreestanding -nostdlib -nostdinc -fno-pic \
           -Wall -Wextra -Wno-main

TARGET  := bare_printf.elf

all: $(TARGET)

$(TARGET): start.S main.c link.ld
	$(CC) $(CFLAGS) -T link.ld -o $@ start.S main.c

disas: $(TARGET)
	$(OBJDUMP) -d $(TARGET) | less

REPO_ROOT := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))../..
EMUKO     := $(REPO_ROOT)/target/release/emuko

run: $(TARGET)
	cd $(REPO_ROOT) && cargo build --release -q
	$(EMUKO) run ./$(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all disas run clean
