CARGO   ?= cargo
RELEASE ?= 1

ifeq ($(RELEASE),1)
  PROFILE      := --release
  TARGET_DIR   := target/release
else
  PROFILE      :=
  TARGET_DIR   := target/debug
endif

BINS := emuko emukod emuko-debug-jitdiff

.PHONY: all build clean test check fmt clippy dow run

all: build

build:
	$(CARGO) build $(PROFILE)

clean:
	$(CARGO) clean

test:
	$(CARGO) test $(PROFILE)

check:
	$(CARGO) check $(PROFILE)

fmt:
	$(CARGO) fmt

clippy:
	$(CARGO) clippy $(PROFILE) -- -D warnings

dow: build
	$(TARGET_DIR)/emuko dow

run: build
	$(TARGET_DIR)/emukod --autostart
