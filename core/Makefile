BUILD_DIR = build

build: format
	cmake --build $(BUILD_DIR)

buildall: genctor
	cmake --build $(BUILD_DIR)

format:
	./scripts/format.sh

genctor:
	./scripts/gen_insn_ctor.py
	./scripts/format.sh

kernel: build
	./scripts/gen_kernel.sh

test: build
	./$(BUILD_DIR)/test_list
	./$(BUILD_DIR)/test_hashtable
	./$(BUILD_DIR)/test_ptrset

configure:
	@mkdir -p $(BUILD_DIR)
	@if [ ! -f $(BUILD_DIR)/CMakeCache.txt ]; then \
		echo "Initializing CMake..."; \
		cmake -S . -B $(BUILD_DIR) -G Ninja; \
	fi

dist: configure build

.PHONY: build format kernel readlog read genctor test configure
.DEFAULT_GOAL := build
