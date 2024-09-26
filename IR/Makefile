build: format
	cmake --build build

buildall: genctor
	cmake --build build

format:
	./scripts/format.sh

genctor:
	./scripts/gen_insn_ctor.py
	./scripts/format.sh

kernel: build
	./scripts/gen_kernel.sh

read: build
	build/read tests/output/${NAME}.o prog

readlog: build
	build/readlog tests/log/${NAME}.txt

.PHONY: build format kernel readlog read genctor
