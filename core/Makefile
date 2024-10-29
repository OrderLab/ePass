build: format
	cmake --build build

buildall: genctor
	cmake --build build

format:
	rm -f tests/vmlinux.h
	./scripts/format.sh

genctor:
	./scripts/gen_insn_ctor.py
	./scripts/format.sh

kernel: build
	./scripts/gen_kernel.sh

read: build
	epasstool -m read -p tests/output/${NAME}.o -s prog

readlog: build
	epasstool -m readlog -p tests/log/${NAME}.txt

.PHONY: build format kernel readlog read genctor
