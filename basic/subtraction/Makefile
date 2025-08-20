COMPILER_INCLUDE_DIR:=/usr/local/include
COMPILER_LIB_DIR:=/usr/local/lib
OPENFHE_INCLUDE_DIR:=/usr/local/include
OPENFHE_LIB_DIR:=/usr/local/lib

LLVM_INCLUDE_DIR ?= $(shell llvm-config --includedir)
LLVM_LIB_DIR ?= $(shell llvm-config --libdir)
LLVM_LIBS ?= $(shell llvm-config --libs passes)

.PHONY: config build execute

config:
	@echo "No configure step needed."

build:
	@echo "Running build target"
	clang++ -std=c++17 -g -DNIOBIUM_COMPILER \
		-I"${LLVM_INCLUDE_DIR}" \
		-I"${COMPILER_INCLUDE_DIR}" \
		-I"${OPENFHE_INCLUDE_DIR}" \
		-I"${OPENFHE_INCLUDE_DIR}/openfhe" \
		-I"${OPENFHE_INCLUDE_DIR}/openfhe/binfhe" \
		-I"${OPENFHE_INCLUDE_DIR}/openfhe/core" \
		-I"${OPENFHE_INCLUDE_DIR}/openfhe/pke" \
		-L"${COMPILER_LIB_DIR}" \
		-L"${OPENFHE_LIB_DIR}" \
		-L"${LLVM_LIB_DIR}" \
		-lOPENFHEcore \
		-lOPENFHEpke \
		-lnbcc \
		"${LLVM_LIBS}" \
		cipher_squared.cpp -o cipher_squared

execute:
	@echo "Running example target"
	./cipher_squared n n 6.48074069840786
