CC=clang
CXX=clang++

EXPAND_LIB=../install/lib/LLVMExpand.so

CFLAGS:=-m32
BIN_PREFIX=bin

all: cmp_unsigned_const memcmp_const strcpy_overflow switch_case

cmp_unsigned_const: cmp_unsigned_const.c
	$(CC) -Xclang -load -Xclang $(EXPAND_LIB) $(CFLAGS) $@.c -o $(BIN_PREFIX)_$@

memcmp_const: memcmp_const.c
	$(CC) -Xclang -load -Xclang $(EXPAND_LIB) $(CFLAGS) $@.c -o $(BIN_PREFIX)_$@

strcpy_overflow: strcpy_overflow.c
	$(CC) -Xclang -load -Xclang $(EXPAND_LIB) $(CFLAGS) $@.c -o $(BIN_PREFIX)_$@

switch_case: switch_case.c
	$(CC) -Xclang -load -Xclang $(EXPAND_LIB) $(CFLAGS) $@.c -o $(BIN_PREFIX)_$@


clean:
	rm bin_*


