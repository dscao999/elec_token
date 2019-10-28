#ifndef VIRTMACH_DSCAO__
#define VIRTMACH_DSCAO__
#include <stdlib.h>

enum vcode {
	OP_NOP = 0x61, OP_CHECKSIG = 0xac, OP_EQUAL = 0x87, OP_VERIFY = 0x69,
	OP_PUSHDATA = 0x4c
};

struct vmach {
	int len;
	unsigned char dgst[0];
};

static inline struct vmach *vmach_init(const void *dgst, int len)
{
	struct vmach *vm;

	vm = malloc(sizeof(struct vmach) + len);
	if (vm) {
		vm->len = len;
		memcpy(vm->dgst, dgst, len);
	}
	return vm;
}

static inline void vmach_exit(struct vmach *vm)
{
	if (vm)
		free(vm);
}

int vmach_execute(struct vmach *vm, const void *script, int len);
#endif /* VIRTMACH_DSCAO__ */
