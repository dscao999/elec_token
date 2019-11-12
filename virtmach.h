#ifndef VIRTMACH_DSCAO__
#define VIRTMACH_DSCAO__
#include <sys/mman.h>
#include "ripemd160.h"
#include "sha256.h"

#define VMACH_STACK_SIZE	1024
enum vcode {
	OP_NOP = 0x81, OP_CHECKSIG = 0xac, OP_EQUALVERIFY = 0x87,
	OP_DUP = 0x82, OP_POPDATA = 0x8d, OP_RIPEMD160 = 0xae
};

struct vmach {
	int chunk_len;
	int top;
	struct ripemd160 *ripe;
	void *stack[VMACH_STACK_SIZE];
	int dgstlen, bufpos, buflen;
	unsigned char dgst[128];
	void *scratch;
	unsigned char buf[0];
};

struct vmach *vmach_init(const unsigned char *dgst, int len);

static inline void vmach_exit(struct vmach *vm)
{
	if (vm) {
		ripemd160_exit(vm->ripe);
		munmap(vm, vm->chunk_len);
	}
}

static inline int vmach_stack_empty(const struct vmach *vm)
{
	return vm->top == VMACH_STACK_SIZE;
}
static inline int vmach_stack_full(const struct vmach *vm)
{
	return vm->top == 0;
}

int vmach_execute(struct vmach *vm, const unsigned char *script, int len);
#endif /* VIRTMACH_DSCAO__ */
