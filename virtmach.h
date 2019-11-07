#ifndef VIRTMACH_DSCAO__
#define VIRTMACH_DSCAO__
#include <sys/mman.h>

enum vcode {
	OP_NOP = 0x81, OP_CHECKSIG = 0xac, OP_EQUAL = 0x87, OP_DUP = 0x82,
	OP_POPDATA = 0x8d, OP_RIPEMD160 = 0xae
};

struct vmach {
	int len;
	int top;
	void *stack[1024];
	int siglen, bufpos;
	unsigned char sig[128];
	unsigned char buf[0];
};

struct vmach *vmach_init(const unsigned char *sig, int len);

static inline void vmach_exit(struct vmach *vm)
{
	if (vm)
		munmap(vm, vm->len);
}

int vmach_pushdata(struct vmach *vm, const unsigned char *opd, int len);
int vmach_popdata(struct vmach *vm, unsigned char *buf, int buflen);
int vmach_dupdata(struct vmach *vm);

static inline int vmach_stack_empty(const struct vmach *vm)
{
	return vm->top == 1024;
}

int vmach_execute(struct vmach *vm, const unsigned char *script, int len);
#endif /* VIRTMACH_DSCAO__ */
