#ifndef VIRTMACH_DSCAO__
#define VIRTMACH_DSCAO__
#include <sys/mman.h>
#include "ripemd160.h"
#include "sha256.h"
#include "virtmach_code.h"

#define VMACH_STACK_SIZE	1024

struct vmach {
	int chunk_len;
	int top;
	struct ripemd160 ripe;
	struct sha256 sha;
	void *stack[VMACH_STACK_SIZE];
	int bufpos, buflen;
	void *scratch;
	unsigned char buf[0];
};

void vmach_reset(struct vmach *vm);
struct vmach *vmach_init(void);
int vmach_success(struct vmach *vm);

static inline void vmach_exit(struct vmach *vm)
{
	if (vm)
		munmap(vm, vm->chunk_len);
}

static inline int vmach_stack_empty(const struct vmach *vm)
{
	return vm->top == VMACH_STACK_SIZE;
}
static inline int vmach_stack_full(const struct vmach *vm)
{
	return vm->top == 0;
}

int vmach_execute(struct vmach *vm, const unsigned char *script, int len,
		const unsigned char *array, int array_len);
#endif /* VIRTMACH_DSCAO__ */
