#include <string.h>
#include <stdlib.h>
#include "loglog.h"
#include "virtmach.h"

struct vmach *vmach_init(const unsigned char *sig, int len)
{
	struct vmach *vm;

	vm = mmap(NULL, 2097152, PROT_READ|PROT_WRITE,
			MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (vm) {
		if (len > 128) {
			free(vm);
			vm = NULL;
		} else {
			vm->len = 2097152;
			vm->top = 1024;
			vm->siglen = len;
			vm->bufpos = 0;
			memcpy(vm->sig, sig, len);
		}
	}
	return vm;
}

int vmach_dupdata(struct vmach *vm)
{
	int spos, len;
	unsigned char *ct, *nt;

	spos = vm->top;
	if (vmach_stack_empty(vm))
		return -ENOMEM;
	ct = vm->stack[spos];
	nt = vm->buf + vm->bufpos;
	len = *ct;
	if (len + vm->bufpos + 1 > vm->len - sizeof(struct vmach))
		return -ENOMEM;
	*nt = *ct;
	memcpy(nt+1, ct+1, len);
	spos -= 1;
	vm->stack[spos] = nt;
	vm->bufpos += (len + 1);
	vm->top = spos;
	return 0;
}

int vmach_pushdata(struct vmach *vm, const unsigned char *opd, int len)
{
	int spos = vm->top - 1;
	unsigned char *buf;

	len &= 0x7f;
	if (spos < 0 || vm->bufpos + len + 1 > vm->len - sizeof(struct vmach))
		return -ENOMEM;
	buf = vm->buf + vm->bufpos;
	*buf = len;
	memcpy(buf+1, opd, len);
	vm->stack[spos] = buf;
	vm->top = spos;
	vm->bufpos += (len + 1);
	return len;
}

int vmach_popdata(struct vmach *vm, unsigned char *buf, int buflen)
{
	int spos = vm->top, len;
	unsigned char *ct;

	if (vmach_stack_empty(vm))
		return -ENOMEM;
	ct = vm->stack[spos];
	len = *ct;
	if (buflen < len)
		return -ENOMEM;
	memcpy(buf, ct+1, len);
	vm->top++;
	vm->bufpos -= (len + 1);
	return len;
}

int vmach_execute(struct vmach *vm, const unsigned char *script, int len)
{
/*	int retv = 0, pos = 0, len;
	const unsigned char *scbyte;

	scbyte = script + pos;
	if ((*scbyte & 0x80)) {
	} else {
		len = *scbyte;

	} */
	return 0;
}
