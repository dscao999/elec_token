#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "loglog.h"
#include "virtmach.h"
#include "base64.h"
#include "ecc_secp256k1.h"

#define VMACH_SCRATCH	8192
#define VMACH_BUFLEN	2097152

void vmach_reset(struct vmach *vm)
{
	int i;

	vm->top = VMACH_STACK_SIZE;
	vm->buflen = VMACH_BUFLEN;
	vm->scratch = vm->buf + vm->buflen;
	vm->bufpos = 0;
	for (i = 0; i < VMACH_STACK_SIZE; i++)
		vm->stack[i] = NULL;
}

struct vmach *vmach_init(void)
{
	struct vmach *vm;
	int chunk_len;

	chunk_len = VMACH_BUFLEN + VMACH_SCRATCH + sizeof(struct vmach);
	vm = mmap(NULL, chunk_len, PROT_READ|PROT_WRITE,
			MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (vm) {
		vm->chunk_len = chunk_len;
		vmach_reset(vm);
	}

	return vm;
}

static int vmach_dupdata(struct vmach *vm)
{
	int spos, len;
	unsigned char *ct, *nt;

	if (vmach_stack_empty(vm) || vmach_stack_full(vm))
		return -ENOMEM;
	spos = vm->top;
	ct = vm->stack[spos];
	nt = vm->buf + vm->bufpos;
	len = *ct;
	if (len + vm->bufpos + 1 > vm->buflen)
		return -ENOMEM;
	*nt = *ct;
	memcpy(nt+1, ct+1, len);
	spos -= 1;
	vm->stack[spos] = nt;
	vm->bufpos += (len + 1);
	vm->top = spos;
	return len;
}

static int vmach_pushdata(struct vmach *vm, const unsigned char *opd, int len)
{
	int spos;
	unsigned char *buf;

	if (vmach_stack_full(vm) || vm->bufpos + len + 1 > vm->buflen)
		return -ENOMEM;
	spos = vm->top - 1;
	buf = vm->buf + vm->bufpos;
	*buf = len;
	memcpy(buf+1, opd, len);
	vm->stack[spos] = buf;
	vm->top = spos;
	vm->bufpos += (len + 1);
	return len;
}

static int vmach_popdata(struct vmach *vm, unsigned char *buf, int buflen)
{
	int spos, len;
	unsigned char *ct;

	if (vmach_stack_empty(vm))
		return -ENOMEM;
	spos = vm->top;
	ct = vm->stack[spos];
	len = *ct;
	memcpy(buf, ct+1, len > buflen? buflen:len);
	vm->stack[spos] = NULL;
	vm->top++;
	vm->bufpos -= (len + 1);
	return len;
}

static int vmach_push_bool(struct vmach *vm, int tf)
{
	int spos;
	unsigned char *opv;

	if (vmach_stack_full(vm))
		return -ENOMEM;
	spos = vm->top - 1;
	opv = vm->buf + vm->bufpos;
	*opv = 1;
	*(opv+1) = tf;
	vm->bufpos += 2;
	vm->stack[spos] = opv;
	vm->top = spos;
	return 1;
}

static int vmach_op_equalverify(struct vmach *vm)
{
	unsigned char *opl, *opr;
	int l_len, r_len, top, tf;

	top = vm->top;
	opl = vm->stack[top];
	opr = vm->stack[top+1];
	l_len = *opl;
	r_len = *opr;

	vm->stack[top] = NULL;
	vm->stack[top+1] = NULL;
	vm->top = top + 2;
	vm->bufpos -= (r_len + l_len + 2);
	if (l_len == r_len && memcmp(opl+1, opr+1, r_len) == 0)
		tf = 1;
	else 
		tf = 0;
	return tf;
}
static int vmach_ripemd160(struct vmach *vm)
{
	int spos, msglen, mlen;
	unsigned char *msg, *ct;

	if (vmach_stack_empty(vm))
		return -ENOMEM;
	spos = vm->top;
	ct = vm->stack[spos];
	msglen = *ct;
	msg = ct + 1;
	ripemd160_reset(&vm->ripe);
	ripemd160_dgst(&vm->ripe, (void *)msg, msglen);
	vm->bufpos -= (msglen + 1);
	mlen = 20;
	*ct = mlen;
	memcpy(ct+1, &vm->ripe, mlen);
	vm->bufpos += mlen + 1;
	return mlen;
}

static int vmach_checksig(struct vmach *vm, const unsigned char *array,
		int array_len)
{
	int retv = 0, msglen, spos;
	const char *msg;
	struct ecc_key *ekey;
	struct ecc_sig *esig;

	if (vmach_stack_empty(vm))
		return 0;
	ekey = vm->scratch;
	memset(ekey, 0, sizeof(struct ecc_key));
	esig = vm->scratch + sizeof(struct ecc_key);
	spos = vm->top;
	msg = vm->stack[spos];
	msglen = *msg;
	assert(msglen == 64);
	vm->stack[spos] = NULL;
	vm->top++;
	vm->bufpos -= (msglen + 1);
	memcpy(ekey->px, msg+1, msglen);

	if (vmach_stack_empty(vm))
		return 0;
	spos = vm->top;
	msg = vm->stack[spos];
	msglen = *msg;
	assert(msglen == 64);
	vm->stack[spos] = NULL;
	vm->top++;
	vm->bufpos -= (msglen + 1);
	memcpy(esig, msg+1, msglen);
	retv = ecc_verify(esig, ekey, array, array_len);
	return retv;
}

static int vmach_calculate_y(struct vmach *vm)
{
	int len;
	struct ecc_key ekey;
	unsigned char *buf;

	memset(&ekey, 0, sizeof(ekey));
	buf = ((unsigned char *)ekey.pr) + 31;
	len = vmach_popdata(vm, buf, 33);
	if (len != 33)
		return -1;
	ecc_get_public_y(&ekey, *buf);
	len = vmach_pushdata(vm, (const unsigned char *)ekey.px, 64);
	return len;
}

int cmd_execute(struct vmach *vm, unsigned char cmd,
		const unsigned char *array, int array_len)
{
	int retv = 0;

	switch(cmd) {
	case OP_CALCULATE_Y:
		retv = vmach_calculate_y(vm);
		break;
	case OP_DUP:
		retv = vmach_dupdata(vm);
		break;
	case OP_EQUALVERIFY:
		retv = vmach_op_equalverify(vm);
		break;
	case OP_RIPEMD160:
		retv = vmach_ripemd160(vm);
		break;
	case OP_CHECKSIG:
		retv = vmach_checksig(vm, array, array_len);
		break;
	case OP_NOP:
		retv = 1;
		break;
	default:
		retv = -1;
	}
	return retv;
}

int vmach_execute(struct vmach *vm, const unsigned char *script, int slen,
		const unsigned char *array, int array_len)
{
	int retv = 0, pos = 0, len;
	const unsigned char *token;

	token = script;
	do {
		if ((*token & 0x80)) {
			retv = cmd_execute(vm, *token, array, array_len);
			pos += 1;
			token += 1;
		} else {
			len = *token;
			retv = vmach_pushdata(vm, token+1, len);
			pos += len + 1;
			token += len + 1;
		}
	} while (pos < slen && retv > 0);
	return retv;
}

int vmach_success(struct vmach *vm)
{
	unsigned char *len;

	if (vm->top != VMACH_STACK_SIZE - 1)
		return 0;
	len = vm->stack[vm->top];
	if (*len != 1 || *(len+1) == 0)
		return 0;
	vmach_reset(vm);
	return 1;
}
