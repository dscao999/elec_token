#include <string.h>
#include <stdlib.h>
#include "loglog.h"
#include "virtmach.h"
#include "base64.h"
#include "ecc_secp256k1.h"

#define VMACH_SCRATCH	8192
#define VMACH_BUFLEN	2097152

struct vmach *vmach_init(const unsigned char *dgst, int len)
{
	struct vmach *vm;
	int i, chunk_len;

	if (len > 128)
		return NULL;

	chunk_len = VMACH_BUFLEN + VMACH_SCRATCH + sizeof(struct vmach);
	vm = mmap(NULL, chunk_len, PROT_READ|PROT_WRITE,
			MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (vm) {
		vm->ripe = ripemd160_init();
		if (!vm->ripe) {
			free(vm);
			vm = NULL;
		} else {
			vm->chunk_len = chunk_len;
			vm->top = VMACH_STACK_SIZE;
			vm->buflen = VMACH_BUFLEN;
			vm->scratch = vm->buf + vm->buflen;
			vm->bufpos = 0;
			for (i = 0; i < VMACH_STACK_SIZE; i++)
				vm->stack[i] = NULL;
			vm->dgstlen = len;
			memcpy(vm->dgst, dgst, len);
		}
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
	return 0;
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
	return 0;
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
		tf = 0;
	else 
		tf = 1;
	return tf;
}
static int vmach_ripemd160(struct vmach *vm)
{
	int spos, msglen;
	unsigned char *msg, *ct;
	struct ecc_key *ecckey;
	char *keystr;

	if (vmach_stack_empty(vm))
		return -ENOMEM;
	spos = vm->top;
	ct = vm->stack[spos];
	msglen = *ct;
	msg = ct + 1;
	keystr = vm->scratch;
	ecckey = vm->scratch + msglen + 1;
	memcpy(keystr, msg, msglen);
	keystr[msglen] = 0;
	ecc_key_import(ecckey, keystr);
	ripemd160_dgst(vm->ripe, (void *)ecckey->px, ECCKEY_INT_LEN*8);
	vm->bufpos -= (msglen + 1);
	msglen = bignum2str_b64((char *)msg, vm->buflen - vm->bufpos,
			vm->ripe->H, RIPEMD_LEN/4);
	*ct = msglen + 1;
	msg[msglen] = 0;
	ripemd160_reset(vm->ripe);
	vm->bufpos += (msglen + 2);
	return 0;
}

int cmd_execute(struct vmach *vm, unsigned char cmd)
{
	int retv = 0;

	switch(cmd) {
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
		retv = vmach_checksig(vm);
		break;
	default:
		retv = -1;
	}
	return retv;
}

int vmach_execute(struct vmach *vm, const unsigned char *script, int len)
{
	int retv = 0, pos = 0;
	const unsigned char *token;

	token = script;
	do {
		if ((*token & 0x80)) {
			retv = cmd_execute(vm, *token);
		} else {
			len = *token;
			retv = vmach_pushdata(vm, token+1, len);
			pos += len + 1;
			token += len + 1;
		}
	} while (pos < len && retv == 0);
	if (retv != 0 || !vmach_stack_empty(vm))
		retv = 1;

	return retv;
}
