
CFLAGS += -I../include -I/usr/include/mariadb -fPIC

VPATH = ../ecc256

.PHONY: all clean release

all: genblk toktx ../lib/libtoktx.so

eccobj = ecc_secp256k1.o sha256.o dscrc.o base64.o dsaes.o ripemd160.o alsarec.o

genblk: genblock.o tok_block.o
	$(LINK.o) -pthread $^ -L../lib -lecc256 -o $@

toktx: txtokens.o toktx.o tokens.o virtmach.o global_param.o $(eccobj)
	$(LINK.o) $^ -lmariadb -lasound -lgmp -o $@

clean:
	rm -f *.o
	rm -f genblk toktx

release: all

release: CFLAGS += -O2

release: LDFLAGS += -O1

../lib/libtoktx.so: tokens.o toktx.o virtmach.o $(eccobj)
	$(LINK.o) -shared -Bsymblic $^ -lmariadb -lgmp -lasound -o $@
