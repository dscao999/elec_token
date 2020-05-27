
CFLAGS += -I../include -I/usr/include/mariadb -fPIC -pthread
CFLAGS += -D_GNU_SOURCE
LDFLAGS += -pthread -g
DBLIB = -lmariadbclient

VPATH = ../ecc256

.PHONY: all clean release

all: genblk toktx ../lib/libtoktx.so tx_service tx_logging edebug

eccobj = ecc_secp256k1.o sha256.o dscrc.o base64.o dsaes.o ripemd160.o alsarec.o

genblk: genblock.o tok_block.o global_param.o $(eccobj)
	$(LINK.o) -pthread $^ -lgmp -lasound -o $@

toktx: txtokens.o toktx.o tokens.o virtmach.o global_param.o $(eccobj)
	$(LINK.o) $^ $(DBLIB) -lasound -lgmp -o $@

tx_service: tx_service.o toktx.o tokens.o virtmach.o tok_block.o global_param.o \
	wcomm.o $(eccobj)
	$(LINK.o) $^ $(DBLIB) -lasound -lgmp -o $@

tx_logging: tx_logging.o tok_block.o toktx.o global_param.o virtmach.o \
	tokens.o $(eccobj)
	$(LINK.o) $^ $(DBLIB) -lasound -lgmp -o $@

edebug: etoken_debug.o tok_block.o toktx.o tokens.o global_param.o virtmach.o $(eccobj)
	$(LINK.o) $^ $(DBLIB) -lasound -lgmp -o $@

clean:
	rm -f *.o
	rm -f genblk toktx tx_service tx_logging

release: all

release: CFLAGS += -O2

release: LDFLAGS += -O1

../lib/libtoktx.so: tokens.o toktx.o virtmach.o global_param.o $(eccobj)
	$(LINK.o) -shared -Bsymblic $^ $(DBLIB) -lgmp -lasound -o $@
