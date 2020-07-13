
CFLAGS += -I../include -I/usr/include/mariadb -fPIC -pthread
CFLAGS += -D_GNU_SOURCE
LDFLAGS += -pthread -g
DBLIB = -lmariadbclient

VPATH = ../ecc256 ../ezini

.PHONY: all clean release

all: genblk toktx ../lib/libtoktx.so tx_service tx_logging edebug

eccobj = ecc_secp256k1.o sha256.o dscrc.o base64.o dsaes.o ripemd160.o rand32bytes.o

genblk: genblock.o tok_block.o global_param.o ezini.o toktx.o tokens.o virtmach.o $(eccobj)
	$(LINK.o) -pthread $^ -lmariadbclient -lgmp -o $@

toktx: txtokens.o toktx.o tokens.o txcheck.o virtmach.o global_param.o ezini.o tok_block.o $(eccobj)
	$(LINK.o) $^ $(DBLIB) -lgmp -o $@

tx_service: tx_service.o toktx.o tokens.o virtmach.o txcheck.o db_probe.o global_param.o ezini.o \
	wcomm.o tok_block.o $(eccobj)
	$(LINK.o) $^ $(DBLIB) -lgmp -o $@

tx_logging: tx_logging.o tok_block.o toktx.o global_param.o ezini.o virtmach.o db_probe.o \
	tokens.o $(eccobj)
	$(LINK.o) $^ $(DBLIB) -lgmp -o $@

edebug: etoken_debug.o tok_block.o toktx.o tokens.o txcheck.o global_param.o ezini.o \
	virtmach.o $(eccobj)
	$(LINK.o) $^ $(DBLIB) -lgmp -o $@

clean:
	rm -f *.o
	rm -f genblk toktx tx_service tx_logging ../lib/libtoktx.so

release: all

release: CFLAGS += -O2

release: LDFLAGS += -O1

../lib/libtoktx.so: tokens.o toktx.o $(eccobj)
	$(LINK.o) -shared $^ -lgmp -o $@

../lib/libtoktx.so: CFLAGS += -DPYTHON_LIB

%.o: %.c
	$(COMPILE.c) -MMD -MP -c $< -o $@

srcs = $(wildcard *.c)
deps = $(srcs:.c=.d)

-include $(deps)
