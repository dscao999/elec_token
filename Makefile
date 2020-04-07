
CFLAGS += -I../include -I/usr/include/mariadb -fPIC

.PHONY: all clean release

all: genblk toktx

genblk: genblock.o tok_block.o
	$(LINK.o) -pthread $^ -L../lib -lecc256 -o $@

toktx: txtokens.o toktx.o tokens.o virtmach.o
	$(LINK.o) $^ -L../lib -lmariadb -lecc256 -o $@

clean:
	rm -f *.o
	rm -f genblk toktx

release: all

release: CFLAGS += -O2

release: LDFLAGS += -O

../lib/libtoktx.so: tokens.o toktx.o
	$(LINK.o) -shared $^ -L../lib -lecc256 -o $@
