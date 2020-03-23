
CFLAGS += -I ../include -fPIC

.PHONY: all clean release

all: genblk txtok

genblk: genblock.o tok_block.o
	$(LINK.o) -pthread $^ -L../lib -lecc256 -o $@

toktx: txtokens.o toktx.o tokens.o
	$(LINK.o) $^ -L../lib -lecc256 -o $@

clean:
	rm -f *.o
	rm -f genblk

release: all

release: CFLAGS += -O2

release: LDFLAGS += -O

../lib/libtoktx.so: tokens.o toktx.o
	$(LINK.o) -shared $^ -L../lib -lecc256 -o $@
