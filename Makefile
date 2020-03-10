
CFLAGS += -I ../include

.PHONY: all clean release

all: genblk

genblk: genblock.o tok_block.o
	$(LINK.o) -pthread $^ -L../lib -lecc256 -o $@


clean:
	rm -f *.o
	rm -f genblk

release: all

release: CFLAGS += -O2

release: LDFLAGS += -O
