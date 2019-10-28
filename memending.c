#include <stdio.h>

int main(int argc, char *argv[])
{
	union {
		unsigned int num;
		struct {
			unsigned char a;
			unsigned char b;
			unsigned char c;
			unsigned char d;
		} snum;
	} tstnum;

	tstnum.num = 0xaabbccdd;
	if ((tstnum.snum.a == 0xaa) && (tstnum.snum.b == 0xbb) &&
			(tstnum.snum.c == 0xcc) && (tstnum.snum.d == 0xdd))
		printf("Big Ending.\n");
	else if ((tstnum.snum.a == 0xdd) && (tstnum.snum.b == 0xcc) &&
			(tstnum.snum.c == 0xbb) && (tstnum.snum.d == 0xaa))
		printf("Little Ending.\n");
	else
		printf("Bizarre Ending, Good Luck!\n");
	return 0;
}
