#include <stdio.h>
#include <stdlib.h>

int main() {
	void* p1 = malloc(8);
	void* p2 = malloc(8);
	fprintf(stderr, "malloc two fastbin chunk: p1=%p p2=%p\n", p1, p2);

	free(p1);
	fprintf(stderr, "free p1\n");

	void* p3 = malloc(0x400);
	fprintf(stderr, "malloc large chunk: p3=%p\n", p3);

 	 free(p1);
	fprintf(stderr, "double free p1\n");

	fprintf(stderr, "malloc two fastbin chunk: %p %p\n", malloc(8), malloc(8));
}
