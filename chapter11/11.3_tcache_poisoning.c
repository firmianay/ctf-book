#include <stdio.h>
#include <stdlib.h>

int main() {
	int64_t *p1, *p2, *p3, target[10];
	printf("target stack: %p\n", target);
	p1 = malloc(0x30);
	fprintf(stderr, "p1 malloc(0x30): %p\n", p1);
	free(p1);
	*p1 = (int64_t)target;
	fprintf(stderr, "free(p1) and overwrite the next ptr\n");
	p2 = malloc(0x30);
	p3 = malloc(0x30);
	fprintf(stderr, "p2 malloc(0x30): %p\np3 malloc(0x30): %p\n", p2, p3);
}
