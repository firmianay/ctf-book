#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
 
int main() {
	int stack;
	int *heap = malloc(sizeof(int));
	void *handle = dlopen("libc.so.6", RTLD_NOW | RTLD_GLOBAL);

	printf("executable: %p\n", &main);
	printf("system@plt: %p\n", &system);
	printf("heap: %p\n", heap);
	printf("stack: %p\n", &stack);
	printf("libc: %p\n", handle);

	free(heap);
	return 0;
}
