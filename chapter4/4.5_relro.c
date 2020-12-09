#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
	size_t *p = (size_t *) strtol(argv[1], NULL, 16);
    p[0] = 0x41414141;
    printf("RELRO: %x\n", (unsigned int)*p);
    return 0;
}
