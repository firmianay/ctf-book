#include <stdlib.h>
#include <stdio.h>

int main() {
    void *p1 = malloc(0x10);
    fprintf(stderr, "1st malloc(0x10): %p\n", p1);
    fprintf(stderr, "free the chunk twice\n");
    free(p1);
    free(p1);
    fprintf(stderr, "2nd malloc(0x10): %p\n", malloc(0x10));
    fprintf(stderr, "3rd malloc(0x10): %p\n", malloc(0x10));
}
