#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>

void vuln_func() {
    char buf[128];
    read(STDIN_FILENO, buf, 256);
}

int main(int argc, char *argv[]) {
	void *handle = dlopen("libc.so.6", RTLD_NOW | RTLD_GLOBAL);
	printf("%p\n", dlsym(handle, "system"));
    vuln_func();
    write(STDOUT_FILENO, "Hello world!\n", 13);
}
