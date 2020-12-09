#include <unistd.h>

void vuln_func() {
	char buf[128];
	read(STDIN_FILENO, buf, 256);
}

int main(int argc, char *argv[]) {
	vuln_func();
	write(STDOUT_FILENO, "Hello world!\n", 13);
}
