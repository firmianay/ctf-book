#include<stdio.h>

void main() {
	char buf[50];
	if (fgets(buf, sizeof buf, stdin) == NULL)
		return;
	printf(buf);
}
