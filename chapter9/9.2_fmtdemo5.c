#include<stdio.h>

void main() {
	int i;
	char str[] = "hello";
	printf("%s %n\n", str, &i);
	printf("%d\n", i);
}
