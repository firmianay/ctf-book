#include<stdio.h>
#include<string.h>
#include<stdlib.h>

int main(int argc, char **argv) {
	char buf1[10], buf2[10], *s;
	int num;

	memcpy(buf1, argv[1], 10);				// safe
	strcpy(buf2, "AAAABBBBC");
	printf("%s %s\n", buf1, buf2);

	memcpy(buf1, argv[2], atoi(argv[3]));		// unknown
	strcpy(buf2, argv[1]);
	printf("%s %s\n", buf1, buf2);

	// memcpy(buf1, argv[1], 11);				// unsafe
	// strcpy(buf2, "AAAABBBBCC");

	s = fgets(buf1, 11, stdin);				// fmt unknown
	printf(buf1, &num);
}
