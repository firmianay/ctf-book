#include<stdio.h>

void main() {
	int i;
	printf("%10u%n\n", 1, &i);
	printf("%d\n", i);
	printf("%.50u%n\n", 1, &i);
	printf("%d\n", i);
	printf("%0100u%n\n", 1, &i);
	printf("%d\n", i);
}
