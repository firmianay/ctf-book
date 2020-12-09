// func.c

int shared = 1;
int tmp = 0;

void func(int *a, int *b) {
	tmp = *a;
	*a = *b;
	*b = tmp;
}
