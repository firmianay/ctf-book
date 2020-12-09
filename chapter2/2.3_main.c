// main.c

extern int shared;
extern void func(int *a, int *b);

int main() {
	int a = 100;
	func(&a, &shared);
	return 0;
}
