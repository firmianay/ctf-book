#include<stdio.h>

int global_init_var = 10;
int global_uninit_var;

void func(int sum) {
	printf("%d\n", sum);
}
void main(void) {
	static int local_static_init_var = 20;
	static int local_static_uninit_var;

	int local_init_val = 30;
	int local_uninit_var;

	func(global_init_var + local_init_val + local_static_init_var);
}
