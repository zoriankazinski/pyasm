//#include <stdio.h>

int main(int argc, char *argv[]) {
	extern say_hi();
	say_hi();
}

// gcc -no-pie use_asm_in_c.c use_asm_in_c.o -o use_asm_in_c
