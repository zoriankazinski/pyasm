SECTION .DATA
	hello:     db 'Hello world!',10
	helloLen:  equ $-hello

SECTION .TEXT
	GLOBAL say_hi

say_hi:
	mov eax,4
	mov ebx,1
	mov ecx,hello
	mov edx,helloLen
	int 80h
        ret

; nasm -f elf64 X
