default:
	gcc -g -fno-stack-protector bof.c -o bof -masm=intel
	gcc -g -fno-stack-protector bof_syscall.c -o bof_syscall -masm=intel
	gcc -g -fno-stack-protector bof_system.c -o bof_system -masm=intel

clean:
	rm bof
