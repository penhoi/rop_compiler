default:
	gcc -g -fno-stack-protector bof.c -o bof -masm=intel
	gcc -g -fno-stack-protector bof_syscall.c -o bof_syscall -masm=intel
	gcc -g -fno-stack-protector bof_system.c -o bof_system -masm=intel
	gcc -g -fno-stack-protector bof_shell.c -o bof_shell -masm=intel

clean:
	rm bof
