LC0:
	.ascii "\n>> 1+2+3+ ... +9+10= %d\n\n\0"
.globl main 
main:	pushl	%ebp
	movl	%esp, %ebp
	subl	$8, %esp
	xorl	%eax, %eax
	movl	$0xa, %ecx
L2:	addl	%ecx, %eax
	loop	L2
	movl	%eax, 4(%esp)
	movl	$LC0, (%esp)
	call	printf
	leave
	ret
