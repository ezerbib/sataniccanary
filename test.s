	.file	"test.c"
	.text
	.p2align 4,,15
	.globl	my_fn_1
	.type	my_fn_1, @function
my_fn_1:
.LFB0:
	.cfi_startproc
	pushl	%ebp
	.cfi_def_cfa_offset 8
	.cfi_offset 5, -8
	movl	%esp, %ebp
	.cfi_def_cfa_register 5
	subl	$24, %esp
	movl	__stack_chk_guard, %eax
	movl	%eax, -12(%ebp)
	movl	-12(%ebp), %ecx
	movl	__stack_chk_guard, %edx
	cmpl	%edx, %ecx
	jne	.L5
	leave
	.cfi_remember_state
	.cfi_restore 5
	.cfi_def_cfa 4, 4
	movl	$1, %eax
	ret
.L5:
	.cfi_restore_state
	call	__stack_chk_fail
	.cfi_endproc
.LFE0:
	.size	my_fn_1, .-my_fn_1
	.p2align 4,,15
	.globl	my_fn_0
	.type	my_fn_0, @function
my_fn_0:
.LFB1:
	.cfi_startproc
	pushl	%ebp
	.cfi_def_cfa_offset 8
	.cfi_offset 5, -8
	movl	%esp, %ebp
	.cfi_def_cfa_register 5
	subl	$24, %esp
	movl	__stack_chk_guard, %eax
	movl	%eax, -12(%ebp)
	movl	-12(%ebp), %ecx
	movl	__stack_chk_guard, %edx
	cmpl	%edx, %ecx
	jne	.L9
	leave
	.cfi_remember_state
	.cfi_restore 5
	.cfi_def_cfa 4, 4
	xorl	%eax, %eax
	ret
.L9:
	.cfi_restore_state
	call	__stack_chk_fail
	.cfi_endproc
.LFE1:
	.size	my_fn_0, .-my_fn_0
	.ident	"GCC: (GNU) 8.2.1 20181105 (Red Hat 8.2.1-5)"
	.section	.note.GNU-stack,"",@progbits
