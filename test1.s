	.file	"test1.c"
	.text
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
	movl	$1, %eax
	movl	-12(%ebp), %ecx
	movl	__stack_chk_guard, %edx
	cmpl	%edx, %ecx
	je	.L3
	call	__stack_chk_fail
.L3:
	leave
	.cfi_restore 5
	.cfi_def_cfa 4, 4
	ret
	.cfi_endproc
.LFE0:
	.size	my_fn_1, .-my_fn_1
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
	movl	$0, %eax
	movl	-12(%ebp), %ecx
	movl	__stack_chk_guard, %edx
	cmpl	%edx, %ecx
	je	.L6
	call	__stack_chk_fail
.L6:
	leave
	.cfi_restore 5
	.cfi_def_cfa 4, 4
	ret
	.cfi_endproc
.LFE1:
	.size	my_fn_0, .-my_fn_0
	.ident	"GCC: (GNU) 8.2.1 20181105 (Red Hat 8.2.1-5)"
	.section	.note.GNU-stack,"",@progbits
