.global 	hwkm_entry_point
.global 	hwkm_exit_point
.extern 	printk

hwkm_entry_point:
	push	{r4-r11, lr}
	msr	cpsr_c, #0x13		   @ Enable interrupts
	mov 	r1, r0

	@ Set Configuration Valid and Jazelle Enable bits
	mov	r0, #2
	mcr	p14, 7, r0, c1, c0, 0
	mov	r0, #1
	mcr	p14, 7, r0, c2, c0, 0

	/* 
		R0-R3 Used to cache Java expression stack
		R4 Local variable 0 (‘this’ pointer)
		R5 Pointer to table of SW handlers
		R6 Java stack pointer
		R7 Java variables pointer
		R8 Java constant pool pointer
		R9-R11 Reserved for JVM (not used by h/w)
		R12, R14 Scratch usage / Java return address
		R13 Machine stack pointer
		R15 Java PC
	*/

	@ 0x0 - 0x3FC (0xFF * 4) - Instruction handlers?

	mov	r5, r1			@ Handler table pointer (must be 1024-byte aligned)
	add	r6, r5, #0x800		@ Stack pointer
	add	r7, r5, #0x900		@ Local variables pointer

	@ Set up handler for ireturn bytecode
	adr	r0, ireturn
	str	r0, [r5, #0xAC * 4]

	@ Execute the bytecode
	adr	r12, jazelle_unavailable
	adr	lr, bytecode
	bxj	r12

bytecode:
	.byte	0x05	@ iconst_2
	.byte	0x06	@ iconst_3
	.byte	0x60	@ iadd
	.byte	0xAC	@ ireturn

ireturn:
	@ Get result off the stack
	ldr	r0, [r6, #-4]!

	@ Display it
	mov 	r1, r0
	ldr 	r0, =msg_success
	bl 	printk
	b 	restore

jazelle_unavailable:
	ldr 	r0, =msg_failure
	bl 	printk
restore:
	@ Restore configuration registers to 0
	mov	r0, #0
	mcr	p14, 7, r0, c1, c0, 0
	mcr	p14, 7, r0, c2, c0, 0
	pop	{r4-r11, pc}	

hwkm_exit_point:
	push	{lr}
	ldr	r0, =msg_on_exit
	bl	printk
	pop 	{pc}

msg_success:
	.ascii "Success: %d\n\0"
msg_failure:
	.ascii "Failure!\n\0"
msg_on_entry:
	.ascii	"Hello!\n\0"
msg_on_exit:
	.ascii	"Goodbye!\n\0"
