	.globl _jump_to_bootcode
	.type  _jump_to_bootcode, @function
	_jump_to_bootcode:
		mov.l stack_start, r0
		mov.l @r0, sp
		mov.l eeprom_start, r0
		mov.l @r0, r0
		jmp @r0
	.align 4
stack_start:	.long 0x00000004
eeprom_start:	.long 0x00000000
