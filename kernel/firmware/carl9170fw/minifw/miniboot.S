	.globl _start
	.type  _start, @function
	.section ".boot", "ax"
	_start:
		mov.l startcode, r0
		jmp @r0
startcode:	.long 0x00000008
