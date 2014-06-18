ENTRY(_start);

MEMORY
{
    pram     : ORIGIN = 0x200000, LENGTH = 16k
}

SECTIONS
{
	.padding : {
		/* NOP NOP just in case */
		LONG(0x00090009)
	} > pram

	.boot   : { *(.boot) } > pram
	.text	: { *(.text*) } > pram
	.rodata	: { *(.rodata*) } > pram
	.bss	: { *(.bss) } > pram
	.data	: { *(.data*) } > pram
}
