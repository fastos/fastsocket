/*
 * The carl9170 firwmare gets copied into the device's
 * Program RAM (pram), which has a size of 16K, but
 * also has to accomodate the stack the device uses,
 * which starts at the top of the 16k, so we pretend
 * that we just have 16256 (16k - 128) of pram.
 *
 * This section documents some of the other areas
 * mapped into the firmware processor's address space
 * as well.
 */

ENTRY(_start);

MEMORY
{
    eeprom   : ORIGIN = 0x000000, LENGTH = 1024k
    sram     : ORIGIN = 0x100000, LENGTH = 96k
    uart     : ORIGIN = 0x1c0000, LENGTH = 4k
    timer    : ORIGIN = 0x1c1000, LENGTH = 4k
    vflash   : ORIGIN = 0x1c2000, LENGTH = 4k
    wlan     : ORIGIN = 0x1c3000, LENGTH = 4k
    pci2ahb  : ORIGIN = 0x1c4000, LENGTH = 4k
    security : ORIGIN = 0x1c5000, LENGTH = 4k
    gpio     : ORIGIN = 0x1d0000, LENGTH = 4k
    memctl   : ORIGIN = 0x1d1000, LENGTH = 4k
    irqctl   : ORIGIN = 0x1d2000, LENGTH = 4k
    usb      : ORIGIN = 0x1e1000, LENGTH = 4k
    pta      : ORIGIN = 0x1e2000, LENGTH = 4k
    pram     : ORIGIN = 0x200000, LENGTH = 16256
    bogus    : ORIGIN = 0x300000, LENGTH = 8k
}

SECTIONS
{
	.eeprom : { *(.eeprom*) } > eeprom
	.sram	: { *(.sram*) } > sram

	/*
	 * The ar9170 boot code will execute the code
	 * at address 0x04 from the loaded firmware as
	 * such we must ensure our starting routine
	 * is kept at that address.
	 */
	.padding : {
		/* NOP NOP just in case */
		LONG(0x00090009)
	} > pram

	.boot     : { *(.boot) } > pram
	/* anything else can be anywhere */

	.text	: { *(.text*) } > pram
	.rodata	: { *(.rodata*) } > pram
	.bss	: { *(.bss) } > pram
	.data	: { *(.data*) } > pram

	.fwdsc	: { KEEP(*(.fwdsc)) } > bogus
}
