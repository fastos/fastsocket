/*
 * scsi_wait_scan.c
 *
 * Copyright (C) 2006 James Bottomley <James.Bottomley@SteelEye.com>
 *
 * This is a simple module to wait until all the async scans are
 * complete.  The idea is to use it in initrd/initramfs scripts.  You
 * modprobe it after all the modprobes of the root SCSI drivers and it
 * will wait until they have all finished scanning their busses before
 * allowing the boot to proceed
 */

#include <linux/module.h>
#include <linux/device.h>

static int __init wait_scan_init(void)
{
	/*
	 * This will not return until all async work (system wide) is
	 * quiesced.  Probing queues host-scanning work to the async
	 * queue which is why we don't need a separate call to
	 * scsi_complete_async_scans()
	 */
	wait_for_device_probe();
	return 0;
}

static void __exit wait_scan_exit(void)
{
}

MODULE_DESCRIPTION("SCSI wait for scans");
MODULE_AUTHOR("James Bottomley");
MODULE_LICENSE("GPL");

module_init(wait_scan_init);
module_exit(wait_scan_exit);
