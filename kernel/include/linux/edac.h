/*
 * Generic EDAC defs
 *
 * Author: Dave Jiang <djiang@mvista.com>
 *
 * 2006-2008 (c) MontaVista Software, Inc. This file is licensed under
 * the terms of the GNU General Public License version 2. This program
 * is licensed "as is" without any warranty of any kind, whether express
 * or implied.
 *
 */
#ifndef _LINUX_EDAC_H_
#define _LINUX_EDAC_H_

#include <asm/atomic.h>
#include <linux/sysdev.h>

#define EDAC_OPSTATE_INVAL	-1
#define EDAC_OPSTATE_POLL	0
#define EDAC_OPSTATE_NMI	1
#define EDAC_OPSTATE_INT	2

extern int edac_op_state;
extern int edac_err_assert;
extern atomic_t edac_handlers;
extern struct sysdev_class edac_class;

extern int edac_handler_set(void);
extern void edac_atomic_assert_error(void);
extern struct sysdev_class *edac_get_sysfs_class(void);
extern void edac_put_sysfs_class(void);

static inline void opstate_init(void)
{
	switch (edac_op_state) {
	case EDAC_OPSTATE_POLL:
	case EDAC_OPSTATE_NMI:
		break;
	default:
		edac_op_state = EDAC_OPSTATE_POLL;
	}
	return;
}

/**
 * enum hw_event_mc_err_type - type of the detected error
 *
 * @HW_EVENT_ERR_CORRECTED:	Corrected Error - Indicates that an ECC
 *				corrected error was detected
 * @HW_EVENT_ERR_UNCORRECTED:	Uncorrected Error - Indicates an error that
 *				can't be corrected by ECC, but it is not
 *				fatal (maybe it is on an unused memory area,
 *				or the memory controller could recover from
 *				it for example, by re-trying the operation).
 * @HW_EVENT_ERR_FATAL:		Fatal Error - Uncorrected error that could not
 *				be recovered.
 */
enum hw_event_mc_err_type {
	HW_EVENT_ERR_CORRECTED,
	HW_EVENT_ERR_UNCORRECTED,
	HW_EVENT_ERR_FATAL,
	HW_EVENT_ERR_INFO,
};

static inline char *mc_event_error_type(const unsigned int err_type)
{
	switch (err_type) {
	case HW_EVENT_ERR_CORRECTED:
		return "Corrected";
	case HW_EVENT_ERR_UNCORRECTED:
		return "Uncorrected";
	case HW_EVENT_ERR_FATAL:
		return "Fatal";
	default:
	case HW_EVENT_ERR_INFO:
		return "Info";
	}
}

#endif
