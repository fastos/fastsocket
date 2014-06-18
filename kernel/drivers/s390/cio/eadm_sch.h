#ifndef EADM_SCH_H
#define EADM_SCH_H

#include <linux/device.h>
#include <linux/timer.h>
#include <linux/list.h>
#include "orb.h"

struct eadm_private {
	union orb orb;
	enum {EADM_IDLE, EADM_BUSY, EADM_NOT_OPER} state;
	struct timer_list timer;
	struct list_head head;
	struct subchannel *sch;
} __aligned(8);

#define get_eadm_private(n) ((struct eadm_private *) sch->private)
#define set_eadm_private(n, p) (sch->private = p)

#endif
