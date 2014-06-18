/*******************************************************************************

  Copyright(c) 2010 - 2013 Red Hat.  All rights reserved.

  Based on code from Intel 10 Gigabit PCI Express Linux driver
  Copyright(c) 1999 - 2009 Intel Corporation.

  This program is free software; you can redistribute it and/or modify it
  under the terms and conditions of the GNU General Public License,
  version 2, as published by the Free Software Foundation.

  This program is distributed in the hope it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  You should have received a copy of the GNU General Public License along with
  this program; if not, write to the Free Software Foundation, Inc.,
  51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.

  The full GNU General Public License is included in this distribution in
  the file called "COPYING".

*******************************************************************************/

#include <linux/types.h>
#include <linux/module.h>

#include "ixgbe.h"

/* This is the only thing that needs to be changed to adjust the
 * maximum number of ports that the driver can manage.
 */

#define IXGBE_MAX_NIC 16

#define OPTION_UNSET    -1
#define OPTION_DISABLED 0
#define OPTION_ENABLED  1

/* All parameters are treated the same, as an integer array of values.
 * This macro just reduces the need to repeat the same declaration code
 * over and over (plus this helps to avoid typo bugs).
 */

#define IXGBE_PARAM_INIT { [0 ... IXGBE_MAX_NIC] = OPTION_UNSET }
#define IXGBE_PARAM(X, desc) \
	static int X[IXGBE_MAX_NIC+1] = IXGBE_PARAM_INIT; \
	static unsigned int num_##X; \
	module_param_array_named(X, X, int, &num_##X, 0); \
	MODULE_PARM_DESC(X, desc);

/* Interrupt Mode
 *
 * Valid Range: 0-2
 *  - 0 - Legacy Interrupt
 *  - 1 - MSI Interrupt
 *  - 2 - MSI-X Interrupt(s)
 *
 * Default Value: 2
 */
IXGBE_PARAM(IntMode, "Change Interrupt Mode (0=Legacy, 1=MSI, 2=MSI-X), default 2");
#define IXGBE_INT_LEGACY		      0
#define IXGBE_INT_MSI			      1
#define IXGBE_INT_MSIX			      2
#define IXGBE_DEFAULT_INT	 IXGBE_INT_MSIX

/* Flow Director filtering mode
 *
 * Valid Range: 0-1  0 = off, 1 = Hashing
 *
 * Default Value: 1 (Hashing)
 */
IXGBE_PARAM(FdirMode, "Flow Director filtering modes (0=Off, 1=On) default 1");

#define IXGBE_FDIR_FILTER_OFF				0
#define IXGBE_FDIR_FILTER_ON				1
#define IXGBE_DEFAULT_FDIR_FILTER  IXGBE_FDIR_FILTER_ON

struct ixgbe_option {
	enum { enable_option, range_option, list_option } type;
	const char *name;
	const char *err;
	int def;
	union {
		struct { /* range_option info */
			int min;
			int max;
		} r;
	} arg;
};

static int ixgbe_validate_option(unsigned int *value,
                                 struct ixgbe_option *opt)
{
	if (*value == OPTION_UNSET) {
		*value = opt->def;
		return 0;
	}
	if (*value >= opt->arg.r.min && *value <= opt->arg.r.max) {
		printk(KERN_INFO "ixgbe: %s set to %d\n", opt->name, *value);
		return 0;
	}
	printk(KERN_INFO "ixgbe: Invalid %s specified (%d),  %s\n",
	       opt->name, *value, opt->err);
	*value = opt->def;
	return -1;
}

bool ixgbe_adapter_fdir_capable(struct ixgbe_adapter *adapter)
{
	if (num_FdirMode <= adapter->bd_number)
		return true;

	if (FdirMode[adapter->bd_number] == IXGBE_FDIR_FILTER_ON)
		return true;

	return false;

}

void ixgbe_set_fdir_flags(struct ixgbe_adapter *adapter, u32 flags)
{
	u32 *aflags = &adapter->flags;

	/* set flags */
	*aflags |= flags;

	/* remove Fdir flags if module option disabled Fdir */
	if (!ixgbe_adapter_fdir_capable(adapter)) {
		/*
		 * Do not set any flags that will enable the
		 * flow director.
		 */
		*aflags &= ~(IXGBE_FLAG_FDIR_HASH_CAPABLE |
			     IXGBE_FLAG_FDIR_PERFECT_CAPABLE);
		e_dev_info("Flow Director disabled\n");
	}
}

/**
 * ixgbe_check_options - Range Checking for Command Line Parameters
 * @adapter: board private structure
 *
 * This routine checks all command line parameters for valid user
 * input.  If an invalid value is given, or if no user specified
 * value exists, a default value is used.  The final value is stored
 * in a variable in the adapter structure.
 **/
void ixgbe_check_options(struct ixgbe_adapter *adapter)
{
	int bd = adapter->bd_number;
	u32 *aflags = &adapter->flags;

	if (bd >= IXGBE_MAX_NIC) {
		printk(KERN_NOTICE
		       "Warning: no configuration for board #%d\n", bd);
		printk(KERN_NOTICE "Using defaults for all values\n");
	}

	{ /* Interrupt Mode */
		unsigned int i_mode;
		static struct ixgbe_option opt = {
			.type = range_option,
			.name = "Interrupt Mode",
			.err =
			  "using default of "__MODULE_STRING(IXGBE_DEFAULT_INT),
			.def = IXGBE_DEFAULT_INT,
			.arg = { .r = { .min = IXGBE_INT_LEGACY,
					.max = IXGBE_INT_MSIX}}
		};
		/* enable MSI/MSI-X capabilities by default */
		*aflags |= IXGBE_FLAG_MSIX_CAPABLE;
		*aflags |= IXGBE_FLAG_MSI_CAPABLE;

		if (num_IntMode > bd) {
			/* take the minimum of whatever was set */
			i_mode = IntMode[bd];
			ixgbe_validate_option(&i_mode, &opt);
			switch (i_mode) {
			case IXGBE_INT_MSIX:
				break;
			case IXGBE_INT_LEGACY:
				*aflags &= ~IXGBE_FLAG_MSI_CAPABLE;
				/* fall through */
			case IXGBE_INT_MSI:
				*aflags &= ~IXGBE_FLAG_MSIX_CAPABLE;
				break;
			default:
				*aflags &= ~IXGBE_FLAG_MSIX_CAPABLE;
				*aflags &= ~IXGBE_FLAG_MSI_CAPABLE;
				break;
			}
		}
		/* empty code line with semi-colon */ ;
	}
	{ /* Flow Director filtering mode */
		unsigned int fdir_filter_mode;
		static struct ixgbe_option opt = {
			.type = range_option,
			.name = "Flow Director mode",
			.err = "using default of "
				__MODULE_STRING(IXGBE_DEFAULT_FDIR_FILTER),
			.def = IXGBE_DEFAULT_FDIR_FILTER,
			.arg = {.r = {.min = IXGBE_FDIR_FILTER_OFF,
				      .max = IXGBE_FDIR_FILTER_ON}}
		};

		if (adapter->hw.mac.type == ixgbe_mac_82598EB)
			goto no_flow_director;

		if (num_FdirMode > bd) {
			fdir_filter_mode = FdirMode[bd];
			ixgbe_validate_option(&fdir_filter_mode, &opt);
			FdirMode[bd] = fdir_filter_mode;
		}
no_flow_director:
		/* empty code line with semi-colon */ ;
	}
}
