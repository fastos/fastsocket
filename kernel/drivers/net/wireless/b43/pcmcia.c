/*

  Broadcom B43 wireless driver

  Copyright (c) 2007 Michael Buesch <m@bues.ch>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; see the file COPYING.  If not, write to
  the Free Software Foundation, Inc., 51 Franklin Steet, Fifth Floor,
  Boston, MA 02110-1301, USA.

*/

#include "pcmcia.h"

#include <linux/ssb/ssb.h>
#include <linux/slab.h>
#include <linux/module.h>

#include <pcmcia/cs_types.h>
#include <pcmcia/cistpl.h>
#include <pcmcia/ciscode.h>
#include <pcmcia/ds.h>
#include <pcmcia/cisreg.h>


static struct pcmcia_device_id b43_pcmcia_tbl[] = {
	PCMCIA_DEVICE_MANF_CARD(0x2D0, 0x448),
	PCMCIA_DEVICE_MANF_CARD(0x2D0, 0x476),
	PCMCIA_DEVICE_NULL,
};

MODULE_DEVICE_TABLE(pcmcia, b43_pcmcia_tbl);

#ifdef CONFIG_PM
static int b43_pcmcia_suspend(struct pcmcia_device *dev)
{
	struct ssb_bus *ssb = dev->priv;

	return ssb_bus_suspend(ssb);
}

static int b43_pcmcia_resume(struct pcmcia_device *dev)
{
	struct ssb_bus *ssb = dev->priv;

	return ssb_bus_resume(ssb);
}
#else /* CONFIG_PM */
# define b43_pcmcia_suspend		NULL
# define b43_pcmcia_resume		NULL
#endif /* CONFIG_PM */

static int b43_pcmcia_probe(struct pcmcia_device *dev)
{
	struct ssb_bus *ssb;
#if 1 /* in RHEL */
	win_req_t win;
#endif
	int err = -ENOMEM;
	int res = 0;

	ssb = kzalloc(sizeof(*ssb), GFP_KERNEL);
	if (!ssb)
		goto out_error;

	err = -ENODEV;

#if 0 /* Not in RHEL */
	dev->config_flags |= CONF_ENABLE_IRQ;

	dev->resource[2]->flags |=  WIN_ENABLE | WIN_DATA_WIDTH_16 |
			 WIN_USE_WAIT;
	dev->resource[2]->start = 0;
	dev->resource[2]->end = SSB_CORE_SIZE;
	res = pcmcia_request_window(dev, dev->resource[2], 250);
#else
	dev->conf.Attributes = CONF_ENABLE_IRQ;
	dev->conf.IntType = INT_MEMORY_AND_IO;

	win.Attributes =  WIN_ENABLE | WIN_DATA_WIDTH_16 |
			 WIN_USE_WAIT;
	win.Base = 0;
	win.Size = SSB_CORE_SIZE;
	win.AccessSpeed = 250;
	res = pcmcia_request_window(&dev, &win, &dev->win);
#endif

	if (res != 0)
		goto err_kfree_ssb;

#if 0 /* Not in RHEL */
	res = pcmcia_map_mem_page(dev, dev->resource[2], 0);
#else
	res = pcmcia_map_mem_page(dev->win, 0);
#endif
	if (res != 0)
		goto err_disable;

#if 0 /* Not in RHEL */
	if (!dev->irq)
#else
	dev->irq.Attributes = IRQ_TYPE_DYNAMIC_SHARING;
	dev->irq.Handler = NULL; /* The handler is registered later. */
	res = pcmcia_request_irq(dev, &dev->irq);
	if (res != 0)
#endif
		goto err_disable;

	res = pcmcia_enable_device(dev);
	if (res != 0)
		goto err_disable;

#if 0 /* Not in RHEL */
	err = ssb_bus_pcmciabus_register(ssb, dev, dev->resource[2]->start);
#else
	err = ssb_bus_pcmciabus_register(ssb, dev, win.Base);
#endif
	if (err)
		goto err_disable;
	dev->priv = ssb;

	return 0;

err_disable:
	pcmcia_disable_device(dev);
err_kfree_ssb:
	kfree(ssb);
out_error:
	printk(KERN_ERR "b43-pcmcia: Initialization failed (%d, %d)\n",
	       res, err);
	return err;
}

static void b43_pcmcia_remove(struct pcmcia_device *dev)
{
	struct ssb_bus *ssb = dev->priv;

	ssb_bus_unregister(ssb);
	pcmcia_disable_device(dev);
	kfree(ssb);
	dev->priv = NULL;
}

static struct pcmcia_driver b43_pcmcia_driver = {
	.owner		= THIS_MODULE,
#if 0 /* Not in RHEL */
	.name		= "b43-pcmcia",
#else
	.drv		= {
		.name	= "b43-pcmcia",
	},
#endif
	.id_table	= b43_pcmcia_tbl,
	.probe		= b43_pcmcia_probe,
	.remove		= b43_pcmcia_remove,
	.suspend	= b43_pcmcia_suspend,
	.resume		= b43_pcmcia_resume,
};

/*
 * These are not module init/exit functions!
 * The module_pcmcia_driver() helper cannot be used here.
 */
int b43_pcmcia_init(void)
{
	return pcmcia_register_driver(&b43_pcmcia_driver);
}

void b43_pcmcia_exit(void)
{
	pcmcia_unregister_driver(&b43_pcmcia_driver);
}
