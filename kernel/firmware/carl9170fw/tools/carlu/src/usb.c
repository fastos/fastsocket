/*
 * carlu - userspace testing utility for ar9170 devices
 *
 * USB back-end driver
 *
 * Copyright 2009-2011 Christian Lamparter <chunkeey@googlemail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <stdlib.h>
#include "libusb.h"

#include "carlu.h"
#include "usb.h"
#include "debug.h"
#include "list.h"
#include "cmd.h"

#define ADD_DEV(_vid, _pid, _vs, _ps)	{		\
	.idVendor = _vid,				\
	.idProduct = _pid,				\
	.vendor_name = _vs,				\
	.product_name = _ps				\
}

static const struct {
	uint16_t idVendor;
	uint16_t idProduct;
	char *vendor_name;
	char *product_name;
} dev_list[] = {
	ADD_DEV(0x0cf3, 0x9170, "Atheros", "9170"),
	ADD_DEV(0x0cf3, 0x1001, "Atheros", "TG121N"),
	ADD_DEV(0x0cf3, 0x1002, "TP-Link", "TL-WN821N v2"),
	ADD_DEV(0xcace, 0x0300, "Cace", "Airpcap NX"),
	ADD_DEV(0x07d1, 0x3c10, "D-Link", "DWA 160 A1"),
	ADD_DEV(0x07d1, 0x3a09, "D-Link", "DWA 160 A2"),
	ADD_DEV(0x0846, 0x9010, "Netgear", "WNDA3100"),
	ADD_DEV(0x0846, 0x9001, "Netgear", "WN111 v2"),
	ADD_DEV(0x0ace, 0x1221, "Zydas", "ZD1221"),
	ADD_DEV(0x0586, 0x3417, "ZyXEL", "NWD271N"),
	ADD_DEV(0x0cde, 0x0023, "Z-Com", "UB81 BG"),
	ADD_DEV(0x0cde, 0x0026, "Z-Com", "UB82 ABG"),
	ADD_DEV(0x0cde, 0x0027, "Sphairon", "Homelink 1202"),
	ADD_DEV(0x083a, 0xf522, "Arcadyan", "WN7512"),
	ADD_DEV(0x2019, 0x5304, "Planex", "GWUS300"),
	ADD_DEV(0x04bb, 0x093f, "IO-Data", "WNGDNUS2"),
	ADD_DEV(0x057C, 0x8401, "AVM", "FRITZ!WLAN USB Stick N"),
	ADD_DEV(0x057C, 0x8402, "AVM", "FRITZ!WLAN USB Stick N 2.4"),
};

static libusb_context *usb_ctx;
static LIST_HEAD(active_dev_list);

static int carlusb_event_thread(void *_ar)
{
	struct carlu *ar = (void *)_ar;
	dbg("event thread active and polling.\n");

	while (!ar->stop_event_polling)
		libusb_handle_events(ar->ctx);

	dbg("==> event thread desixed.\n");
	return 0;
}

static int carlusb_is_ar9170(struct libusb_device_descriptor *desc)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(dev_list); i++) {
		if ((desc->idVendor == dev_list[i].idVendor) &&
		    (desc->idProduct == dev_list[i].idProduct)) {
			dbg("== found device \"%s %s\" [0x%04x:0x%04x]\n",
				dev_list[i].vendor_name, dev_list[i].product_name,
				desc->idVendor, desc->idProduct);

			return i;
		}
	}

	return -1;
}

static bool carlusb_is_dev(struct carlu *iter,
			       struct libusb_device *dev)
{
	libusb_device *list_dev;

	if (!iter->dev)
		return false;

	list_dev = libusb_get_device(iter->dev);

	if (libusb_get_bus_number(list_dev) == libusb_get_bus_number(dev) &&
	    libusb_get_device_address(list_dev) == libusb_get_device_address(dev))
		return true;

	return false;
}

int carlusb_show_devinfo(struct carlu *ar)
{
	struct libusb_device_descriptor desc;
	libusb_device *dev;
	int err;

	dev = libusb_get_device(ar->dev);

	err = libusb_get_device_descriptor(dev, &desc);
	if (err)
		return err;

	info("USB Device Information:\n");
	info("\tUSB VendorID:%.4x(%s), ProductID:%.4x(%s)\n",
	     dev_list[ar->idx].idVendor, dev_list[ar->idx].vendor_name,
	     dev_list[ar->idx].idProduct, dev_list[ar->idx].product_name);
	info("\tBus:%d Address:%d\n", libusb_get_bus_number(dev),
	     libusb_get_device_address(dev));

	return 0;
}

static int carlusb_get_dev(struct carlu *ar, bool reset)
{
	struct carlu *iter;
	libusb_device_handle *dev;
	libusb_device **list;
	int ret, err, i, idx = -1;

	ret = libusb_get_device_list(usb_ctx, &list);
	if (ret < 0) {
		err("usb device enum failed (%d)\n", ret);
		return ret;
	}

	for (i = 0; i < ret; i++) {
		struct libusb_device_descriptor desc;

		memset(&desc, 0, sizeof(desc));
		err = libusb_get_device_descriptor(list[i], &desc);
		if (err != 0)
			continue;

		idx = carlusb_is_ar9170(&desc);
		if (idx < 0)
			continue;

		list_for_each_entry(iter, &active_dev_list, dev_list) {
			if (carlusb_is_dev(iter, list[i])) {
				err = -EALREADY;
				break;
			}
		}

		if (err)
			continue;

		err = libusb_open(list[i], &dev);
		if (err != 0) {
			err("failed to open device (%d)\n", err);
			continue;
		}

		err = libusb_kernel_driver_active(dev, 0);
		switch (err) {
		case 0:
			break;
		default:
			err("failed to aquire exculusive access (%d).\n", err);
			goto skip;
		}

		if (reset) {
			err = libusb_reset_device(dev);
			if (err != 0) {
				err("failed to reset device (%d)\n", err);
				goto skip;
			}
		}

		err = libusb_claim_interface(dev, 0);
		if (err == 0) {
			dbg(">device is now under our control.\n");
			break;
		} else {
			err("failed to claim device (%d)\n", err);
			goto skip;
		}

skip:
		libusb_close(dev);
	}

	if (i != ret) {
		ar->idx = idx;
		ar->ctx = usb_ctx;
		ar->dev = dev;
		list_add_tail(&ar->dev_list, &active_dev_list);
		ret = 0;
	} else {
		ret = -ENODEV;
	}

	libusb_free_device_list(list, 1);
	return ret;
}

static void carlusb_tx_cb(struct carlu *ar,
			      struct frame *frame)
{
	if (ar->tx_cb)
		ar->tx_cb(ar, frame);

	ar->tx_octets += frame->len;

	carlu_free_frame(ar, frame);
}

static void carlusb_zap_queues(struct carlu *ar)
{
	struct frame *frame;

	BUG_ON(SDL_mutexP(ar->tx_queue_lock) != 0);
	while (!list_empty(&ar->tx_queue)) {
		frame = list_first_entry(&ar->tx_queue, struct frame, dcb.list);
		list_del(&frame->dcb.list);
		carlusb_tx_cb(ar, frame);
	}
	SDL_mutexV(ar->tx_queue_lock);
}

static void carlusb_free_driver(struct carlu *ar)
{
	if (!IS_ERR_OR_NULL(ar)) {
		if (ar->event_pipe[0] > -1)
			close(ar->event_pipe[0]);

		if (ar->event_pipe[1] > -1)
			close(ar->event_pipe[1]);

		carlusb_zap_queues(ar);
		carlfw_release(ar->fw);
		ar->fw = NULL;

		if (ar->dev) {
			libusb_release_interface(ar->dev, 0);
			libusb_close(ar->dev);
			ar->dev = NULL;
		}
		carlu_free_driver(ar);
	}
}

static int carlusb_init(struct carlu *ar)
{
	init_list_head(&ar->tx_queue);
	ar->tx_queue_lock = SDL_CreateMutex();
	ar->event_pipe[0] = ar->event_pipe[1] = -1;

	return 0;
}

static struct carlu *carlusb_open(void)
{
	struct carlu *tmp;
	int err;

	tmp = carlu_alloc_driver(sizeof(*tmp));
	if (tmp == NULL)
		return NULL;

	err = carlusb_init(tmp);
	if (err < 0)
		goto err_out;

	err = carlusb_get_dev(tmp, true);
	if (err < 0)
		goto err_out;

	return tmp;

err_out:
	carlusb_free_driver(tmp);
	return ERR_PTR(err);
}

static void carlusb_cancel_rings(struct carlu *ar)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(ar->rx_ring); i++)
		libusb_cancel_transfer(ar->rx_ring[i]);

	libusb_cancel_transfer(ar->rx_interrupt);
}

static void carlusb_free_rings(struct carlu *ar)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(ar->rx_ring); i++)
		libusb_free_transfer(ar->rx_ring[i]);

	libusb_free_transfer(ar->rx_interrupt);
}

static void carlusb_destroy(struct carlu *ar)
{
	int event_thread_status;

	dbg("==>release device.\n");

	ar->stop_event_polling = true;

	carlusb_cancel_rings(ar);

	SDL_WaitThread(ar->event_thread, &event_thread_status);

	carlusb_free_rings(ar);
	list_del(&ar->dev_list);
}

static void carlusb_tx_bulk_cb(struct libusb_transfer *transfer);

static void carlusb_tx_pending(struct carlu *ar)
{
	struct frame *frame;
	struct libusb_transfer *urb;
	int err;

	BUG_ON(SDL_mutexP(ar->tx_queue_lock) != 0);
	if (ar->tx_queue_len >= (AR9170_TX_MAX_ACTIVE_URBS) ||
	    list_empty(&ar->tx_queue))
		goto out;

	ar->tx_queue_len++;

	urb = libusb_alloc_transfer(0);
	if (urb == NULL)
		goto out;

	frame = list_first_entry(&ar->tx_queue, struct frame, dcb.list);
	list_del(&frame->dcb.list);

	if (ar->tx_stream) {
		struct ar9170_stream *tx_stream;

		tx_stream = frame_push(frame, sizeof(*tx_stream));
		tx_stream->length = cpu_to_le16(frame->len);
		tx_stream->tag = cpu_to_le16(0x697e);
	}

	libusb_fill_bulk_transfer(urb, ar->dev, AR9170_EP_TX, (unsigned char *)
		frame->data, frame->len, carlusb_tx_bulk_cb, (void *)frame, 0);

	/* FIXME: ZERO_PACKET support! */
	urb->flags |= LIBUSB_TRANSFER_FREE_TRANSFER;
/*	urb->flags |= LIBUSB_TRANSFER_ZERO_PACKET; */
	frame->dev = (void *) ar;
	frame_get(frame);

	err = libusb_submit_transfer(urb);
	if (err != 0) {
		err("->usb bulk tx submit failed (%d).\n", err);
		libusb_free_transfer(urb);
	}

out:
	SDL_mutexV(ar->tx_queue_lock);
	return;
}

void carlusb_tx(struct carlu *ar, struct frame *frame)
{
	BUG_ON(SDL_mutexP(ar->tx_queue_lock) != 0);

	list_add_tail(&frame->dcb.list, &ar->tx_queue);
	SDL_mutexV(ar->tx_queue_lock);

	carlusb_tx_pending(ar);
}

static void carlusb_tx_bulk_cb(struct libusb_transfer *transfer)
{
	struct frame *frame = (void *) transfer->user_data;
	struct carlu *ar = (void *) frame->dev;

	BUG_ON(SDL_mutexP(ar->tx_queue_lock) != 0);
	ar->tx_queue_len--;
	SDL_mutexV(ar->tx_queue_lock);

	if (ar->tx_stream)
		frame_pull(frame, 4);

	carlusb_tx_cb(ar, frame);
	carlusb_tx_pending(ar);
}

static void carlusb_rx_interrupt_cb(struct libusb_transfer *transfer)
{
	struct carlu *ar = (void *) transfer->user_data;
	int err;

	switch (transfer->status) {
	case LIBUSB_TRANSFER_COMPLETED:
		carlu_handle_command(ar, transfer->buffer, transfer->actual_length);
		break;

	case LIBUSB_TRANSFER_CANCELLED:
		return;

	default:
		err("==>rx_irq urb died (%d)\n", transfer->status);
		break;
	}

	err = libusb_submit_transfer(transfer);
	if (err != 0)
		err("==>rx_irq urb resubmit failed (%d)\n", err);
}

static void carlusb_rx_bulk_cb(struct libusb_transfer *transfer)
{
	struct frame *frame = (void *) transfer->user_data;
	struct carlu *ar = (void *) frame->dev;
	int err;

	switch (transfer->status) {
	case LIBUSB_TRANSFER_COMPLETED:
		frame_put(frame, transfer->actual_length);

		carlu_rx(ar, frame);

		frame_trim(frame, 0);
		break;

	case LIBUSB_TRANSFER_CANCELLED:
		return;

	default:
		err("==>rx_bulk urb died (%d)\n", transfer->status);
		break;
	}

	err = libusb_submit_transfer(transfer);
	if (err != 0)
		err("->rx_bulk urb resubmit failed (%d)\n", err);
}

static int carlusb_initialize_rxirq(struct carlu *ar)
{
	int err;

	ar->rx_interrupt = libusb_alloc_transfer(0);
	if (ar->rx_interrupt == NULL) {
		err("==>cannot alloc rx interrupt urb\n");
		return -1;
	}

	libusb_fill_interrupt_transfer(ar->rx_interrupt, ar->dev, AR9170_EP_IRQ,
				       (unsigned char *)&ar->irq_buf, sizeof(ar->irq_buf),
				       carlusb_rx_interrupt_cb, (void *) ar, 0);

	err = libusb_submit_transfer(ar->rx_interrupt);
	if (err != 0) {
		err("==>failed to submit rx interrupt (%d)\n", err);
		return err;
	}

	dbg("rx interrupt is now operational.\n");
	return 0;
}

static int carlusb_initialize_rxrings(struct carlu *ar)
{
	struct frame *tmp;
	unsigned int i;
	int err;

	for (i = 0; i < ARRAY_SIZE(ar->rx_ring); i++) {
		tmp = frame_alloc(ar->rx_max);
		if (tmp == NULL)
			return -ENOMEM;

		tmp->dev = (void *) ar;

		ar->rx_ring[i] = libusb_alloc_transfer(0);
		if (ar->rx_ring[i] == NULL) {
			frame_free(tmp);
			return -ENOMEM;
		}

		libusb_fill_bulk_transfer(ar->rx_ring[i], ar->dev,
			AR9170_EP_RX, (unsigned char *)tmp->data,
			ar->rx_max, carlusb_rx_bulk_cb, (void *)tmp, 0);

		err = libusb_submit_transfer(ar->rx_ring[i]);
		if (err != 0) {
			err("==>failed to submit rx buld urb (%d)\n", err);
			return EXIT_FAILURE;
		}
	}

	dbg("rx ring is now ready to receive.\n");
	return 0;
}

static int carlusb_load_firmware(struct carlu *ar)
{
	int ret = 0;

	dbg("loading firmware...\n");

	ar->fw = carlfw_load(CARL9170_FIRMWARE_FILE);
	if (IS_ERR_OR_NULL(ar->fw))
		return PTR_ERR(ar->fw);

	ret = carlu_fw_check(ar);
	if (ret)
		return ret;

	ret = carlusb_fw_check(ar);
	if (ret)
		return ret;

	return 0;
}

static int carlusb_upload_firmware(struct carlu *ar, bool boot)
{
	uint32_t addr = 0x200000;
	size_t len;
	void *buf;
	int ret = 0;

	dbg("initiating firmware image upload procedure.\n");

	buf = carlfw_get_fw(ar->fw, &len);
	if (IS_ERR_OR_NULL(buf))
		return PTR_ERR(buf);

	if (ar->miniboot_size) {
		dbg("Miniboot firmware size:%d\n", ar->miniboot_size);
		len -= ar->miniboot_size;
		buf += ar->miniboot_size;
	}

	while (len) {
		int blocklen = len > 4096 ? 4096 : len;

		ret = libusb_control_transfer(ar->dev, 0x40, 0x30, addr >> 8, 0, buf, blocklen, 1000);
		if (ret != blocklen && ret != LIBUSB_ERROR_TIMEOUT) {
			err("==>firmware upload failed (%d)\n", ret);
			return -EXIT_FAILURE;
		}

		dbg("uploaded %d bytes to start address 0x%04x.\n", blocklen, addr);

		buf += blocklen;
		addr += blocklen;
		len -= blocklen;
	}

	if (boot) {
		ret = libusb_control_transfer(ar->dev, 0x40, 0x31, 0, 0, NULL, 0, 5000);
		if (ret < 0) {
			err("unable to boot firmware (%d)\n", ret);
			return -EXIT_FAILURE;
		}

		/* give the firmware some time to reset & reboot */
		SDL_Delay(100);

		/*
		 * since the device did a full usb reset,
		 * we have to get a new "dev".
		 */
		libusb_release_interface(ar->dev, 0);
		libusb_close(ar->dev);
		ar->dev = NULL;
		list_del(&ar->dev_list);

		ret = carlusb_get_dev(ar, false);
	}

	return 0;
}

int carlusb_cmd_async(struct carlu *ar, struct carl9170_cmd *cmd,
		      const bool free_buf)
{
	struct libusb_transfer *urb;
	int ret, send;

	if (cmd->hdr.len > (CARL9170_MAX_CMD_LEN - 4)) {
		err("|-> too much payload\n");
		ret = -EINVAL;
		goto out;
	}

	if (cmd->hdr.len % 4) {
		err("|-> invalid command length\n");
		ret = -EINVAL;
		goto out;
	}

	ret = libusb_interrupt_transfer(ar->dev, AR9170_EP_CMD, (void *) cmd, cmd->hdr.len + 4, &send, 32);
	if (ret != 0) {
		err("OID:0x%.2x failed due to (%d) (%d).\n", cmd->hdr.cmd, ret, send);
		print_hex_dump_bytes(ERROR, "CMD:", cmd, cmd->hdr.len);
	}

out:
	if (free_buf)
		free((void *)cmd);

	return ret;
}

int carlusb_cmd(struct carlu *ar, uint8_t oid,
		      uint8_t *cmd, size_t clen,
		      uint8_t *rsp, size_t rlen)
{
	int ret, send;

	if (clen > (CARL9170_MAX_CMD_LEN - 4)) {
		err("|-> OID:0x%.2x has too much payload (%d octs)\n", oid, (int)clen);
		return -EINVAL;
	}

	ret = SDL_mutexP(ar->resp_lock);
	if (ret != 0) {
		err("failed to acquire resp_lock.\n");
		print_hex_dump_bytes(ERROR, "CMD:", ar->cmd.buf, clen);
		return -1;
	}

	ar->cmd.cmd.hdr.len = clen;
	ar->cmd.cmd.hdr.cmd = oid;
	/* buf[2] & buf[3] are padding */
	if (clen && cmd != (uint8_t *)(&ar->cmd.cmd.data))
		memcpy(&ar->cmd.cmd.data, cmd, clen);

	ar->resp_buf = (uint8_t *)rsp;
	ar->resp_len = rlen;

	ret = carlusb_cmd_async(ar, &ar->cmd.cmd, false);
	if (ret != 0) {
		err("OID:0x%.2x failed due to (%d) (%d).\n", oid, ret, send);
		print_hex_dump_bytes(ERROR, "CMD:", ar->cmd.buf, clen);
		SDL_mutexV(ar->resp_lock);
		return ret;
	}

	ret = SDL_CondWaitTimeout(ar->resp_pend, ar->resp_lock, 100);
	if (ret != 0) {
		err("|-> OID:0x%.2x timed out %d.\n", oid, ret);
		ar->resp_buf = NULL;
		ar->resp_len = 0;
		ret = -ETIMEDOUT;
	}

	SDL_mutexV(ar->resp_lock);
	return ret;
}

struct carlu *carlusb_probe(void)
{
	struct carlu *ar;
	int ret = -ENOMEM;

	ar = carlusb_open();
	if (IS_ERR_OR_NULL(ar)) {
		if (IS_ERR(ar))
			ret = PTR_ERR(ar);
		goto err_out;
	}

	ret = carlusb_show_devinfo(ar);
	if (ret)
		goto err_out;

	ret = carlusb_load_firmware(ar);
	if (ret)
		goto err_out;

	ret = pipe(ar->event_pipe);
	if (ret)
		goto err_out;

	ar->stop_event_polling = false;
	ar->event_thread = SDL_CreateThread(carlusb_event_thread, ar);

	ret = carlusb_upload_firmware(ar, true);
	if (ret)
		goto err_kill;

	ret = carlusb_initialize_rxirq(ar);
	if (ret)
		goto err_kill;

	ret = carlusb_initialize_rxrings(ar);
	if (ret)
		goto err_kill;

	ret = carlu_cmd_echo(ar, 0x44110dee);
	if (ret) {
		err("echo test failed...\n");
		goto err_kill;
	}

	info("firmware is active and running.\n");

	carlu_fw_info(ar);

	return ar;

err_kill:
	carlusb_destroy(ar);

err_out:
	carlusb_free_driver(ar);
	err("usb device rendezvous failed (%d).\n", ret);
	return ERR_PTR(ret);
}

void carlusb_close(struct carlu *ar)
{
	carlu_cmd_reboot(ar);

	carlusb_destroy(ar);
	carlusb_free_driver(ar);
}

int carlusb_print_known_devices(void)
{
	unsigned int i;

	debug_level = INFO;

	info("==> dumping known device list <==\n");
	for (i = 0; i < ARRAY_SIZE(dev_list); i++) {
		info("Vendor:\"%-9s\" Product:\"%-26s\" => USBID:[0x%04x:0x%04x]\n",
		     dev_list[i].vendor_name, dev_list[i].product_name,
		     dev_list[i].idVendor, dev_list[i].idProduct);
	}
	info("==> end of device list <==\n");

	return EXIT_SUCCESS;
}

int usb_init(void)
{
	int ret;

	ret = libusb_init(&usb_ctx);
	if (ret != 0) {
		err("failed to initialize usb subsystem (%d)\n", ret);
		return ret;
	}

	/* like a silent chatterbox! */
	libusb_set_debug(usb_ctx, 2);

	return 0;
}

void usb_exit(void)
{
	libusb_exit(usb_ctx);
}
