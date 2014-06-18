/*
 * carl9170 firmware - used by the ar9170 wireless device
 *
 * USB Controller
 *
 * Copyright (c) 2000-2005  ZyDAS Technology Corporation
 * Copyright (c) 2007-2009 Atheros Communications, Inc.
 * Copyright	2009	Johannes Berg <johannes@sipsolutions.net>
 * Copyright 2009-2011	Christian Lamparter <chunkeey@googlemail.com>
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
#include "carl9170.h"
#include "usb.h"
#include "printf.h"
#include "rom.h"

/*
 * NB: The firmware has to write into these structures
 * so don't try to make them "const".
 */

static struct ar9170_usb_config usb_config_highspeed = {
	.cfg = {
		.bLength = USB_DT_CONFIG_SIZE,
		.bDescriptorType = USB_DT_CONFIG,
		.wTotalLength = cpu_to_le16(sizeof(usb_config_highspeed)),
		.bNumInterfaces = 1,
		.bConfigurationValue = 1,
		.iConfiguration = 0,
		.bmAttributes = USB_CONFIG_ATT_ONE |
#ifdef CONFIG_CARL9170FW_WOL
				USB_CONFIG_ATT_WAKEUP |
#endif /* CONFIG_CARL9170FW_WOL */
				0,
		.bMaxPower = 0xfa, /* 500 mA */
	},

	.intf = {
		.bLength = USB_DT_INTERFACE_SIZE,
		.bDescriptorType = USB_DT_INTERFACE,
		.bInterfaceNumber = 0,
		.bAlternateSetting = 0,
		.bNumEndpoints = AR9170_USB_NUM_EXTRA_EP,
		.bInterfaceClass = USB_CLASS_VENDOR_SPEC,
		.bInterfaceSubClass = USB_SUBCLASS_VENDOR_SPEC,
		.bInterfaceProtocol = 0,
		.iInterface = 0,
	},

	.ep = {
		{	/* EP 1 */
			.bLength = USB_DT_ENDPOINT_SIZE,
			.bDescriptorType = USB_DT_ENDPOINT,
			.bEndpointAddress = USB_DIR_OUT | AR9170_USB_EP_TX,
			.bmAttributes = USB_ENDPOINT_XFER_BULK,
			.wMaxPacketSize = cpu_to_le16(512),
			.bInterval = 0,
		},

		{	/* EP 2 */
			.bLength = USB_DT_ENDPOINT_SIZE,
			.bDescriptorType = USB_DT_ENDPOINT,
			.bEndpointAddress = USB_DIR_IN | AR9170_USB_EP_RX,
			.bmAttributes = USB_ENDPOINT_XFER_BULK,
			.wMaxPacketSize = cpu_to_le16(512),
			.bInterval = 0,
		},

		{	/* EP 3 */
			.bLength = USB_DT_ENDPOINT_SIZE,
			.bDescriptorType = USB_DT_ENDPOINT,
			.bEndpointAddress = USB_DIR_IN | AR9170_USB_EP_IRQ,
			.bmAttributes = USB_ENDPOINT_XFER_INT,
			.wMaxPacketSize = cpu_to_le16(64),
			.bInterval = 1,
		},

		{	/* EP 4 */
			.bLength = USB_DT_ENDPOINT_SIZE,
			.bDescriptorType = USB_DT_ENDPOINT,
			.bEndpointAddress = USB_DIR_OUT | AR9170_USB_EP_CMD,
			.bmAttributes = USB_ENDPOINT_XFER_INT,
			.wMaxPacketSize = cpu_to_le16(64),
			.bInterval = 1,
		},
	},
};

static struct ar9170_usb_config usb_config_fullspeed = {
	.cfg = {
		.bLength = USB_DT_CONFIG_SIZE,
		.bDescriptorType = USB_DT_CONFIG,
		.wTotalLength = cpu_to_le16(sizeof(usb_config_fullspeed)),
		.bNumInterfaces = 1,
		.bConfigurationValue = 1,
		.iConfiguration = 0,
		.bmAttributes = USB_CONFIG_ATT_ONE |
#ifdef CONFIG_CARL9170FW_WOL
				USB_CONFIG_ATT_WAKEUP |
#endif /* CONFIG_CARL9170FW_WOL */
				0,
		.bMaxPower = 0xfa, /* 500 mA */
	},

	.intf = {
		.bLength = USB_DT_INTERFACE_SIZE,
		.bDescriptorType = USB_DT_INTERFACE,
		.bInterfaceNumber = 0,
		.bAlternateSetting = 0,
		.bNumEndpoints = AR9170_USB_NUM_EXTRA_EP,
		.bInterfaceClass = USB_CLASS_VENDOR_SPEC,
		.bInterfaceSubClass = USB_SUBCLASS_VENDOR_SPEC,
		.bInterfaceProtocol = 0,
		.iInterface = 0,
	},

	.ep = {
		{	/* EP 1 */
			.bLength = USB_DT_ENDPOINT_SIZE,
			.bDescriptorType = USB_DT_ENDPOINT,
			.bEndpointAddress = USB_DIR_OUT | AR9170_USB_EP_TX,
			.bmAttributes = USB_ENDPOINT_XFER_BULK,
			.wMaxPacketSize = cpu_to_le16(64),
			.bInterval = 0,
		},

		{	/* EP 2 */
			.bLength = USB_DT_ENDPOINT_SIZE,
			.bDescriptorType = USB_DT_ENDPOINT,
			.bEndpointAddress = USB_DIR_IN | AR9170_USB_EP_RX,
			.bmAttributes = USB_ENDPOINT_XFER_BULK,
			.wMaxPacketSize = cpu_to_le16(64),
			.bInterval = 0,
		},

		{	/* EP 3 */
			.bLength = USB_DT_ENDPOINT_SIZE,
			.bDescriptorType = USB_DT_ENDPOINT,
			.bEndpointAddress = USB_DIR_IN | AR9170_USB_EP_IRQ,
			.bmAttributes = USB_ENDPOINT_XFER_INT,
			.wMaxPacketSize = cpu_to_le16(64),
			.bInterval = 1,
		},

		{	/* EP 4 */
			.bLength = USB_DT_ENDPOINT_SIZE,
			.bDescriptorType = USB_DT_ENDPOINT,
			.bEndpointAddress = USB_DIR_OUT | AR9170_USB_EP_CMD,
			.bmAttributes = USB_ENDPOINT_XFER_INT,
			.wMaxPacketSize = cpu_to_le16(64),
			.bInterval = 1,
		},
	},
};

#ifdef CONFIG_CARL9170FW_USB_MODESWITCH
static void usb_reset_eps(void)
{
	unsigned int i;

	/* clear all EPs' toggle bit */
	for (i = 1; i < __AR9170_USB_NUM_MAX_EP; i++) {
		usb_set_input_ep_toggle(i);
		usb_clear_input_ep_toggle(i);
	}

	/*
	 * NB: I've no idea why this cannot be integrated into the
	 * previous loop?
	 */
	for (i = 1; i < __AR9170_USB_NUM_MAX_EP; i++) {
		usb_set_output_ep_toggle(i);
		usb_clear_output_ep_toggle(i);
	}
}
#endif /* CONFIG_CARL9170FW_USB_MODESWITCH */


static void usb_pta_init(void)
{
	unsigned int usb_dma_ctrl = 0;
	/* Set PTA mode to USB */
	andl(AR9170_PTA_REG_DMA_MODE_CTRL,
		~AR9170_PTA_DMA_MODE_CTRL_DISABLE_USB);

	/* Do a software reset to PTA component */
	orl(AR9170_PTA_REG_DMA_MODE_CTRL, AR9170_PTA_DMA_MODE_CTRL_RESET);
	andl(AR9170_PTA_REG_DMA_MODE_CTRL, ~AR9170_PTA_DMA_MODE_CTRL_RESET);

	if (usb_detect_highspeed()) {
		fw.usb.os_cfg_desc = &usb_config_fullspeed;
		fw.usb.cfg_desc = &usb_config_highspeed;

		/* 512 Byte DMA transfers */
		usb_dma_ctrl |= AR9170_USB_DMA_CTL_HIGH_SPEED;
	} else {
		fw.usb.cfg_desc = &usb_config_fullspeed;
		fw.usb.os_cfg_desc = &usb_config_highspeed;
	}

#ifdef CONFIG_CARL9170FW_USB_UP_STREAM
# if (CONFIG_CARL9170FW_RX_FRAME_LEN == 4096)
	usb_dma_ctrl |= AR9170_USB_DMA_CTL_UP_STREAM_4K;
# elif (CONFIG_CARL9170FW_RX_FRAME_LEN == 8192)
	usb_dma_ctrl |= AR9170_USB_DMA_CTL_UP_STREAM_8K;
# elif (CONFIG_CARL9170FW_RX_FRAME_LEN == 16384)
	usb_dma_ctrl |= AR9170_USB_DMA_CTL_UP_STREAM_16K;
# elif (CONFIG_CARL9170FW_RX_FRAME_LEN == 32768)
	usb_dma_ctrl |= AR9170_USB_DMA_CTL_UP_STREAM_32K;
# else
#	error "Invalid AR9170_RX_FRAME_LEN setting"
# endif

#else /* CONFIG_CARL9170FW_USB_UP_STREAM */
	usb_dma_ctrl |= AR9170_USB_DMA_CTL_UP_PACKET_MODE;
#endif /* CONFIG_CARL9170FW_USB_UP_STREAM */

#ifdef CONFIG_CARL9170FW_USB_DOWN_STREAM
	/* Enable down stream mode */
	usb_dma_ctrl |= AR9170_USB_DMA_CTL_DOWN_STREAM;
#endif /* CONFIG_CARL9170FW_USB_DOWN_STREAM */

#ifdef CONFIG_CARL9170FW_USB_UP_STREAM
	/* Set the up stream mode maximum aggregate number */
	set(AR9170_USB_REG_MAX_AGG_UPLOAD, 4);

	/*
	 * Set the up stream mode timeout value.
	 * NB: The vendor driver (otus) set 0x80?
	 */
	set(AR9170_USB_REG_UPLOAD_TIME_CTL, 0x80);
#endif /* CONFIG_CARL9170FW_USB_UP_STREAM */

	/* Enable up stream and down stream */
	usb_dma_ctrl |= AR9170_USB_DMA_CTL_ENABLE_TO_DEVICE |
	    AR9170_USB_DMA_CTL_ENABLE_FROM_DEVICE;

	set(AR9170_USB_REG_DMA_CTL, usb_dma_ctrl);
}

void usb_init(void)
{
	usb_pta_init();

	fw.usb.config = 1;
	/*
	 * The fw structure is always initialized with "0"
	 * during boot(); No need to waste precious bytes here.
	 *
	 * fw.usb.interface_setting = 0;
	 * fw.usb.alternate_interface_setting = 0;
	 * fw.usb.device_feature = 0;
	 */

#ifdef CONFIG_CARL9170FW_WOL
	fw.usb.device_feature |= USB_DEVICE_REMOTE_WAKEUP;
	usb_enable_remote_wakeup();
#endif /* CONFIG_CARL9170FW_WOL */
}

#define GET_ARRAY(a, o)	((uint32_t *) (((unsigned long) data) + offset))

static void usb_ep0rx_data(const void *data, const unsigned int len)
{
	unsigned int offset;
	uint32_t value;

	BUG_ON(len > AR9170_USB_EP_CTRL_MAX);
	BUILD_BUG_ON(len > AR9170_USB_EP_CTRL_MAX);

	for (offset = 0; offset < ((len + 3) & ~3); offset += 4) {
		value = get(AR9170_USB_REG_EP0_DATA);
		memcpy(GET_ARRAY(data, offset), &value,
		       min(len - offset, (unsigned int)4));
	}
}

static int usb_ep0tx_data(const void *data, const unsigned int len)
{
	unsigned int offset = 0, block, last_block = 0;
	uint32_t value;

	BUG_ON(len > AR9170_USB_EP_CTRL_MAX);
	BUILD_BUG_ON(len > AR9170_USB_EP_CTRL_MAX);

	block = min(len, (unsigned int) 4);
	offset = 0;
	while (offset < len) {

		if (last_block != block || block < 4)
			setb(AR9170_USB_REG_FIFO_SIZE, (1 << block) - 1);

		memcpy(&value, GET_ARRAY(data, offset), block);

		set(AR9170_USB_REG_EP0_DATA, value);

		offset += block;
		last_block = block = min(len - offset, (unsigned int) 4);
	}

	setb(AR9170_USB_REG_FIFO_SIZE, 0xf);

	/* this will push the data to the host */
	return 1;
}
#undef GET_ARRAY

#ifdef CONFIG_CARL9170FW_USB_STANDARD_CMDS
static int usb_get_status(const struct usb_ctrlrequest *ctrl)
{
	__le16 status = cpu_to_le16(fw.usb.device_feature);

	if ((ctrl->bRequestType & USB_DIR_MASK) != USB_DIR_IN)
		return -1;

	switch (ctrl->bRequestType & USB_RECIP_MASK) {
	case USB_RECIP_DEVICE:
		status &= cpu_to_le16(~USB_DEVICE_SELF_POWERED);
		status &= cpu_to_le16(~USB_DEVICE_REMOTE_WAKEUP);
		break;

	case USB_RECIP_INTERFACE:
		/* USB spec: This is reserved for future use. */
		status = cpu_to_le16(0);
		break;

	case USB_RECIP_ENDPOINT:
	case USB_RECIP_OTHER:
	default:
		break;
	}

	return usb_ep0tx_data((const void *) &status, sizeof(status));
}

static int usb_get_string_desc(const struct usb_ctrlrequest *ctrl)
{
	const struct usb_string_descriptor *string_desc = NULL;

	switch (le16_to_cpu(ctrl->wValue) & 0xff) {
	case 0x00:
		string_desc = (const struct usb_string_descriptor *)
			rom.hw.usb.string0_desc;
		break;

	case 0x10:
		string_desc = (const struct usb_string_descriptor *)
			rom.hw.usb.string1_desc;
		break;

	case 0x20:
		string_desc = (const struct usb_string_descriptor *)
			rom.hw.usb.string2_desc;
		break;

	case 0x30:
		string_desc = (const struct usb_string_descriptor *)
			rom.hw.usb.string3_desc;
		break;

	default:
		break;
	}

	if (string_desc)
		return usb_ep0tx_data(string_desc, string_desc->bLength);

	return -1;
}

static int usb_get_device_desc(const struct usb_ctrlrequest *ctrl __unused)
{
	return usb_ep0tx_data(&rom.hw.usb.device_desc,
			      rom.hw.usb.device_desc.bLength);
}

static int usb_get_config_desc(const struct usb_ctrlrequest *ctrl __unused)
{
	fw.usb.cfg_desc->cfg.bDescriptorType = USB_DT_CONFIG;

	return usb_ep0tx_data(fw.usb.cfg_desc,
		le16_to_cpu(fw.usb.cfg_desc->cfg.wTotalLength));
}

#ifdef CONFIG_CARL9170FW_USB_MODESWITCH
static int usb_get_otherspeed_desc(const struct usb_ctrlrequest *ctrl __unused)
{

	fw.usb.os_cfg_desc->cfg.bDescriptorType = USB_DT_OTHER_SPEED_CONFIG;

	return usb_ep0tx_data(fw.usb.os_cfg_desc,
		le16_to_cpu(fw.usb.os_cfg_desc->cfg.wTotalLength));
}
#endif /* CONFIG_CARL9170FW_USB_MODESWITCH */

static int usb_get_qualifier_desc(const struct usb_ctrlrequest *ctrl __unused)
{
	struct usb_qualifier_descriptor qual;

	/*
	 * The qualifier descriptor shares some structural details
	 * with the main device descriptor.
	 */

	memcpy(&qual, &rom.hw.usb.device_desc, sizeof(qual));

	/* (Re)-Initialize fields */
	qual.bDescriptorType = USB_DT_DEVICE_QUALIFIER;
	qual.bLength = sizeof(qual);
	qual.bNumConfigurations = rom.hw.usb.device_desc.bNumConfigurations;
	qual.bRESERVED = 0;

	return usb_ep0tx_data(&qual, qual.bLength);
}

#define USB_CHECK_REQTYPE(ctrl, recip, dir)			\
	(((ctrl->bRequestType & USB_RECIP_MASK) != recip) ||	\
	 ((ctrl->bRequestType & USB_DIR_MASK) != dir))

static int usb_get_descriptor(const struct usb_ctrlrequest *ctrl)
{
	int status = -1;

	if (USB_CHECK_REQTYPE(ctrl, USB_RECIP_DEVICE, USB_DIR_IN))
		return status;

	switch (le16_to_cpu(ctrl->wValue) >> 8) {
	case USB_DT_DEVICE:
		status = usb_get_device_desc(ctrl);
		break;

	case USB_DT_CONFIG:
		status = usb_get_config_desc(ctrl);
		break;

	case USB_DT_STRING:
		status = usb_get_string_desc(ctrl);
		break;

	case USB_DT_INTERFACE:
		break;

	case USB_DT_ENDPOINT:
		break;

	case USB_DT_DEVICE_QUALIFIER:
		status = usb_get_qualifier_desc(ctrl);
		break;

#ifdef CONFIG_CARL9170FW_USB_MODESWITCH
	case USB_DT_OTHER_SPEED_CONFIG:
		status = usb_get_otherspeed_desc(ctrl);
		break;
#endif /* CONFIG_CARL9170FW_USB_MODESWITCH */
	default:
		break;

	}

	return status;
}

static int usb_get_configuration(const struct usb_ctrlrequest *ctrl)
{
	if (USB_CHECK_REQTYPE(ctrl, USB_RECIP_DEVICE, USB_DIR_IN))
		return -1;

	return usb_ep0tx_data(&fw.usb.config, 1);
}

static int usb_set_configuration(const struct usb_ctrlrequest *ctrl)
{
	unsigned int config;

	if (USB_CHECK_REQTYPE(ctrl, USB_RECIP_DEVICE, USB_DIR_OUT))
		return -1;

	config = le16_to_cpu(ctrl->wValue);
	switch (config) {
	case 0:
		/* Disable Device */
		andb(AR9170_USB_REG_DEVICE_ADDRESS,
		      (uint8_t) ~(AR9170_USB_DEVICE_ADDRESS_CONFIGURE));
#ifdef CONFIG_CARL9170FW_USB_MODESWITCH
	case 1:
		fw.usb.config = config;

		if (usb_detect_highspeed()) {
			/* High Speed Configuration */
			usb_init_highspeed_fifo_cfg();
		} else {
			/* Full Speed Configuration */
			usb_init_fullspeed_fifo_cfg();
		}
		break;

	default:
		return -1;
	}
	/* usb_pta_init() ? */

	usb_reset_eps();
	orb(AR9170_USB_REG_DEVICE_ADDRESS,
	    (AR9170_USB_DEVICE_ADDRESS_CONFIGURE));

	usb_enable_global_int();
	usb_trigger_out();
	return 1;
#else
	default:
		return -1;
	}
#endif /* CONFIG_CARL9170FW_USB_MODESWITCH */
}

static int usb_set_address(const struct usb_ctrlrequest *ctrl)
{
	unsigned int address;

	if (USB_CHECK_REQTYPE(ctrl, USB_RECIP_DEVICE, USB_DIR_OUT))
		return -1;

	address = le16_to_cpu(ctrl->wValue);

	/*
	 * The original firmware used 0x100 (which is, of course,
	 * too big to fit into uint8_t).
	 * However based on the available information (hw.h), BIT(7)
	 * is used as some sort of flag and should not be
	 * part of the device address.
	 */
	if (address >= BIT(7))
		return -1;

	setb(AR9170_USB_REG_DEVICE_ADDRESS, (uint8_t) address);
	return 1;
}

static int usb_get_interface(const struct usb_ctrlrequest *ctrl)
{
	if (USB_CHECK_REQTYPE(ctrl, USB_RECIP_INTERFACE, USB_DIR_IN))
		return -1;

	if (usb_configured() == false)
		return -1;

	switch (fw.usb.config) {
	case 1:
		break;

	default:
		return -1;
	}

	return usb_ep0tx_data(&fw.usb.alternate_interface_setting, 1);
}

static int usb_manipulate_feature(const struct usb_ctrlrequest *ctrl, bool __unused clear)
{
	unsigned int feature;
	if (USB_CHECK_REQTYPE(ctrl, USB_RECIP_DEVICE, USB_DIR_OUT))
		return -1;

	if (usb_configured() == false)
		return -1;

	feature = le16_to_cpu(ctrl->wValue);

#ifdef CONFIG_CARL9170FW_WOL
	if (feature & USB_DEVICE_REMOTE_WAKEUP) {
		if (clear)
			usb_disable_remote_wakeup();
		else
			usb_enable_remote_wakeup();
	}
#endif /* CONFIG_CARL9170FW_WOL */

	if (clear)
		fw.usb.device_feature &= ~feature;
	else
		fw.usb.device_feature |= feature;

	return 1;
}

#ifdef CONFIG_CARL9170FW_USB_MODESWITCH
static int usb_set_interface(const struct usb_ctrlrequest *ctrl)
{
	unsigned int intf, alt_intf;
	if (USB_CHECK_REQTYPE(ctrl, USB_RECIP_INTERFACE, USB_DIR_OUT))
		return -1;

	if (usb_configured() == false)
		return -1;

	intf = le16_to_cpu(ctrl->wIndex);
	alt_intf = le16_to_cpu(ctrl->wValue);

	switch (intf) {
	case 0:
		if (alt_intf != fw.usb.cfg_desc->intf.bAlternateSetting)
			return -1;

		fw.usb.interface_setting = (uint8_t) intf;
		fw.usb.alternate_interface_setting = (uint8_t) alt_intf;
		if (usb_detect_highspeed())
			usb_init_highspeed_fifo_cfg();
		else
			usb_init_fullspeed_fifo_cfg();

		usb_reset_eps();
		usb_enable_global_int();
		usb_trigger_out();
		return 1;

	default:
		return -1;
	}
}
#endif /* CONFIG_CARL9170FW_USB_MODESWITCH */
#endif /* CONFIG_CARL9170FW_USB_STANDARD_CMDS */

static int usb_standard_command(const struct usb_ctrlrequest *ctrl __unused)
{
	int status = -1;

#ifdef CONFIG_CARL9170FW_USB_STANDARD_CMDS
	switch (ctrl->bRequest) {
	case USB_REQ_GET_STATUS:
		status = usb_get_status(ctrl);
		break;

	case USB_REQ_CLEAR_FEATURE:
	case USB_REQ_SET_FEATURE:
		usb_manipulate_feature(ctrl, ctrl->bRequest == USB_REQ_CLEAR_FEATURE);
		break;

	case USB_REQ_SET_ADDRESS:
		status = usb_set_address(ctrl);
		break;

	case USB_REQ_GET_DESCRIPTOR:
		status = usb_get_descriptor(ctrl);
		break;

	case USB_REQ_SET_DESCRIPTOR:
		break;

	case USB_REQ_GET_CONFIGURATION:
		status = usb_get_configuration(ctrl);
		break;

	case USB_REQ_SET_CONFIGURATION:
		status = usb_set_configuration(ctrl);
		break;

	case USB_REQ_GET_INTERFACE:
		status = usb_get_interface(ctrl);
		break;

	case USB_REQ_SET_INTERFACE:
#ifdef CONFIG_CARL9170FW_USB_MODESWITCH
		status = usb_set_interface(ctrl);
#endif /* CONFIG_CARL9170FW_USB_MODESWITCH */
		break;

	case USB_REQ_SYNCH_FRAME:
		break;

	default:
		break;

	}
#endif /* CONFIG_CARL9170FW_USB_STANDARD_CMDS */

	return status;
}

static int usb_class_command(const struct usb_ctrlrequest *ctrl __unused)
{
	return -1;
}

static int usb_vendor_command(const struct usb_ctrlrequest *ctrl __unused)
{
	/*
	 * Note: Firmware upload/boot is not implemented.
	 * It's impossible to replace the current image
	 * in place.
	 */

	return -1;
}

#undef USB_CHECK_TYPE

void usb_ep0setup(void)
{
	struct usb_ctrlrequest ctrl;
	int status = -1;
	usb_ep0rx_data(&ctrl, sizeof(ctrl));

	switch (ctrl.bRequestType & USB_TYPE_MASK) {
	case USB_TYPE_STANDARD:
		status = usb_standard_command(&ctrl);
		break;

	case USB_TYPE_CLASS:
		status = usb_class_command(&ctrl);
		break;

	case USB_TYPE_VENDOR:
		status = usb_vendor_command(&ctrl);
		break;

	default:
		break;

	}

	if (status < 0)
		fw.usb.ep0_action |= CARL9170_EP0_STALL;
#ifdef CONFIG_CARL9170FW_USB_STANDARD_CMDS
	if (status > 0)
		fw.usb.ep0_action |= CARL9170_EP0_TRIGGER;
#endif /* CONFIG_CARL9170FW_USB_STANDARD_CMDS */
}

void usb_ep0rx(void)
{
	if (BUG_ON(!fw.usb.ep0_txrx_buffer || !fw.usb.ep0_txrx_len))
		return ;

	usb_ep0rx_data(fw.usb.ep0_txrx_buffer, fw.usb.ep0_txrx_len);
	fw.usb.ep0_txrx_pos = fw.usb.ep0_txrx_len;
}

void usb_ep0tx(void)
{
	if (BUG_ON(!fw.usb.ep0_txrx_buffer || !fw.usb.ep0_txrx_len))
		return ;

	usb_ep0tx_data(fw.usb.ep0_txrx_buffer, fw.usb.ep0_txrx_len);
	fw.usb.ep0_txrx_pos = fw.usb.ep0_txrx_len;
}
