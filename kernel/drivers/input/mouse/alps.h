/*
 * ALPS touchpad PS/2 mouse driver
 *
 * Copyright (c) 2003 Peter Osterlund <petero2@telia.com>
 * Copyright (c) 2005 Vojtech Pavlik <vojtech@suse.cz>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 */

#ifndef _ALPS_H
#define _ALPS_H

#define ALPS_PROTO_V1	1
#define ALPS_PROTO_V2	2
#define ALPS_PROTO_V3	3
#define ALPS_PROTO_V4	4
#define ALPS_PROTO_V5	5

struct alps_model_info {
        unsigned char signature[3];
	unsigned char command_mode_resp; /* v3/v4 only */
	unsigned char proto_version;
        unsigned char byte0, mask0;
        unsigned char flags;
};

struct alps_nibble_commands {
	int command;
	unsigned char data;
};

/**
 * struct alps_fields - decoded version of the report packet
 * @x: X position for ST.
 * @y: Y position for ST.
 * @z: Z position for ST.
 * @first_mp: Packet is the first of a multi-packet report.
 * @is_mp: Packet is part of a multi-packet report.
 * @left: Left touchpad button is active.
 * @right: Right touchpad button is active.
 * @middle: Middle touchpad button is active.
 * @ts_left: Left trackstick button is active.
 * @ts_right: Right trackstick button is active.
 * @ts_middle: Middle trackstick button is active.
 */
struct alps_fields {
	unsigned int x;
	unsigned int y;
	unsigned int z;
	unsigned int first_mp:1;
	unsigned int is_mp:1;

	unsigned int left:1;
	unsigned int right:1;
	unsigned int middle:1;

	unsigned int ts_left:1;
	unsigned int ts_right:1;
	unsigned int ts_middle:1;
};

struct alps_data {
	struct input_dev *dev2;		/* Relative device */
	char phys[32];			/* Phys */
	const struct alps_nibble_commands *nibble_commands;
	int addr_command;		/* Command to set register address */
	unsigned char proto_version;
	unsigned char byte0, mask0;
	unsigned char flags;
	int x_max;
	int y_max;

	int (*hw_init)(struct psmouse *psmouse);
	void (*process_packet)(struct psmouse *psmouse);
	void (*decode_fields)(struct alps_fields *f, unsigned char *p);
	void (*set_abs_params)(struct alps_data *priv, struct input_dev *dev1);

	int prev_fin;			/* Finger bit from previous packet */
	int multi_packet;		/* Multi-packet data in progress */
	u8 quirks;
	struct timer_list timer;
};

#define ALPS_QUIRK_TRACKSTICK_BUTTONS	1 /* trakcstick buttons in trackstick packet */

#ifdef CONFIG_MOUSE_PS2_ALPS
int alps_detect(struct psmouse *psmouse, bool set_properties);
int alps_init(struct psmouse *psmouse);
#else
inline int alps_detect(struct psmouse *psmouse, bool set_properties)
{
	return -ENOSYS;
}
inline int alps_init(struct psmouse *psmouse)
{
	return -ENOSYS;
}
#endif /* CONFIG_MOUSE_PS2_ALPS */

#endif
