/*
 * carlu - userspace testing utility for ar9170 devices
 *
 * main program routine
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
#include <string.h>
#include <stdlib.h>
#include "SDL.h"
#include <SDL_version.h>

#include "debug.h"
#include "carlu.h"
#include "usb.h"
#include "frame.h"
#include "test.h"
#include "cmd.h"

void *carlu_alloc_driver(size_t size)
{
	unsigned int i;
	struct carlu *ar;

	if (size < sizeof(*ar)) {
		err("bogus driver context request.");
		return NULL;
	}

	ar = malloc(size);
	if (ar == NULL) {
		err("failed to alloc driver context.");
		return NULL;
	}
	memset(ar, 0, size);

	for (i = 0; i < __AR9170_NUM_TXQ; i++)
		frame_queue_init(&ar->tx_sent_queue[i]);
	ar->resp_lock = SDL_CreateMutex();
	ar->mem_lock = SDL_CreateMutex();
	ar->resp_pend = SDL_CreateCond();
	ar->tx_pending = 0;
	return ar;
}

void carlu_free_driver(struct carlu *ar)
{
	unsigned int i;

	dbg("destroy driver struct.\n");
	SDL_DestroyMutex(ar->resp_lock);
	SDL_DestroyMutex(ar->mem_lock);
	SDL_DestroyCond(ar->resp_pend);

	for (i = 0; i < __AR9170_NUM_TXQ; i++)
		frame_queue_kill(&ar->tx_sent_queue[i]);

	free(ar);
}

static int carlu_init()
{
	struct SDL_version compiled;
	int ret;

	SDL_VERSION(&compiled);
	dbg("=== SDL %d.%d.%d ===\n", compiled.major, compiled.minor, compiled.patch);

	ret = SDL_Init(SDL_INIT_TIMER);
	if (ret != 0) {
		err("Unable to initialize SDL: (%s)\n", SDL_GetError());
		return EXIT_FAILURE;
	}

	return usb_init();
}

static void carlu_exit()
{
	SDL_Quit();
	usb_exit();
}

static int carlu_dump_eeprom(void)
{
	struct carlu *carl = NULL;
	uint8_t data[8192] = { 0 };
	int err;

	err = carlu_init();
	if (err)
		goto out;

	carl = carlusb_probe();
	if (IS_ERR_OR_NULL(carl)) {
		err = PTR_ERR(carl);
		goto out;
	}

	err = carlu_cmd_mem_dump(carl, 0, sizeof(data), &data);
	if (err)
		goto out_close;

	print_hex_dump_bytes(INFO, "EEPROM:", data, sizeof(data));

out_close:
	carlusb_close(carl);

out:
	carlu_exit();
	return err ? EXIT_FAILURE : EXIT_SUCCESS;
}

static int carlu_run_gpio_test(void)
{
	struct carlu *carl = NULL;
	int err;

	err = carlu_init();
	if (err)
		goto out;

	carl = carlusb_probe();
	if (IS_ERR_OR_NULL(carl)) {
		err = PTR_ERR(carl);
		goto out;
	}

	err = carlu_gpio_test(carl);
	if (err)
		goto out_close;

out_close:
	carlusb_close(carl);

out:
	carlu_exit();
	return err ? EXIT_FAILURE : EXIT_SUCCESS;
}

static int carlu_run_random_test(void)
{
	struct carlu *carl = NULL;
	int err;

	err = carlu_init();
	if (err)
		goto out;

	carl = carlusb_probe();
	if (IS_ERR_OR_NULL(carl)) {
		err = PTR_ERR(carl);
		goto out;
	}

	err = carlu_random_test(carl);
	if (err)
		goto out_close;

out_close:
	carlusb_close(carl);

out:
	carlu_exit();
	return err ? EXIT_FAILURE : EXIT_SUCCESS;
}

static int carlu_run_loop_test(void)
{
	struct carlu *carl;
	int err;

	err = carlu_init();
	if (err)
		return EXIT_FAILURE;

	carl = carlusb_probe();
	if (IS_ERR_OR_NULL(carl)) {
		err = PTR_ERR(carl);
		goto out;
	}

	carlu_cmd_write_mem(carl, AR9170_MAC_REG_BCN_PERIOD, 0xFFFFFFFF);
	carlu_cmd_write_mem(carl, AR9170_MAC_REG_PRETBTT, 0xFFFFFFFF);

	/* different payload test */
	carlu_loopback_test(carl, 9000, 1000, 1566, 1566);
	carlusb_close(carl);

out:
	return err ? EXIT_FAILURE : EXIT_SUCCESS;
}

static int carlu_probe_all(void)
{
	struct carlu *carl[32] = { 0 };
	unsigned int devs;
	int ret;

	ret = carlu_init();
	if (ret)
		return EXIT_FAILURE;

	for (devs = 0; devs < ARRAY_SIZE(carl); devs++) {
		carl[devs] = carlusb_probe();
		if (IS_ERR_OR_NULL(carl[devs]))
			break;
	}

	info("Found %d devices\n", devs);

	for (; devs > 0; devs--)
		carlusb_close(carl[devs - 1]);

	carlu_exit();
	return EXIT_SUCCESS;
}

struct menu_struct {
	char option;
	unsigned int parameters;
	int (*function)(void);
	char help_text[80];
};

#define MENU_ITEM(op, func, helpme)	\
	{				\
		.option = op,		\
		.parameters = 0,	\
		.function = func,	\
		.help_text = helpme,	\
	}

static int show_help(void);

static const struct menu_struct menu[] = {
	[0] = MENU_ITEM('h', show_help, "shows this useless help message text."),	/* keep this entry at 0! */
	      MENU_ITEM('e', carlu_dump_eeprom, "hexdumps eeprom content to stdout."),
	      MENU_ITEM('l', carlusb_print_known_devices, "list of all known ar9170 usb devices."),
	      MENU_ITEM('p', carlu_probe_all, "probe all possible devices."),
	      MENU_ITEM('t', carlu_run_loop_test, "run tx/rx test."),
	      MENU_ITEM('g', carlu_run_gpio_test, "flash the leds."),
	      MENU_ITEM('r', carlu_run_random_test, "get random numbers."),
};

static int show_help(void)
{
	unsigned int i;
	char parameters[ARRAY_SIZE(menu) + 1];

	for (i = 0; i < ARRAY_SIZE(menu); i++)
		parameters[i] = menu[i].option;

	parameters[ARRAY_SIZE(menu)] = '\0';

	info("usage: ar9170user -[%s]\n", parameters);

	for (i = 0; i < ARRAY_SIZE(menu); i++)
		info("\t-%c\t%s\n", menu[i].option, menu[i].help_text);

	return EXIT_FAILURE;
}

static int select_menu_item(const char arg)
{
	unsigned int i;

	for (i = ARRAY_SIZE(menu) - 1; i != 0; i--) {
		if (arg == menu[i].option)
			break;
	}

	return menu[i].function();
}

int main(int argc, char *argv[])
{
	init_debug();

	if (argc != 2 || strlen(argv[1]) != 2 || argv[1][0] != '-')
		return show_help();

	return select_menu_item(argv[1][1]);
}
