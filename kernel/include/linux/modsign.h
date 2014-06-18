/* Module signing definitions
 *
 * Copyright (C) 2009 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#ifndef _LINUX_MODSIGN_H
#define _LINUX_MODSIGN_H

#ifdef CONFIG_MODULE_SIG

#include <linux/elfnote.h>

/*
 * The parameters of the ELF note used to carry the signature
 */
#define MODSIGN_NOTE_NAME	module.sig
#define MODSIGN_NOTE_TYPE	100

#endif

#endif /* _LINUX_MODSIGN_H */
