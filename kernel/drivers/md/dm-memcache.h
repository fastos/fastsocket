/*
 * Copyright (C) 2006-2008 Red Hat, Inc. All rights reserved.
 *
 * Module Author: Heinz Mauelshagen <Mauelshagen@RedHat.com>
 *
 * Device-mapper memory object handling:
 *
 * o allocate/free total_pages in a per client page pool.
 *
 * o allocate/free memory objects with chunks (1..n) of
 *   pages_per_chunk pages hanging off.
 *
 * This file is released under the GPL.
 */

#ifndef _DM_MEM_CACHE_H
#define _DM_MEM_CACHE_H

#define	DM_MEM_CACHE_H_VERSION	"0.1"

#include "dm.h"
#include <linux/dm-io.h>

static inline struct page_list *pl_elem(struct page_list *pl, unsigned p)
{
	while (pl && p--)
		pl = pl->next;

	return pl;
}

struct dm_mem_cache_object {
	struct page_list *pl; /* Dynamically allocated array */
	void *private;	      /* Caller context reference */
};

struct dm_mem_cache_client;

/*
 * Create/destroy dm memory cache client resources.
 *
 * On creation, a number of @objects with @chunks of
 * @pages_per_chunk pages will be allocated.
 */
struct dm_mem_cache_client *
dm_mem_cache_client_create(unsigned objects, unsigned chunks,
			   unsigned pages_per_chunk);
void dm_mem_cache_client_destroy(struct dm_mem_cache_client *client);

/*
 * Grow/shrink a dm memory cache client resources
 * by @objetcs amount of objects.
 */
int dm_mem_cache_grow(struct dm_mem_cache_client *client, unsigned objects);
int dm_mem_cache_shrink(struct dm_mem_cache_client *client, unsigned objects);

/*
 * Allocate/free a memory object
 *
 * On allocation one object with an amount of chunks and
 * an amount of pages per chunk will be returned on success.
 */
struct dm_mem_cache_object *
dm_mem_cache_alloc(struct dm_mem_cache_client *client);
void dm_mem_cache_free(struct dm_mem_cache_client *client,
		       struct dm_mem_cache_object *object);

#endif
