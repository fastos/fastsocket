/*
 * list.h List Utilities
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2003-2006 Thomas Graf <tgraf@suug.ch>
 */

#ifndef __LIST_H
#define __LIST_H

struct list_head {
	struct list_head *next;
	struct list_head *prev;
};

static inline void list_add(struct list_head *obj,
			    struct list_head *prev,
			    struct list_head *next)
{
	prev->next = obj;
	obj->prev = prev;
	next->prev = obj;
	obj->next = next;
}

static inline void list_add_tail(struct list_head *obj,
				 struct list_head *head)
{
	list_add(obj, head->prev, head);
}

static inline void list_add_head(struct list_head *obj,
				 struct list_head *head)
{
	list_add(obj, head, head->next);
}

static inline void list_del(struct list_head *obj)
{
	obj->prev->next = obj->next;
	obj->next->prev = obj->prev;
	obj->next = obj->prev = obj;
}

static inline void list_replace(struct list_head *old,
				struct list_head *obj)
{
	obj->next = old->next;
	obj->next->prev = obj;
	obj->prev = old->prev;
	obj->prev->next = obj;
}

static inline int list_empty(struct list_head *head)
{
	return head->next == head;
}

#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)

#define list_first_entry(ptr, type, member) \
	container_of((ptr)->next, type, member)

#define list_at_tail(pos, head, member) \
	((pos)->member.next == (head))

#define list_at_head(pos, head, member) \
	((pos)->member.prev == (head))

#define LIST_HEAD(name) \
	struct list_head name = { &(name), &(name) }

#define list_for_each_entry(pos, head, member)				\
	for (pos = list_entry((head)->next, typeof(*pos), member);	\
	     &(pos)->member != (head);					\
	     (pos) = list_entry((pos)->member.next, typeof(*(pos)), member))

#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_entry((head)->next, typeof(*pos), member),	\
	     n = list_entry(pos->member.next, typeof(*pos), member);	\
	     &(pos)->member != (head);					\
	     pos = n, n = list_entry(n->member.next, typeof(*n), member))

#define init_list_head(head) \
	do { (head)->next = (head); (head)->prev = (head); } while (0)

#endif /* __LIST_H */
