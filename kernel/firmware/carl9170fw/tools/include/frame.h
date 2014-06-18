/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Most ideas and some code are copied from the linux' kernels
 *	include/linux/skbuff.h
 */

#ifndef __TOOLS_FRAME_H
#define __TOOLS_FRAME_H

#include "SDL.h"
#include "list.h"

/**
 * struct frame_queue - sk_buff_head like frame queue
 *
 * @list: pointer to head and tail
 * @lock: mutex lock for serialize access
 * @len: exact number of queued frames
 */

struct frame_queue {
	struct list_head list;
	SDL_mutex *lock;
	size_t len;
};

/**
 * struct frame - frame data structure (like sk_buff)
 *
 * @list: storage for double-linked &struct frame_queue list
 * @dev: pointer to private device/driver structure
 * @timestamp: space for the current timestamp
 * @cb: private driver data
 * @dcb: more reserved space for low-level / backend driver
 * @queue: selected frame queue / priority
 * @ref: reference counter
 * @alloced: maximum available space
 * @total_len: currently consumed and reserved memory
 * @len: current frame length
 * @head: points to the buffer head
 * @data: current frame data pointer
 * @tail: frame data tail pointer
 * @payload: frame data storage container
 */

struct frame {
	struct list_head list;
	void *dev;
	unsigned long timestamp;
	uint8_t cb[64];
	union {
		struct list_head list;
		uint8_t raw_data[32];
	} dcb;

	unsigned int queue;
	unsigned int ref;
	unsigned int alloced;
	unsigned int total_len;
	unsigned int len;
	uint8_t *head;
	uint8_t *data;
	uint8_t *tail;

	/* payload must be the last entry */
	uint8_t payload[0];
};

/**
 * frame_put - append more data to &struct frame
 *
 * Allocate @size bytes from &struct frame tail and
 * returns a pointer to the requested location.
 *
 * @frame: frame to alter
 * @size: extra size
 */
static inline void *frame_put(struct frame *frame, unsigned int size)
{
	void *tmp;

	BUG_ON(frame->total_len + size > frame->alloced);

	frame->len += size;
	frame->total_len += size;

	tmp = (void *) frame->tail;
	frame->tail += size;

	BUG_ON(frame->tail > (frame->payload + frame->alloced));

	return tmp;
}

/**
 * frame_push - allocate head
 *
 * returns a pointer to a newly allocate area at &struct frame head.
 *
 * @frame: frame to modify
 * @size: requested extra size
 */
static inline void *frame_push(struct frame *frame, unsigned int size)
{
	frame->len += size;
	frame->data -= size;

	BUG_ON(frame->data < frame->payload);
	return frame->data;
}

/**
 * frame_get - reference frame buffer
 *
 * grab a reference from the frame buffer, in order to
 * prevent it from being freed prematurely by a different user.
 *
 * @frame: frame pointer
 */
static inline struct frame *frame_get(struct frame *frame)
{
	frame->ref++;
	return frame;
}

/**
 * frame_pull - remove space from &struct frame head
 *
 * Does the opposite of frame_push() and removes freed-up
 * space at the frames's head.
 *
 * @frame: pointer to frame structure
 * @size: bytes to remove from head
 */
static inline void *frame_pull(struct frame *frame, unsigned int size)
{
	BUG_ON(frame->len < size);

	frame->len -= size;
	frame->total_len -= size;
	frame->data += size;

	return frame->data;
}

/**
 * frame_reserve - reserve frame headroom
 *
 * Reserve a certain amount of space to allow headroom manipulations
 * in the future.
 *
 * @frame: frame to adjust
 * @size: bytes to reserve
 */
static inline void frame_reserve(struct frame *frame, unsigned int size)
{
	BUG_ON(frame->total_len + size > frame->alloced);
	BUG_ON(frame->len != 0);

	frame->total_len += size;
	frame->data += size;
	frame->tail += size;
}

/**
 * frame_trim - set frame length
 *
 * cut the frame to @size length.
 *
 * @frame: frame to be trimmed
 * @size: new length
 */
static inline void frame_trim(struct frame *frame, unsigned int size)
{
	BUG_ON(size > frame->total_len);

	frame->len = size;
	frame->total_len = size;
	frame->data = frame->head;
	frame->tail = frame->head + size;
}

/**
 * frame_alloc - alloc and initialize new frame
 *
 * returns a newly created &struct frame object.
 *
 * @size: maximum frame size of the new frame
 */
static inline struct frame *frame_alloc(unsigned int size)
{
	struct frame *tmp;

	tmp = malloc(size + sizeof(*tmp));
	if (tmp != NULL) {
		memset(tmp, 0, sizeof(*tmp));
		init_list_head(&tmp->list);
		init_list_head(&tmp->dcb.list);
		tmp->len = 0;
		tmp->total_len = 0;
		tmp->alloced = size;

		tmp->head = tmp->payload;
		tmp->data = tmp->payload;
		tmp->tail = tmp->payload;
		tmp->ref = 1;
	}
	return tmp;
}

/**
 * frame_free - unref and free frame
 *
 * Unreference frame and free it up, if all users are gone.
 *
 * @frame: frame to be freed
 */
static inline void frame_free(struct frame *frame)
{
	if (!--frame->ref)
		free(frame);
}

/**
 * FRAME_WALK - MACRO walker
 *
 * Walks over all queued elements in &struct frame_queue
 *
 * NOTE: This function is vulnerable in concurrent access
 *	 scenarios without proper locking.
 *
 * @pos: current position inside the queue
 * @head: &struct frame_queue head
 */
#define FRAME_WALK(pos, head)					\
	list_for_each_entry((pos), &(head)->list, list)

static inline void __frame_queue_init(struct frame_queue *queue)
{
	queue->len = 0;
	init_list_head(&queue->list);
}

/**
 * frame_queue_init - initialize frame_queue
 *
 * Initialize the given &struct frame_queue object.
 *
 * @queue: frame_queue to be initialized
 */
static inline void frame_queue_init(struct frame_queue *queue)
{
	queue->lock = SDL_CreateMutex();
	__frame_queue_init(queue);
}

/**
 * frame_queue_len - returns number of queue elements
 *
 * @queue: frame_queue object
 */
static inline unsigned int frame_queue_len(struct frame_queue *queue)
{
	return queue->len;
}

/**
 * frame_queue_empty - returns %TRUE whenever queue is empty
 *
 * @queue: frame_queue object
 */
static inline bool frame_queue_empty(struct frame_queue *queue)
{
	return list_empty(&queue->list);
}

static inline void __frame_queue_head(struct frame_queue *queue, struct frame *frame)
{
	list_add_head(&frame->list, &queue->list);
	queue->len++;
}

/**
 * frame_queue_head - queue a frame at the queues head
 * @queue: queue to use
 */
static inline void frame_queue_head(struct frame_queue *queue, struct frame *frame)
{
	BUG_ON((SDL_mutexP(queue->lock) != 0));
	__frame_queue_head(queue, frame);
	SDL_mutexV(queue->lock);
}

static inline void __frame_queue_tail(struct frame_queue *queue, struct frame *frame)
{
	list_add_tail(&frame->list, &queue->list);
	queue->len++;
}

/**
 * frame_queue_head - queue a frame at the queues tail
 * @queue: queue to use
 */
static inline void frame_queue_tail(struct frame_queue *queue, struct frame *frame)
{
	BUG_ON((SDL_mutexP(queue->lock) != 0));
	__frame_queue_tail(queue, frame);
	SDL_mutexV(queue->lock);
}

static inline void __frame_unlink(struct frame_queue *queue, struct frame *frame)
{
	list_del(&frame->list);
	queue->len--;
}

/**
 * frame_queue_unlink - remove a frame from the queue
 * @queue: queue to use
 * @frame: frame to remove
 */
static inline void frame_unlink(struct frame_queue *queue, struct frame *frame)
{
	BUG_ON((SDL_mutexP(queue->lock) != 0));
	__frame_unlink(queue, frame);
	SDL_mutexV(queue->lock);
}


static inline struct frame *__frame_dequeue(struct frame_queue *queue)
{
	struct frame *tmp = NULL;

	if (!frame_queue_empty(queue)) {
		tmp = list_entry(queue->list.next, struct frame, list);
		__frame_unlink(queue, tmp);
	}

	return tmp;
}

/**
 * frame_dequeue - remove frame from the head of the queue
 *
 * @queue: queue to dequeue from
 */
static inline struct frame *frame_dequeue(struct frame_queue *queue)
{
	struct frame *tmp;

	BUG_ON((SDL_mutexP(queue->lock) != 0));

	tmp = __frame_dequeue(queue);
	SDL_mutexV(queue->lock);
	return tmp;
}

static inline void __frame_queue_purge(struct frame_queue *queue)
{
	while (list_empty(&queue->list) == false)
		frame_free(__frame_dequeue(queue));
}

/**
 * frame_queue_purge - frees all queued &struct frame objects
 *
 * @queue: queue to be freed
 */
static inline void frame_queue_purge(struct frame_queue *queue)
{
	BUG_ON((SDL_mutexP(queue->lock) != 0));
	__frame_queue_purge(queue);
	SDL_mutexV(queue->lock);
}

/**
 * frame_queue_kill - destroys frame_queue object
 *
 * Destroy object and frees up all remaining elements
 *
 * @queue: frame_queue victim
 */
static inline void frame_queue_kill(struct frame_queue *queue)
{
	SDL_DestroyMutex(queue->lock);
	__frame_queue_purge(queue);
}

#endif /* __TOOLS_FRAME_H */
