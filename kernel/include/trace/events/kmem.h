#undef TRACE_SYSTEM
#define TRACE_SYSTEM kmem

#if !defined(_TRACE_KMEM_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_KMEM_H

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/tracepoint.h>
#include <linux/mmzone.h>

/*
 * The order of these masks is important. Matching masks will be seen
 * first and the left over flags will end up showing by themselves.
 *
 * For example, if we have GFP_KERNEL before GFP_USER we wil get:
 *
 *  GFP_KERNEL|GFP_HARDWALL
 *
 * Thus most bits set go first.
 */
#define show_gfp_flags(flags)						\
	(flags) ? __print_flags(flags, "|",				\
	{(unsigned long)GFP_HIGHUSER_MOVABLE,	"GFP_HIGHUSER_MOVABLE"}, \
	{(unsigned long)GFP_HIGHUSER,		"GFP_HIGHUSER"},	\
	{(unsigned long)GFP_USER,		"GFP_USER"},		\
	{(unsigned long)GFP_TEMPORARY,		"GFP_TEMPORARY"},	\
	{(unsigned long)GFP_KERNEL,		"GFP_KERNEL"},		\
	{(unsigned long)GFP_NOFS,		"GFP_NOFS"},		\
	{(unsigned long)GFP_ATOMIC,		"GFP_ATOMIC"},		\
	{(unsigned long)GFP_NOIO,		"GFP_NOIO"},		\
	{(unsigned long)__GFP_HIGH,		"GFP_HIGH"},		\
	{(unsigned long)__GFP_WAIT,		"GFP_WAIT"},		\
	{(unsigned long)__GFP_IO,		"GFP_IO"},		\
	{(unsigned long)__GFP_COLD,		"GFP_COLD"},		\
	{(unsigned long)__GFP_NOWARN,		"GFP_NOWARN"},		\
	{(unsigned long)__GFP_REPEAT,		"GFP_REPEAT"},		\
	{(unsigned long)__GFP_NOFAIL,		"GFP_NOFAIL"},		\
	{(unsigned long)__GFP_NORETRY,		"GFP_NORETRY"},		\
	{(unsigned long)__GFP_COMP,		"GFP_COMP"},		\
	{(unsigned long)__GFP_ZERO,		"GFP_ZERO"},		\
	{(unsigned long)__GFP_NOMEMALLOC,	"GFP_NOMEMALLOC"},	\
	{(unsigned long)__GFP_HARDWALL,		"GFP_HARDWALL"},	\
	{(unsigned long)__GFP_THISNODE,		"GFP_THISNODE"},	\
	{(unsigned long)__GFP_RECLAIMABLE,	"GFP_RECLAIMABLE"},	\
	{(unsigned long)__GFP_MOVABLE,		"GFP_MOVABLE"}		\
	) : "GFP_NOWAIT"

DECLARE_EVENT_CLASS(kmem_alloc,

	TP_PROTO(unsigned long call_site,
		 const void *ptr,
		 size_t bytes_req,
		 size_t bytes_alloc,
		 gfp_t gfp_flags),

	TP_ARGS(call_site, ptr, bytes_req, bytes_alloc, gfp_flags),

	TP_STRUCT__entry(
		__field(	unsigned long,	call_site	)
		__field(	const void *,	ptr		)
		__field(	size_t,		bytes_req	)
		__field(	size_t,		bytes_alloc	)
		__field(	gfp_t,		gfp_flags	)
	),

	TP_fast_assign(
		__entry->call_site	= call_site;
		__entry->ptr		= ptr;
		__entry->bytes_req	= bytes_req;
		__entry->bytes_alloc	= bytes_alloc;
		__entry->gfp_flags	= gfp_flags;
	),

	TP_printk("call_site=%lx ptr=%p bytes_req=%zu bytes_alloc=%zu gfp_flags=%s",
		__entry->call_site,
		__entry->ptr,
		__entry->bytes_req,
		__entry->bytes_alloc,
		show_gfp_flags(__entry->gfp_flags))
);

DEFINE_EVENT(kmem_alloc, kmalloc,

	TP_PROTO(unsigned long call_site, const void *ptr,
		 size_t bytes_req, size_t bytes_alloc, gfp_t gfp_flags),

	TP_ARGS(call_site, ptr, bytes_req, bytes_alloc, gfp_flags)
);

DEFINE_EVENT(kmem_alloc, kmem_cache_alloc,

	TP_PROTO(unsigned long call_site, const void *ptr,
		 size_t bytes_req, size_t bytes_alloc, gfp_t gfp_flags),

	TP_ARGS(call_site, ptr, bytes_req, bytes_alloc, gfp_flags)
);

DECLARE_EVENT_CLASS(kmem_alloc_node,

	TP_PROTO(unsigned long call_site,
		 const void *ptr,
		 size_t bytes_req,
		 size_t bytes_alloc,
		 gfp_t gfp_flags,
		 int node),

	TP_ARGS(call_site, ptr, bytes_req, bytes_alloc, gfp_flags, node),

	TP_STRUCT__entry(
		__field(	unsigned long,	call_site	)
		__field(	const void *,	ptr		)
		__field(	size_t,		bytes_req	)
		__field(	size_t,		bytes_alloc	)
		__field(	gfp_t,		gfp_flags	)
		__field(	int,		node		)
	),

	TP_fast_assign(
		__entry->call_site	= call_site;
		__entry->ptr		= ptr;
		__entry->bytes_req	= bytes_req;
		__entry->bytes_alloc	= bytes_alloc;
		__entry->gfp_flags	= gfp_flags;
		__entry->node		= node;
	),

	TP_printk("call_site=%lx ptr=%p bytes_req=%zu bytes_alloc=%zu gfp_flags=%s node=%d",
		__entry->call_site,
		__entry->ptr,
		__entry->bytes_req,
		__entry->bytes_alloc,
		show_gfp_flags(__entry->gfp_flags),
		__entry->node)
);

DEFINE_EVENT(kmem_alloc_node, kmalloc_node,

	TP_PROTO(unsigned long call_site, const void *ptr,
		 size_t bytes_req, size_t bytes_alloc,
		 gfp_t gfp_flags, int node),

	TP_ARGS(call_site, ptr, bytes_req, bytes_alloc, gfp_flags, node)
);

DEFINE_EVENT(kmem_alloc_node, kmem_cache_alloc_node,

	TP_PROTO(unsigned long call_site, const void *ptr,
		 size_t bytes_req, size_t bytes_alloc,
		 gfp_t gfp_flags, int node),

	TP_ARGS(call_site, ptr, bytes_req, bytes_alloc, gfp_flags, node)
);

DECLARE_EVENT_CLASS(kmem_free,

	TP_PROTO(unsigned long call_site, const void *ptr),

	TP_ARGS(call_site, ptr),

	TP_STRUCT__entry(
		__field(	unsigned long,	call_site	)
		__field(	const void *,	ptr		)
	),

	TP_fast_assign(
		__entry->call_site	= call_site;
		__entry->ptr		= ptr;
	),

	TP_printk("call_site=%lx ptr=%p", __entry->call_site, __entry->ptr)
);

DEFINE_EVENT(kmem_free, kfree,

	TP_PROTO(unsigned long call_site, const void *ptr),

	TP_ARGS(call_site, ptr)
);

DEFINE_EVENT(kmem_free, kmem_cache_free,

	TP_PROTO(unsigned long call_site, const void *ptr),

	TP_ARGS(call_site, ptr)
);

TRACE_EVENT(mm_page_free_direct,

	TP_PROTO(struct page *page, unsigned int order),

	TP_ARGS(page, order),

	TP_STRUCT__entry(
		__field(	struct page *,	page		)
		__field(	unsigned int,	order		)
	),

	TP_fast_assign(
		__entry->page		= page;
		__entry->order		= order;
	),

	TP_printk("page=%p pfn=%lu order=%d",
			__entry->page,
			page_to_pfn(__entry->page),
			__entry->order)
);

TRACE_EVENT(mm_pagevec_free,

	TP_PROTO(struct page *page, int cold),

	TP_ARGS(page, cold),

	TP_STRUCT__entry(
		__field(	struct page *,	page		)
		__field(	int,		cold		)
	),

	TP_fast_assign(
		__entry->page		= page;
		__entry->cold		= cold;
	),

	TP_printk("page=%p pfn=%lu order=0 cold=%d",
			__entry->page,
			page_to_pfn(__entry->page),
			__entry->cold)
);

TRACE_EVENT(mm_page_alloc,

	TP_PROTO(struct page *page, unsigned int order,
			gfp_t gfp_flags, int migratetype),

	TP_ARGS(page, order, gfp_flags, migratetype),

	TP_STRUCT__entry(
		__field(	struct page *,	page		)
		__field(	unsigned int,	order		)
		__field(	gfp_t,		gfp_flags	)
		__field(	int,		migratetype	)
	),

	TP_fast_assign(
		__entry->page		= page;
		__entry->order		= order;
		__entry->gfp_flags	= gfp_flags;
		__entry->migratetype	= migratetype;
	),

	TP_printk("page=%p pfn=%lu order=%d migratetype=%d gfp_flags=%s",
		__entry->page,
		page_to_pfn(__entry->page),
		__entry->order,
		__entry->migratetype,
		show_gfp_flags(__entry->gfp_flags))
);

DECLARE_EVENT_CLASS(mm_page,

	TP_PROTO(struct page *page, unsigned int order, int migratetype),

	TP_ARGS(page, order, migratetype),

	TP_STRUCT__entry(
		__field(	struct page *,	page		)
		__field(	unsigned int,	order		)
		__field(	int,		migratetype	)
	),

	TP_fast_assign(
		__entry->page		= page;
		__entry->order		= order;
		__entry->migratetype	= migratetype;
	),

	TP_printk("page=%p pfn=%lu order=%u migratetype=%d percpu_refill=%d",
		__entry->page,
		page_to_pfn(__entry->page),
		__entry->order,
		__entry->migratetype,
		__entry->order == 0)
);

DEFINE_EVENT(mm_page, mm_page_alloc_zone_locked,

	TP_PROTO(struct page *page, unsigned int order, int migratetype),

	TP_ARGS(page, order, migratetype)
);

DEFINE_EVENT_PRINT(mm_page, mm_page_pcpu_drain,

	TP_PROTO(struct page *page, unsigned int order, int migratetype),

	TP_ARGS(page, order, migratetype),

	TP_printk("page=%p pfn=%lu order=%d migratetype=%d",
		__entry->page, page_to_pfn(__entry->page),
		__entry->order, __entry->migratetype)
);

TRACE_EVENT(mm_page_alloc_extfrag,

	TP_PROTO(struct page *page,
			int alloc_order, int fallback_order,
			int alloc_migratetype, int fallback_migratetype),

	TP_ARGS(page,
		alloc_order, fallback_order,
		alloc_migratetype, fallback_migratetype),

	TP_STRUCT__entry(
		__field(	struct page *,	page			)
		__field(	int,		alloc_order		)
		__field(	int,		fallback_order		)
		__field(	int,		alloc_migratetype	)
		__field(	int,		fallback_migratetype	)
	),

	TP_fast_assign(
		__entry->page			= page;
		__entry->alloc_order		= alloc_order;
		__entry->fallback_order		= fallback_order;
		__entry->alloc_migratetype	= alloc_migratetype;
		__entry->fallback_migratetype	= fallback_migratetype;
	),

	TP_printk("page=%p pfn=%lu alloc_order=%d fallback_order=%d pageblock_order=%d alloc_migratetype=%d fallback_migratetype=%d fragmenting=%d change_ownership=%d",
		__entry->page,
		page_to_pfn(__entry->page),
		__entry->alloc_order,
		__entry->fallback_order,
		pageblock_order,
		__entry->alloc_migratetype,
		__entry->fallback_migratetype,
		__entry->fallback_order < pageblock_order,
		__entry->alloc_migratetype == __entry->fallback_migratetype)
);

TRACE_EVENT(mm_anon_fault,

	TP_PROTO(struct mm_struct *mm, unsigned long address),

	TP_ARGS(mm, address),

	TP_STRUCT__entry(
		__field(struct mm_struct *, mm)
		__field(unsigned long, address)
	),

	TP_fast_assign(
		__entry->mm = mm;
		__entry->address = address;
	),

	TP_printk("mm=%lx address=%lx",
		(unsigned long)__entry->mm, __entry->address)
);

TRACE_EVENT(mm_anon_pgin,

	TP_PROTO(struct mm_struct *mm, unsigned long address),

	TP_ARGS(mm, address),

	TP_STRUCT__entry(
		__field(struct mm_struct *, mm)
		__field(unsigned long, address)
	),

	TP_fast_assign(
		__entry->mm = mm;
		__entry->address = address;
	),

	TP_printk("mm=%lx address=%lx",
		(unsigned long)__entry->mm, __entry->address)
	);

TRACE_EVENT(mm_anon_cow,

	TP_PROTO(struct mm_struct *mm,
			unsigned long address),

	TP_ARGS(mm, address),

	TP_STRUCT__entry(
		__field(struct mm_struct *, mm)
		__field(unsigned long, address)
	),

	TP_fast_assign(
		__entry->mm = mm;
		__entry->address = address;
	),

	TP_printk("mm=%lx address=%lx",
		(unsigned long)__entry->mm, __entry->address)
	);

TRACE_EVENT(mm_anon_userfree,

	TP_PROTO(struct mm_struct *mm,
			unsigned long address),

	TP_ARGS(mm, address),

	TP_STRUCT__entry(
		__field(struct mm_struct *, mm)
		__field(unsigned long, address)
	),

	TP_fast_assign(
		__entry->mm = mm;
		__entry->address = address;
	),

	TP_printk("mm=%lx address=%lx",
		(unsigned long)__entry->mm, __entry->address)
	);

TRACE_EVENT(mm_anon_unmap,

	TP_PROTO(struct mm_struct *mm, unsigned long address),

	TP_ARGS(mm, address),

	TP_STRUCT__entry(
		__field(struct mm_struct *, mm)
		__field(unsigned long, address)
	),

	TP_fast_assign(
		__entry->mm = mm;
		__entry->address = address;
	),

	TP_printk("mm=%lx address=%lx",
		(unsigned long)__entry->mm, __entry->address)
	);

TRACE_EVENT(mm_filemap_fault,

	TP_PROTO(struct mm_struct *mm, unsigned long address, int flag),

	TP_ARGS(mm, address, flag),

	TP_STRUCT__entry(
		__field(struct mm_struct *, mm)
		__field(unsigned long, address)
		__field(int, flag)
	),

	TP_fast_assign(
		__entry->mm = mm;
		__entry->address = address;
		__entry->flag = flag;
	),

	TP_printk("%s: mm=%lx address=%lx",
		__entry->flag ? "pagein" : "primary fault",
		(unsigned long)__entry->mm, __entry->address)
	);

TRACE_EVENT(mm_filemap_cow,

	TP_PROTO(struct mm_struct *mm, unsigned long address),

	TP_ARGS(mm, address),

	TP_STRUCT__entry(
		__field(struct mm_struct *, mm)
		__field(unsigned long, address)
	),

	TP_fast_assign(
		__entry->mm = mm;
		__entry->address = address;
	),

	TP_printk("mm=%lx address=%lx",
		(unsigned long)__entry->mm, __entry->address)
	);

TRACE_EVENT(mm_filemap_unmap,

	TP_PROTO(struct mm_struct *mm, unsigned long address),

	TP_ARGS(mm, address),

	TP_STRUCT__entry(
		__field(struct mm_struct *, mm)
		__field(unsigned long, address)
	),

	TP_fast_assign(
		__entry->mm = mm;
		__entry->address = address;
	),

	TP_printk("mm=%lx address=%lx",
		(unsigned long)__entry->mm, __entry->address)
	);

TRACE_EVENT(mm_filemap_userunmap,

	TP_PROTO(struct mm_struct *mm, unsigned long address),

	TP_ARGS(mm, address),

	TP_STRUCT__entry(
		__field(struct mm_struct *, mm)
		__field(unsigned long, address)
	),

	TP_fast_assign(
		__entry->mm = mm;
		__entry->address = address;
	),

	TP_printk("mm=%lx address=%lx",
		(unsigned long)__entry->mm, __entry->address)
	);

TRACE_EVENT(mm_pagereclaim_pgout,

	TP_PROTO(struct address_space *mapping, unsigned long offset, int anon, int filecache),

	TP_ARGS(mapping, offset, anon, filecache),

	TP_STRUCT__entry(
		__field(struct address_space *, mapping)
		__field(unsigned long, offset)
		__field(int, anon)
		__field(int, filecache)
	),

	TP_fast_assign(
		__entry->mapping = mapping;
		__entry->offset = offset;
		__entry->anon = anon;
		__entry->filecache = filecache;
	),

	TP_printk("mapping=%lx, offset=%lx %s %s",
		(unsigned long)__entry->mapping, __entry->offset, 
			__entry->anon ? "anonymous" : "pagecache",
			__entry->filecache ? "filebacked" : "swapbacked")
	);

TRACE_EVENT(mm_pagereclaim_free,

	TP_PROTO(unsigned long nr_reclaimed),

	TP_ARGS(nr_reclaimed),

	TP_STRUCT__entry(
		__field(unsigned long, nr_reclaimed)
	),

	TP_fast_assign(
		__entry->nr_reclaimed = nr_reclaimed;
	),

	TP_printk("freed=%ld", __entry->nr_reclaimed)
	);

TRACE_EVENT(mm_background_writeout,

	TP_PROTO(unsigned long written),

	TP_ARGS(written),

	TP_STRUCT__entry(
		__field(unsigned long, written)
	),

	TP_fast_assign(
		__entry->written = written;
	),

	TP_printk("written=%ld", __entry->written)
	);

TRACE_EVENT(mm_olddata_writeout,

	TP_PROTO(unsigned long written),

	TP_ARGS(written),

	TP_STRUCT__entry(
		__field(unsigned long, written)
	),

	TP_fast_assign(
		__entry->written = written;
	),

	TP_printk("written=%ld", __entry->written)
	);

TRACE_EVENT(mm_balancedirty_writeout,

	TP_PROTO(unsigned long written),

	TP_ARGS(written),

	TP_STRUCT__entry(
		__field(unsigned long, written)
	),

	TP_fast_assign(
		__entry->written = written;
	),

	TP_printk("written=%ld", __entry->written)
	);

TRACE_EVENT(mm_kswapd_ran,

	TP_PROTO(struct pglist_data *pgdat, unsigned long reclaimed),

	TP_ARGS(pgdat, reclaimed),

	TP_STRUCT__entry(
		__field(struct pglist_data *, pgdat)
		__field(int, node_id)
		__field(unsigned long, reclaimed)
	),

	TP_fast_assign(
		__entry->pgdat = pgdat;
		__entry->node_id = pgdat->node_id;
		__entry->reclaimed = reclaimed;
	),

	TP_printk("node=%d reclaimed=%ld", __entry->node_id, __entry->reclaimed)
	);

TRACE_EVENT(mm_directreclaim_reclaimall,

	TP_PROTO(int node, unsigned long reclaimed, unsigned long priority),

	TP_ARGS(node, reclaimed, priority),

	TP_STRUCT__entry(
		__field(int, node)
		__field(unsigned long, reclaimed)
		__field(unsigned long, priority)
	),

	TP_fast_assign(
		__entry->node = node;
		__entry->reclaimed = reclaimed;
		__entry->priority = priority;
	),

	TP_printk("node=%d reclaimed=%ld priority=%ld", __entry->node, __entry->reclaimed, 
					__entry->priority)
	);

TRACE_EVENT(mm_directreclaim_reclaimzone,

	TP_PROTO(int node, unsigned long reclaimed, unsigned long priority),

	TP_ARGS(node, reclaimed, priority),

	TP_STRUCT__entry(
		__field(int, node)
		__field(unsigned long, reclaimed)
		__field(unsigned long, priority)
	),

	TP_fast_assign(
		__entry->node = node;
		__entry->reclaimed = reclaimed;
		__entry->priority = priority;
	),

	TP_printk("node = %d reclaimed=%ld, priority=%ld",
			__entry->node, __entry->reclaimed, __entry->priority)
	);
TRACE_EVENT(mm_pagereclaim_shrinkzone,

	TP_PROTO(unsigned long reclaimed, unsigned long priority),

	TP_ARGS(reclaimed, priority),

	TP_STRUCT__entry(
		__field(unsigned long, reclaimed)
		__field(unsigned long, priority)
	),

	TP_fast_assign(
		__entry->reclaimed = reclaimed;
		__entry->priority = priority;
	),

	TP_printk("reclaimed=%ld priority=%ld",
			__entry->reclaimed, __entry->priority)
	);

TRACE_EVENT(mm_pagereclaim_shrinkactive,

	TP_PROTO(unsigned long scanned, int file, int priority),

	TP_ARGS(scanned, file, priority),

	TP_STRUCT__entry(
		__field(unsigned long, scanned)
		__field(int, file)
		__field(int, priority)
	),

	TP_fast_assign(
		__entry->scanned = scanned;
		__entry->file = file;
		__entry->priority = priority;
	),

	TP_printk("scanned=%ld, %s, priority=%d",
		__entry->scanned, __entry->file ? "pagecache" : "anonymous",
		__entry->priority)
	);

TRACE_EVENT(mm_pagereclaim_shrinkinactive,

	TP_PROTO(unsigned long scanned, int file, 
			unsigned long reclaimed, int priority),

	TP_ARGS(scanned, file, reclaimed, priority),

	TP_STRUCT__entry(
		__field(unsigned long, scanned)
		__field(int, file)
		__field(unsigned long, reclaimed)
		__field(int, priority)
	),

	TP_fast_assign(
		__entry->scanned = scanned;
		__entry->file = file;
		__entry->reclaimed = reclaimed;
		__entry->priority = priority;
	),

	TP_printk("scanned=%ld, %s, reclaimed=%ld, priority=%d",
		__entry->scanned,
		__entry->file ? "pagecache" : "anonymous",
		__entry->reclaimed, __entry->priority)
	);

TRACE_EVENT(mm_kernel_pagefault,

	TP_PROTO(struct task_struct *task, unsigned long address, struct pt_regs *regs),

	TP_ARGS(task, address, regs),

	TP_STRUCT__entry(
		__field(struct task_struct *, task)
		__field(unsigned long, address)
		__field(struct pt_regs *, regs)
	),

	TP_fast_assign(
		__entry->task = task;
		__entry->address = address;
		__entry->regs = regs;
	),

	TP_printk("task=%lx, address=%lx, regs=%lx",
		(unsigned long)__entry->task, (unsigned long)__entry->address,
			(unsigned long)__entry->regs)
	);

TRACE_EVENT(mm_vmscan_kswapd_sleep,

	TP_PROTO(int nid),

	TP_ARGS(nid),

	TP_STRUCT__entry(
		__field(        int,    nid     )
	),

	TP_fast_assign(
		__entry->nid    = nid;
	),

	TP_printk("nid=%d", __entry->nid)
	);

TRACE_EVENT(mm_vmscan_kswapd_wake,

	TP_PROTO(int nid, int order),

	TP_ARGS(nid, order),

	TP_STRUCT__entry(
		__field(        int,    nid     )
		__field(        int,    order   )
	),

	TP_fast_assign(
		__entry->nid    = nid;
		__entry->order  = order;
	),

	TP_printk("nid=%d order=%d", __entry->nid, __entry->order)
	);

TRACE_EVENT(mm_vmscan_wakeup_kswapd,

	TP_PROTO(int nid, int zid, int order),

	TP_ARGS(nid, zid, order),

	TP_STRUCT__entry(
		__field(        int,            nid     )
		__field(        int,            zid     )
		__field(        int,            order   )
	),

	TP_fast_assign(
		__entry->nid            = nid;
		__entry->zid            = zid;
		__entry->order          = order;
	),

	TP_printk("nid=%d zid=%d order=%d",
		__entry->nid,
		__entry->zid,
		__entry->order)
	);

TRACE_EVENT(mm_vmscan_direct_reclaim_begin,

	TP_PROTO(int order, int may_writepage, gfp_t gfp_flags),

	TP_ARGS(order, may_writepage, gfp_flags),

	TP_STRUCT__entry(
		__field(        int,    order           )
		__field(        int,    may_writepage   )
		__field(        gfp_t,  gfp_flags       )
	),

	TP_fast_assign(
		__entry->order          = order;
		__entry->may_writepage  = may_writepage;
		__entry->gfp_flags      = gfp_flags;
	),

	TP_printk("order=%d may_writepage=%d gfp_flags=%s",
		__entry->order,
		__entry->may_writepage,
		show_gfp_flags(__entry->gfp_flags))
	);

TRACE_EVENT(mm_vmscan_direct_reclaim_end,

	TP_PROTO(unsigned long nr_reclaimed),

	TP_ARGS(nr_reclaimed),

	TP_STRUCT__entry(
		__field(        unsigned long,  nr_reclaimed    )
	),

	TP_fast_assign(
		__entry->nr_reclaimed   = nr_reclaimed;
	),

	TP_printk("nr_reclaimed=%lu", __entry->nr_reclaimed)
	);

TRACE_EVENT(mm_vmscan_lru_isolate,

	TP_PROTO(int order,
		unsigned long nr_requested,
		unsigned long nr_scanned,
		unsigned long nr_taken,
		unsigned long nr_lumpy_taken,
		unsigned long nr_lumpy_dirty,
		unsigned long nr_lumpy_failed,
		int isolate_mode),

	TP_ARGS(order, nr_requested, nr_scanned, nr_taken, nr_lumpy_taken, nr_lumpy_dirty, nr_lumpy_failed, isolate_mode),

	TP_STRUCT__entry(
		__field(int, order)
		__field(unsigned long, nr_requested)
		__field(unsigned long, nr_scanned)
		__field(unsigned long, nr_taken)
		__field(unsigned long, nr_lumpy_taken)
		__field(unsigned long, nr_lumpy_dirty)
		__field(unsigned long, nr_lumpy_failed)
		__field(int, isolate_mode)
		),

	TP_fast_assign(
		__entry->order = order;
		__entry->nr_requested = nr_requested;
		__entry->nr_scanned = nr_scanned;
		__entry->nr_taken = nr_taken;
		__entry->nr_lumpy_taken = nr_lumpy_taken;
		__entry->nr_lumpy_dirty = nr_lumpy_dirty;
		__entry->nr_lumpy_failed = nr_lumpy_failed;
		__entry->isolate_mode = isolate_mode;
		),

		TP_printk("isolate_mode=%d order=%d nr_requested=%lu nr_scanned=%lu nr_taken=%lu contig_taken=%lu contig_dirty=%lu contig_failed=%lu",
		__entry->isolate_mode,
		__entry->order,
		__entry->nr_requested,
		__entry->nr_scanned,
		__entry->nr_taken,
		__entry->nr_lumpy_taken,
		__entry->nr_lumpy_dirty,
		__entry->nr_lumpy_failed)
	);

TRACE_EVENT(mm_vmscan_writepage,

	TP_PROTO(struct page *page,
		int file,
		int sync_io),

	TP_ARGS(page, file, sync_io),

	TP_STRUCT__entry(
		__field(struct page *, page)
		__field(int, file)
		__field(int, sync_io)
	),

	TP_fast_assign(
		__entry->page = page;
		__entry->file = file;
		__entry->sync_io = sync_io;
	),

	TP_printk("page=%p pfn=%lu file=%d sync_io=%d",
		__entry->page,
		page_to_pfn(__entry->page),
		__entry->file,
		__entry->sync_io)
	);

#endif /* _TRACE_KMEM_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
