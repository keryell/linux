/*
 * Copyright 2013 Red Hat Inc.
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
 * Authors: Jérôme Glisse <jglisse@redhat.com>
 */
/*
 * Refer to include/linux/hmm.h for information about heterogeneous memory
 * management or HMM for short.
 */
#include <linux/mm.h>
#include <linux/hmm.h>
#include <linux/rmap.h>
#include <linux/swap.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mmzone.h>
#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/swapops.h>
#include <linux/hugetlb.h>
#include <linux/memremap.h>
#include <linux/mmu_notifier.h>

#define SECTION_SIZE (1UL << PA_SECTION_SHIFT)


/*
 * struct hmm - HMM per mm struct
 *
 * @mm: mm struct this HMM struct is bound to
 * @lock: lock protecting mirrors list
 * @mirrors: list of mirrors for this mm
 * @wait_queue: wait queue
 * @sequence: we track update to CPU page table with a sequence number
 * @mmu_notifier: mmu notifier to track update to CPU page table
 * @notifier_count: number of currently active notifier count
 */
struct hmm {
	struct mm_struct	*mm;
	spinlock_t		lock;
	struct list_head	ranges;
	struct list_head	mirrors;
	atomic_t		sequence;
	wait_queue_head_t	wait_queue;
	struct mmu_notifier	mmu_notifier;
	atomic_t		notifier_count;
};

/*
 * hmm_register - register HMM against an mm (HMM internal)
 *
 * @mm: mm struct to attach to
 *
 * This is not intended to be use directly by device driver but by other HMM
 * component. It allocates an HMM struct if mm does not have one and initialize
 * it.
 */
static struct hmm *hmm_register(struct mm_struct *mm)
{
	if (!mm->hmm) {
		struct hmm *hmm = NULL;

		hmm = kmalloc(sizeof(*hmm), GFP_KERNEL);
		if (!hmm)
			return NULL;
		init_waitqueue_head(&hmm->wait_queue);
		atomic_set(&hmm->notifier_count, 0);
		INIT_LIST_HEAD(&hmm->mirrors);
		atomic_set(&hmm->sequence, 0);
		hmm->mmu_notifier.ops = NULL;
		INIT_LIST_HEAD(&hmm->ranges);
		spin_lock_init(&hmm->lock);
		hmm->mm = mm;

		spin_lock(&mm->page_table_lock);
		if (!mm->hmm)
			mm->hmm = hmm;
		else
			kfree(hmm);
		spin_unlock(&mm->page_table_lock);
	}

	/*
	 * The hmm struct can only be free once mm_struct goes away
	 * hence we should always have pre-allocated an new hmm struct
	 * above.
	 */
	return mm->hmm;
}

void hmm_mm_destroy(struct mm_struct *mm)
{
	struct hmm *hmm;

	/*
	 * We should not need to lock here as no one should be able to register
	 * a new HMM while an mm is being destroy. But just to be safe ...
	 */
	spin_lock(&mm->page_table_lock);
	hmm = mm->hmm;
	mm->hmm = NULL;
	spin_unlock(&mm->page_table_lock);
	kfree(hmm);
}


#if IS_ENABLED(CONFIG_HMM_MIRROR)
static void hmm_invalidate_range(struct hmm *hmm,
				 enum hmm_update action,
				 unsigned long start,
				 unsigned long end)
{
	struct hmm_mirror *mirror;
	struct hmm_range *range;

	rcu_read_lock();
	list_for_each_entry_rcu(range, &hmm->ranges, list) {
		unsigned long addr, idx, npages;

		if (end < range->start || start >= range->end)
			continue;

		range->valid = false;
		addr = max(start, range->start);
		idx = (addr - range->start) >> PAGE_SHIFT;
		npages = (min(range->end, end) - addr) >> PAGE_SHIFT;
		memset(&range->pfns[idx], 0, sizeof(*range->pfns) * npages);
	}
	rcu_read_unlock();

	/*
	 * Mirror being added or remove is a rare event so list traversal isn't
	 * protected by a lock, we rely on simple rules. All list modification
	 * are done using list_add_rcu() and list_del_rcu() under a spinlock to
	 * protect from concurrent addition or removal but not traversal.
	 *
	 * Because hmm_mirror_unregister() wait for all running invalidation to
	 * complete (and thus all list traversal to finish). None of the mirror
	 * struct can be freed from under us while traversing the list and thus
	 * it is safe to dereference their list pointer even if they were just
	 * remove.
	 */
	list_for_each_entry (mirror, &hmm->mirrors, list)
		mirror->ops->update(mirror, action, start, end);
}

static void hmm_invalidate_page(struct mmu_notifier *mn,
				struct mm_struct *mm,
				unsigned long addr)
{
	unsigned long start = addr & PAGE_MASK;
	unsigned long end = start + PAGE_SIZE;
	struct hmm *hmm = mm->hmm;

	VM_BUG_ON(!hmm);

	atomic_inc(&hmm->notifier_count);
	atomic_inc(&hmm->sequence);
	hmm_invalidate_range(mm->hmm, HMM_UPDATE_INVALIDATE, start, end);
	atomic_dec(&hmm->notifier_count);
	wake_up(&hmm->wait_queue);
}

static void hmm_invalidate_range_start(struct mmu_notifier *mn,
				       struct mm_struct *mm,
				       unsigned long start,
				       unsigned long end)
{
	struct hmm *hmm = mm->hmm;

	VM_BUG_ON(!hmm);

	atomic_inc(&hmm->notifier_count);
	atomic_inc(&hmm->sequence);
	hmm_invalidate_range(mm->hmm, HMM_UPDATE_INVALIDATE, start, end);
}

static void hmm_invalidate_range_end(struct mmu_notifier *mn,
				     struct mm_struct *mm,
				     unsigned long start,
				     unsigned long end)
{
	struct hmm *hmm = mm->hmm;

	VM_BUG_ON(!hmm);

	/* Reverse order here because we are getting out of invalidation */
	atomic_dec(&hmm->notifier_count);
	wake_up(&hmm->wait_queue);
}

static const struct mmu_notifier_ops hmm_mmu_notifier_ops = {
	.invalidate_page	= hmm_invalidate_page,
	.invalidate_range_start	= hmm_invalidate_range_start,
	.invalidate_range_end	= hmm_invalidate_range_end,
};

static int hmm_mirror_do_register(struct hmm_mirror *mirror,
				  struct mm_struct *mm,
				  const bool locked)
{
	/* Sanity check */
	if (!mm || !mirror || !mirror->ops)
		return -EINVAL;

	mirror->hmm = hmm_register(mm);
	if (!mirror->hmm)
		return -ENOMEM;

	/* Register mmu_notifier if not already, use mmap_sem for locking */
	if (!mirror->hmm->mmu_notifier.ops) {
		struct hmm *hmm = mirror->hmm;

		if (!locked)
			down_write(&mm->mmap_sem);
		if (!hmm->mmu_notifier.ops) {
			hmm->mmu_notifier.ops = &hmm_mmu_notifier_ops;
			if (__mmu_notifier_register(&hmm->mmu_notifier, mm)) {
				hmm->mmu_notifier.ops = NULL;
				up_write(&mm->mmap_sem);
				return -ENOMEM;
			}
		}
		if (!locked)
			up_write(&mm->mmap_sem);
	}

	spin_lock(&mirror->hmm->lock);
	list_add_rcu(&mirror->list, &mirror->hmm->mirrors);
	spin_unlock(&mirror->hmm->lock);

	return 0;
}

/*
 * hmm_mirror_register() - register a mirror against an mm
 *
 * @mirror: new mirror struct to register
 * @mm: mm to register against
 *
 * To start mirroring a process address space device driver must register an
 * HMM mirror struct.
 */
int hmm_mirror_register(struct hmm_mirror *mirror, struct mm_struct *mm)
{
	return hmm_mirror_do_register(mirror, mm, false);
}
EXPORT_SYMBOL(hmm_mirror_register);

/*
 * hmm_mirror_register_locked() - register a mirror against an mm
 *
 * @mirror: new mirror struct to register
 * @mm: mm to register against
 *
 * Same as hmm_mirror_register() except that mmap_sem must write locked !
 */
int hmm_mirror_register_locked(struct hmm_mirror *mirror, struct mm_struct *mm)
{
	return hmm_mirror_do_register(mirror, mm, true);
}
EXPORT_SYMBOL(hmm_mirror_register_locked);

/*
 * hmm_mirror_unregister() - unregister a mirror
 *
 * @mirror: new mirror struct to register
 *
 * Stop mirroring a process address space and cleanup.
 */
void hmm_mirror_unregister(struct hmm_mirror *mirror)
{
	struct hmm *hmm = mirror->hmm;

	spin_lock(&hmm->lock);
	list_del_rcu(&mirror->list);
	spin_unlock(&hmm->lock);

	/*
	 * Wait for all active notifier so that it is safe to traverse mirror
	 * list without any lock.
	 */
	wait_event(hmm->wait_queue, !atomic_read(&hmm->notifier_count));
}
EXPORT_SYMBOL(hmm_mirror_unregister);


static void hmm_pfns_error(hmm_pfn_t *pfns,
			   unsigned long addr,
			   unsigned long end)
{
	for (; addr < end; addr += PAGE_SIZE, pfns++)
		*pfns = HMM_PFN_ERROR;
}

static void hmm_pfns_empty(hmm_pfn_t *pfns,
			   unsigned long addr,
			   unsigned long end)
{
	for (; addr < end; addr += PAGE_SIZE, pfns++)
		*pfns = HMM_PFN_EMPTY;
}

static void hmm_pfns_special(hmm_pfn_t *pfns,
			     unsigned long addr,
			     unsigned long end)
{
	for (; addr < end; addr += PAGE_SIZE, pfns++)
		*pfns = HMM_PFN_SPECIAL;
}

static void hmm_pfns_clear(hmm_pfn_t *pfns,
			   unsigned long addr,
			   unsigned long end)
{
	unsigned long npfns = (end - addr) >> PAGE_SHIFT;

	memset(pfns, 0, sizeof(*pfns) * npfns);
}

static int hmm_vma_do_fault(struct vm_area_struct *vma,
			    const hmm_pfn_t fault,
			    unsigned long addr,
			    hmm_pfn_t *pfn,
			    bool block)
{
	unsigned flags = FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_REMOTE;
	int r;

	flags |= block ? 0 : FAULT_FLAG_ALLOW_RETRY;
	flags |= (fault & HMM_PFN_WRITE) ? FAULT_FLAG_WRITE : 0;
	r = handle_mm_fault(vma, addr, flags);
	if (r & VM_FAULT_RETRY)
		return -EAGAIN;
	if (r & VM_FAULT_ERROR) {
		*pfn = HMM_PFN_ERROR;
		return -EFAULT;
	}

	return 0;
}

static int hmm_vma_walk(struct vm_area_struct *vma,
			const hmm_pfn_t fault,
			unsigned long start,
			unsigned long end,
			hmm_pfn_t *pfns,
			bool block)
{
	unsigned long addr, next;
	hmm_pfn_t flag;

	flag = vma->vm_flags & VM_READ ? HMM_PFN_READ : 0;

	for (addr = start; addr < end; addr = next) {
		unsigned long i = (addr - start) >> PAGE_SHIFT;
		pgd_t *pgdp;
		pud_t *pudp;
		pmd_t *pmdp;
		pte_t *ptep;
		pmd_t pmd;
		int ret;

		/*
		 * We are accessing/faulting for a device from an unknown
		 * thread that might be foreign to the mm we are faulting
		 * against so do not call arch_vma_access_permitted() !
		 */

		next = pgd_addr_end(addr, end);
		pgdp = pgd_offset(vma->vm_mm, addr);
		if (pgd_none(*pgdp) || pgd_bad(*pgdp)) {
			if (!(vma->vm_flags & VM_READ)) {
				hmm_pfns_empty(&pfns[i], addr, next);
				continue;
			}
			if (!fault) {
				hmm_pfns_empty(&pfns[i], addr, next);
				continue;
			}
			pudp = pud_alloc(vma->vm_mm, pgdp, addr);
			if (!pudp) {
				hmm_pfns_error(&pfns[i], addr, next);
				continue;
			}
		}

		next = pud_addr_end(addr, end);
		pudp = pud_offset(pgdp, addr);
		if (pud_none(*pudp) || pud_bad(*pudp)) {
			if (!(vma->vm_flags & VM_READ)) {
				hmm_pfns_empty(&pfns[i], addr, next);
				continue;
			}
			if (!fault) {
				hmm_pfns_empty(&pfns[i], addr, next);
				continue;
			}
			pmdp = pmd_alloc(vma->vm_mm, pudp, addr);
			if (!pmdp) {
				hmm_pfns_error(&pfns[i], addr, next);
				continue;
			}
		}

		next = pmd_addr_end(addr, end);
		pmdp = pmd_offset(pudp, addr);
		pmd = pmd_read_atomic(pmdp);
		barrier();
		if (pmd_none(pmd) || pmd_bad(pmd)) {
			if (!(vma->vm_flags & VM_READ)) {
				hmm_pfns_empty(&pfns[i], addr, next);
				continue;
			}
			if (!fault) {
				hmm_pfns_empty(&pfns[i], addr, next);
				continue;
			}
			/*
			 * Use pte_alloc() instead of pte_alloc_map, because we
			 * can't run pte_offset_map on the pmd, if an huge pmd
			 * could materialize from under us.
			 */
			if (unlikely(pte_alloc(vma->vm_mm, pmdp, addr))) {
				hmm_pfns_error(&pfns[i], addr, next);
				continue;
			}
			pmd = *pmdp;
		}
		if (pmd_trans_huge(pmd) || pmd_devmap(pmd)) {
			unsigned long pfn = pmd_pfn(pmd) + pte_index(addr);
			hmm_pfn_t flags = flag;

			if (pmd_protnone(pmd)) {
				hmm_pfns_clear(&pfns[i], addr, next);
				if (fault)
					goto fault;
				continue;
			}
			flags |= pmd_write(*pmdp) ? HMM_PFN_WRITE : 0;
			flags |= pmd_devmap(pmd) ? HMM_PFN_DEVICE : 0;
			if ((flags & fault) != fault)
				goto fault;
			for (; addr < next; addr += PAGE_SIZE, i++, pfn++)
				pfns[i] = hmm_pfn_from_pfn(pfn) | flags;
			continue;
		}

		ptep = pte_offset_map(pmdp, addr);
		for (; addr < next; addr += PAGE_SIZE, i++, ptep++) {
			swp_entry_t entry;
			pte_t pte = *ptep;

			if (pte_none(pte)) {
				if (fault) {
					pte_unmap(ptep);
					goto fault;
				}
				pfns[i] = HMM_PFN_EMPTY;
				continue;
			}

			entry = pte_to_swp_entry(pte);
			if (!pte_present(pte) && !non_swap_entry(entry)) {
				if (fault) {
					pte_unmap(ptep);
					goto fault;
				}
				pfns[i] = 0;
				continue;
			}

			if (pte_present(pte)) {
				pfns[i] = hmm_pfn_from_pfn(pte_pfn(pte))|flag;
				pfns[i] |= pte_write(pte) ? HMM_PFN_WRITE : 0;
			} else if (is_device_entry(entry)) {
				/* Do not fault device entry */
				pfns[i] = hmm_pfn_from_pfn(swp_offset(entry));
				if (is_write_device_entry(entry))
					pfns[i] |= HMM_PFN_WRITE;
				pfns[i] |= HMM_PFN_DEVICE;
				pfns[i] |= HMM_PFN_UNADDRESSABLE;
				pfns[i] |= flag;
			} else if (is_migration_entry(entry) && fault) {
				migration_entry_wait(vma->vm_mm, pmdp, addr);
				/* Start again for current address */
				next = addr;
				ptep++;
				break;
			} else {
				/* Report error for everything else */
				pfns[i] = HMM_PFN_ERROR;
			}
			if ((fault & pfns[i]) != fault) {
				pte_unmap(ptep);
				goto fault;
			}
		}
		pte_unmap(ptep - 1);
		continue;

fault:
		ret = hmm_vma_do_fault(vma, fault, addr, &pfns[i], block);
		if (ret)
			return ret;
		/* Start again for current address */
		next = addr;
	}

	return 0;
}

/*
 * hmm_vma_get_pfns() - snapshot CPU page table for a range of virtual address
 * @vma: virtual memory area containing the virtual address range
 * @range: use to track snapshot validity
 * @start: range virtual start address (inclusive)
 * @end: range virtual end address (exclusive)
 * @entries: array of hmm_pfn_t provided by caller fill by function
 * Returns: -EINVAL if invalid argument, -ENOMEM out of memory, 0 success
 *
 * This snapshot the CPU page table for a range of virtual address, snapshot
 * validity is track by the range struct see hmm_vma_range_done() for further
 * informations.
 *
 * The range struct is initialized and track CPU page table only if function
 * returns success (0) then you must call hmm_vma_range_done() to stop range
 * CPU page table update tracking.
 *
 * NOT CALLING hmm_vma_range_done() IF FUNCTION RETURNS 0 WILL LEAD TO SERIOUS
 * MEMORY CORRUPTION ! YOU HAVE BEEN WARN !
 */
int hmm_vma_get_pfns(struct vm_area_struct *vma,
		     struct hmm_range *range,
		     unsigned long start,
		     unsigned long end,
		     hmm_pfn_t *pfns)
{
	struct hmm *hmm;

	/* FIXME support hugetlb fs */
	if (is_vm_hugetlb_page(vma) || (vma->vm_flags & VM_SPECIAL)) {
		hmm_pfns_special(pfns, start, end);
		return -EINVAL;
	}

	/* Sanity check, this really should not happen ! */
	if (start < vma->vm_start || start >= vma->vm_end)
		return -EINVAL;
	if (end < vma->vm_start || end > vma->vm_end)
		return -EINVAL;

	hmm = hmm_register(vma->vm_mm);
	if (!hmm)
		return -ENOMEM;
	/* Caller must have register a mirror (with hmm_mirror_register()) ! */
	if (!hmm->mmu_notifier.ops)
		return -EINVAL;

	/* Initialize range to track CPU page table update */
	range->start = start;
	range->pfns = pfns;
	range->end = end;
	spin_lock(&hmm->lock);
	range->valid = true;
	list_add_rcu(&range->list, &hmm->ranges);
	spin_unlock(&hmm->lock);

	hmm_vma_walk(vma, 0, start, end, pfns, false);
	return 0;
}
EXPORT_SYMBOL(hmm_vma_get_pfns);

/*
 * hmm_vma_range_done() - stop tracking change to CPU page table over a range
 * @vma: virtual memory area containing the virtual address range
 * @range: range being track
 * Returns: false if range data have been invalidated, true otherwise
 *
 * Range struct is use to track update to CPU page table after call to either
 * hmm_vma_get_pfns() or hmm_vma_fault(). Once device driver is done using or
 * want to lock update to data it gots from those functions it must call the
 * hmm_vma_range_done() function which stop tracking CPU page table update.
 *
 * Note that device driver must still implement general CPU page table update
 * tracking either by using hmm_mirror (see hmm_mirror_register()) or by using
 * mmu_notifier API directly.
 *
 * CPU page table update tracking done through hmm_range is only temporary and
 * to be use while trying to duplicate CPU page table content for a range of
 * virtual address.
 *
 * There is 2 way to use this :
 * again:
 *   hmm_vma_get_pfns(vma, range, start, end, pfns); or hmm_vma_fault(...);
 *   trans = device_build_page_table_update_transaction(pfns);
 *   device_page_table_lock();
 *   if (!hmm_vma_range_done(vma, range)) {
 *     device_page_table_unlock();
 *     goto again;
 *   }
 *   device_commit_transaction(trans);
 *   device_page_table_unlock();
 *
 * Or:
 *   hmm_vma_get_pfns(vma, range, start, end, pfns); or hmm_vma_fault(...);
 *   device_page_table_lock();
 *   hmm_vma_range_done(vma, range);
 *   device_update_page_table(pfns);
 *   device_page_table_unlock();
 */
bool hmm_vma_range_done(struct vm_area_struct *vma, struct hmm_range *range)
{
	unsigned long npages = (range->end - range->start) >> PAGE_SHIFT;
	struct hmm *hmm;

	if (range->end <= range->start) {
		BUG();
		return false;
	}

	hmm = hmm_register(vma->vm_mm);
	if (!hmm) {
		memset(range->pfns, 0, sizeof(*range->pfns) * npages);
		return false;
	}

	spin_lock(&hmm->lock);
	list_del_rcu(&range->list);
	spin_unlock(&hmm->lock);

	return range->valid;
}
EXPORT_SYMBOL(hmm_vma_range_done);

/*
 * hmm_vma_fault() - try to fault some address in a virtual address range
 * @vma: virtual memory area containing the virtual address range
 * @range: use to track pfns array content validity
 * @start: fault range virtual start address (inclusive)
 * @end: fault range virtual end address (exclusive)
 * @pfns: array of hmm_pfn_t, only entry with fault flag set will be faulted
 * @write: is it a write fault
 * @block: allow blocking on fault (if true it sleeps and do not drop mmap_sem)
 * Returns: 0 success, error otherwise (-EAGAIN means mmap_sem have been drop)
 *
 * This is similar to a regular CPU page fault except that it will not trigger
 * any memory migration if the memory being faulted is not accessible by CPUs.
 *
 * On error, for one virtual address in the range, the function will set the
 * hmm_pfn_t error flag for the corresponding pfn entry.
 *
 * Expected use pattern:
 * retry:
 *   down_read(&mm->mmap_sem);
 *   // Find vma and address device wants to fault, initialize hmm_pfn_t
 *   // array accordingly
 *   ret = hmm_vma_fault(vma, start, end, pfns, allow_retry);
 *   switch (ret) {
 *   case -EAGAIN:
 *     hmm_vma_range_done(vma, range);
 *     // You might want to rate limit or yield to play nicely, you may
 *     // also commit any valid pfn in the array assuming that you are
 *     // getting true from hmm_vma_range_monitor_end()
 *     goto retry;
 *   case 0:
 *     break;
 *   default:
 *     // Handle error !
 *     up_read(&mm->mmap_sem)
 *     return;
 *   }
 *   // Take device driver lock that serialize device page table update
 *   driver_lock_device_page_table_update();
 *   hmm_vma_range_done(vma, range);
 *   // Commit pfns we got from hmm_vma_fault()
 *   driver_unlock_device_page_table_update();
 *   up_read(&mm->mmap_sem)
 *
 * YOU MUST CALL hmm_vma_range_done() AFTER THIS FUNCTION RETURN SUCCESS (0)
 * BEFORE FREEING THE range struct OR YOU WILL HAVE SERIOUS MEMORY CORRUPTION !
 *
 * YOU HAVE BEEN WARN !
 */
int hmm_vma_fault(struct vm_area_struct *vma,
		  struct hmm_range *range,
		  unsigned long start,
		  unsigned long end,
		  hmm_pfn_t *pfns,
		  bool write,
		  bool block)
{
	hmm_pfn_t fault = HMM_PFN_READ | (write ? HMM_PFN_WRITE : 0);
	struct hmm *hmm;
	int ret;

	/* Sanity check, this really should not happen ! */
	if (start < vma->vm_start || start >= vma->vm_end)
		return -EINVAL;
	if (end < vma->vm_start || end > vma->vm_end)
		return -EINVAL;

	hmm = hmm_register(vma->vm_mm);
	if (!hmm) {
		hmm_pfns_clear(pfns, start, end);
		return -ENOMEM;
	}
	/* Caller must have register a mirror (with hmm_mirror_register()) ! */
	if (!hmm->mmu_notifier.ops)
		return -EINVAL;

	/* Initialize range to track CPU page table update */
	range->start = start;
	range->pfns = pfns;
	range->end = end;
	spin_lock(&hmm->lock);
	range->valid = true;
	list_add_rcu(&range->list, &hmm->ranges);
	spin_unlock(&hmm->lock);

	/* FIXME support hugetlb fs */
	if (is_vm_hugetlb_page(vma) || (vma->vm_flags & VM_SPECIAL)) {
		hmm_pfns_special(pfns, start, end);
		return 0;
	}

	ret = hmm_vma_walk(vma, fault, start, end, pfns, block);
	if (ret)
		hmm_vma_range_done(vma, range);
	return ret;
}
EXPORT_SYMBOL(hmm_vma_fault);
#endif /* IS_ENABLED(CONFIG_HMM_MIRROR) */


#if IS_ENABLED(CONFIG_HMM_DEVMEM)
struct page *hmm_vma_alloc_locked_page(struct vm_area_struct *vma,
				       unsigned long addr)
{
	struct page *page;

	page = alloc_page_vma(GFP_HIGHUSER, vma, addr);
	if (!page)
		return NULL;
	lock_page(page);
	return page;
}
EXPORT_SYMBOL(hmm_vma_alloc_locked_page);


static void hmm_devmem_release(struct percpu_ref *ref)
{
	struct hmm_devmem *devmem;

	devmem = container_of(ref, struct hmm_devmem, ref);
	complete(&devmem->completion);
	devmem->inuse = false;
}

static void hmm_devmem_exit(void *data)
{
	struct percpu_ref *ref = data;
	struct hmm_devmem *devmem;

	devmem = container_of(ref, struct hmm_devmem, ref);
	percpu_ref_exit(ref);
	devm_remove_action(devmem->device, hmm_devmem_exit, data);
}

static void hmm_devmem_kill(void *data)
{
	struct percpu_ref *ref = data;
	struct hmm_devmem *devmem;

	devmem = container_of(ref, struct hmm_devmem, ref);
	devmem->inuse = false;
	percpu_ref_kill(ref);
	wait_for_completion(&devmem->completion);
	devm_remove_action(devmem->device, hmm_devmem_kill, data);
}

static int hmm_devmem_fault(struct vm_area_struct *vma,
			    unsigned long addr,
			    struct page *page,
			    unsigned flags,
			    pmd_t *pmdp)
{
	struct hmm_devmem *devmem = page->pgmap->data;

	return devmem->ops->fault(devmem, vma, addr, page, flags, pmdp);
}

static void hmm_devmem_free(struct page *page, void *data)
{
	struct hmm_devmem *devmem = data;

	devmem->ops->free(devmem, page);
}

/*
 * hmm_devmem_add() - hotplug fake ZONE_DEVICE memory for device memory
 *
 * @devmem: hmm_devmem struct use to track and manage the ZONE_DEVICE memory
 * @ops: memory event device driver callback (see struct hmm_devmem_ops)
 * @device: device struct to bind the resource too
 * @size: size in bytes of the device memory to add
 * Returns: 0 on success, error code otherwise
 *
 * This first find an empty range of physical address big enough to for the new
 * resource and then hotplug it as ZONE_DEVICE memory allocating struct page.
 * It does not do anything beside that, all events affecting the memory will go
 * through the various callback provided by hmm_devmem_ops struct.
 */
int hmm_devmem_add(struct hmm_devmem *devmem,
		   const struct hmm_devmem_ops *ops,
		   struct device *device,
		   unsigned long size)
{
	const struct resource *res;
	resource_size_t addr;
	void *ptr;
	int ret;

	init_completion(&devmem->completion);
	devmem->pfn_first = -1UL;
	devmem->pfn_last = -1UL;
	devmem->resource = NULL;
	devmem->device = device;
	devmem->pagemap = NULL;
	devmem->inuse = false;
	devmem->ops = ops;

	ret = percpu_ref_init(&devmem->ref,&hmm_devmem_release,0,GFP_KERNEL);
	if (ret)
		return ret;

	ret = devm_add_action(device, hmm_devmem_exit, &devmem->ref);
	if (ret)
		goto error;

	size = ALIGN(size, SECTION_SIZE);
	addr = (1UL << MAX_PHYSMEM_BITS) - size;

	/*
	 * FIXME add a new helper to quickly walk resource tree and find free
	 * range
	 *
	 * FIXME what about ioport_resource resource ?
	 */
	for (; addr > size; addr -= size) {
		ret = region_intersects(addr, size, 0, IORES_DESC_NONE);
		if (ret != REGION_DISJOINT)
			continue;

		devmem->resource = devm_request_mem_region(device, addr, size,
							   dev_name(device));
		if (!devmem->resource) {
			ret = -ENOMEM;
			goto error;
		}
		devmem->resource->desc = IORES_DESC_UNADDRESSABLE_MEMORY;
		break;
	}
	if (!devmem->resource) {
		ret = -ERANGE;
		goto error;
	}

	ptr = devm_memremap_pages(device, devmem->resource, &devmem->ref,
				  NULL, &devmem->pagemap,
				  hmm_devmem_fault, hmm_devmem_free, devmem,
				  MEMORY_DEVICE | MEMORY_DEVICE_ALLOW_MIGRATE |
				  MEMORY_DEVICE_UNADDRESSABLE);
	if (IS_ERR(ptr)) {
		ret = PTR_ERR(ptr);
		goto error;
	}

	ret = devm_add_action(device, hmm_devmem_kill, &devmem->ref);
	if (ret) {
		hmm_devmem_kill(&devmem->ref);
		goto error;
	}

	res = devmem->pagemap->res;
	devmem->pfn_first = res->start >> PAGE_SHIFT;
	devmem->pfn_last = (resource_size(res)>>PAGE_SHIFT)+devmem->pfn_first;
	devmem->inuse = true;

	return 0;

error:
	hmm_devmem_exit(&devmem->ref);
	return ret;
}
EXPORT_SYMBOL(hmm_devmem_add);

/*
 * hmm_devmem_remove() - remove device memory (kill and free ZONE_DEVICE)
 *
 * @devmem: hmm_devmem struct use to track and manage the ZONE_DEVICE memory
 * Returns: true if device memory is no longer in use, false if still in use
 *
 * This will hot remove memory that was hotplug by hmm_devmem_add on behalf of
 * device driver. It will free struct page and remove the resource that reserve
 * the physical address range for this device memory.
 *
 * Device driver can not free the struct while this function return false, it
 * must call over and over this function until it returns true. Note that if
 * there is a refcount bug this might never happen !
 */
bool hmm_devmem_remove(struct hmm_devmem *devmem)
{
	struct device *device = devmem->device;

	hmm_devmem_kill(&devmem->ref);

	if (devmem->pagemap) {
		const struct resource *res = devmem->pagemap->res;

		devm_memunmap_pages(device, __va(res->start));
		devmem->pagemap = NULL;
	}

	hmm_devmem_exit(&devmem->ref);

	/* FIXME maybe wait a bit ? */
	if (devmem->inuse)
		return false;

	if (devmem->resource) {
		resource_size_t size = resource_size(devmem->resource);

		devm_release_mem_region(device, devmem->resource->start, size);
		devmem->resource = NULL;
	}

	return true;
}
EXPORT_SYMBOL(hmm_devmem_remove);

/*
 * hmm_devmem_fault_range() - migrate back a virtual range of memory
 *
 * @devmem: hmm_devmem struct use to track and manage the ZONE_DEVICE memory
 * @vma: virtual memory area containing the range to be migrated
 * @ops: migration callback for allocating destination memory and copying
 * @src_pfns: array of hmm_pfn_t containing source pfns
 * @dst_pfns: array of hmm_pfn_t containing destination pfns
 * @start: start address of the range to migrate (inclusive)
 * @addr: fault address (must be inside the range)
 * @end: end address of the range to migrate (exclusive)
 * @private: pointer passed back to each of the callback
 * Returns: 0 on success, VM_FAULT_SIGBUS on error
 *
 * This is a wrapper around hmm_vma_migrate() which check the migration status
 * for a given fault address and return corresponding page fault handler status
 * ie 0 on success or VM_FAULT_SIGBUS if migration failed for fault address.
 *
 * This is an helper intendend to be use by ZONE_DEVICE fault handler.
 */
int hmm_devmem_fault_range(struct hmm_devmem *devmem,
			   struct vm_area_struct *vma,
			   const struct hmm_migrate_ops *ops,
			   hmm_pfn_t *src_pfns,
			   hmm_pfn_t *dst_pfns,
			   unsigned long start,
			   unsigned long addr,
			   unsigned long end,
			   void *private)
{
	if (hmm_vma_migrate(ops, vma, src_pfns, dst_pfns, start, end, private))
		return VM_FAULT_SIGBUS;

	if (dst_pfns[(addr - start) >> PAGE_SHIFT] & HMM_PFN_ERROR)
		return VM_FAULT_SIGBUS;

	return 0;
}
EXPORT_SYMBOL(hmm_devmem_fault_range);

/*
 * Device driver that want to handle multiple devices memory through a single
 * fake device can use hmm_device to do so. This is purely an helper and it
 * is not needed to make use of any HMM functionality.
 */
#define HMM_DEVICE_MAX 256

static DECLARE_BITMAP(hmm_device_mask, HMM_DEVICE_MAX);
static DEFINE_SPINLOCK(hmm_device_lock);
static struct class *hmm_device_class;
static dev_t hmm_device_devt;

static void hmm_device_release(struct device *device)
{
	struct hmm_device *hmm_device;

	hmm_device = container_of(device, struct hmm_device, device);
	spin_lock(&hmm_device_lock);
	clear_bit(hmm_device->minor, hmm_device_mask);
	spin_unlock(&hmm_device_lock);

	kfree(hmm_device);
}

struct hmm_device *hmm_device_new(void)
{
	struct hmm_device *hmm_device;
	int ret;

	hmm_device = kzalloc(sizeof(*hmm_device), GFP_KERNEL);
	if (!hmm_device)
		return ERR_PTR(-ENOMEM);

	ret = alloc_chrdev_region(&hmm_device->device.devt,0,1,"hmm_device");
	if (ret < 0) {
		kfree(hmm_device);
		return NULL;
	}

	spin_lock(&hmm_device_lock);
	hmm_device->minor=find_first_zero_bit(hmm_device_mask,HMM_DEVICE_MAX);
	if (hmm_device->minor >= HMM_DEVICE_MAX) {
		spin_unlock(&hmm_device_lock);
		kfree(hmm_device);
		return NULL;
	}
	set_bit(hmm_device->minor, hmm_device_mask);
	spin_unlock(&hmm_device_lock);

	dev_set_name(&hmm_device->device, "hmm_device%d", hmm_device->minor);
	hmm_device->device.devt = MKDEV(MAJOR(hmm_device_devt),
					hmm_device->minor);
	hmm_device->device.release = hmm_device_release;
	hmm_device->device.class = hmm_device_class;
	device_initialize(&hmm_device->device);

	return hmm_device;
}
EXPORT_SYMBOL(hmm_device_new);

void hmm_device_put(struct hmm_device *hmm_device)
{
	put_device(&hmm_device->device);
}
EXPORT_SYMBOL(hmm_device_put);

static int __init hmm_init(void)
{
	int ret;

	ret = alloc_chrdev_region(&hmm_device_devt, 0,
				  HMM_DEVICE_MAX,
				  "hmm_device");
	if (ret)
		return ret;

	hmm_device_class = class_create(THIS_MODULE, "hmm_device");
	if (IS_ERR(hmm_device_class)) {
		unregister_chrdev_region(hmm_device_devt, HMM_DEVICE_MAX);
		return PTR_ERR(hmm_device_class);
	}
	return 0;
}

static void __exit hmm_exit(void)
{
	unregister_chrdev_region(hmm_device_devt, HMM_DEVICE_MAX);
	class_destroy(hmm_device_class);
}

module_init(hmm_init);
module_exit(hmm_exit);
MODULE_LICENSE("GPL");
#endif /* IS_ENABLED(CONFIG_HMM_DEVMEM) */
