// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023 Advanced Micro Devices, Inc.
 */

#define pr_fmt(fmt)     "AMD-Vi: " fmt
#define dev_fmt(fmt)    pr_fmt(fmt)

#include <linux/iommu.h>
#include <linux/mm_types.h>

#include "amd_iommu.h"

static inline bool is_gcr3_table_empty(struct iommu_dev_data *dev_data)
{
	return (dev_data->gcr3_info.pasid_cnt == 0);
}

static inline bool is_pasid_enabled(struct iommu_dev_data *dev_data)
{
	if (dev_data->gcr3_info.gcr3_tbl != NULL &&
	    !is_gcr3_table_empty(dev_data)) {
		return true;
	}

	return false;
}

static int iommu_pasid_enable(struct iommu_dev_data *dev_data)
{
	struct device *dev = dev_data->dev;
	int ret = 0;

	spin_lock(&dev_data->lock);

	if (is_pasid_enabled(dev_data))
		goto out;

	if (!amd_iommu_pasid_supported()) {
		ret = -ENODEV;
		goto out;
	}

	/* attach_device path enables device PASID feature */
	if (!dev_data->pasid_enabled) {
		ret = -EINVAL;
		goto out;
	}

	ret = amd_iommu_gcr3_init(dev_data, dev->iommu->max_pasids);

out:
	spin_unlock(&dev_data->lock);
	return ret;
}

static void iommu_pasid_disable(struct iommu_dev_data *dev_data)
{
	spin_lock(&dev_data->lock);

	if (!is_gcr3_table_empty(dev_data))
		goto out;

	if (dev_data->gcr3_info.gcr3_tbl == NULL)
		goto out;

	amd_iommu_gcr3_uninit(dev_data);

out:
	spin_unlock(&dev_data->lock);
}

static int iommu_setup_pasid_pri(struct iommu_dev_data *dev_data)
{
	struct pci_dev *pdev;
	int ret;

	if (is_pasid_enabled(dev_data))
		return 0;

	ret = iommu_pasid_enable(dev_data);
	if (ret)
		return ret;

	pdev = dev_is_pci(dev_data->dev) ? to_pci_dev(dev_data->dev) : NULL;
	if (!pdev || !amd_iommu_pdev_pri_supported(pdev))
		return 0;

	if (!dev_data->pri_enabled)
		return -EINVAL;

	ret = amd_iommu_iopf_enable_device(dev_data->dev);

	return ret;
}

static void remove_dev_pasid(struct pdom_pasid_data *pasid_data)
{
	/* Update GCR3 table and flush IOTLB */
	amd_iommu_clear_gcr3(pasid_data->dev_data, pasid_data->pasid);

	list_del(&pasid_data->pdom_link);
	kfree(pasid_data);
}

static void remove_pdom_dev_pasid(struct protection_domain *pdom,
				  struct device *dev, ioasid_t pasid)
{
	struct pdom_pasid_data *pasid_data;
	struct iommu_dev_data *dev_data = dev_iommu_priv_get(dev);

	lockdep_assert_held(&pdom->lock);

	list_for_each_entry(pasid_data, &pdom->pasid_list, pdom_link) {
		if (pasid_data->pasid == pasid &&
		    pasid_data->dev_data == dev_data) {
			remove_dev_pasid(pasid_data);
			break;
		}
	}
}

static void sva_arch_invalidate_secondary_tlbs(struct mmu_notifier *mn,
				    struct mm_struct *mm,
				    unsigned long start, unsigned long end)
{
	struct pdom_pasid_data *pasid_data;
	struct protection_domain *sva_pdom;
	struct iommu_dev_data *dev_data;
	unsigned long flags;

	sva_pdom = container_of(mn, struct protection_domain, mn);

	spin_lock_irqsave(&sva_pdom->lock, flags);

	list_for_each_entry(pasid_data, &sva_pdom->pasid_list, pdom_link) {
		dev_data = pasid_data->dev_data;

		amd_iommu_dev_flush_pasid_pages(dev_data, pasid_data->pasid,
						start, end - start);
	}

	spin_unlock_irqrestore(&sva_pdom->lock, flags);
}

static void sva_mn_release(struct mmu_notifier *mn, struct mm_struct *mm)
{
	struct pdom_pasid_data *pasid_data, *next;
	struct protection_domain *sva_pdom;
	unsigned long flags;

	sva_pdom = container_of(mn, struct protection_domain, mn);

	spin_lock_irqsave(&sva_pdom->lock, flags);

	/* Assume pasid_list contains same PASID with different devices */
	list_for_each_entry_safe(pasid_data, next,
				 &sva_pdom->pasid_list, pdom_link) {
		remove_dev_pasid(pasid_data);
	}

	spin_unlock_irqrestore(&sva_pdom->lock, flags);
}

static const struct mmu_notifier_ops sva_mn = {
	.arch_invalidate_secondary_tlbs = sva_arch_invalidate_secondary_tlbs,
	.release = sva_mn_release,
};

int iommu_sva_set_dev_pasid(struct iommu_domain *domain,
			    struct device *dev, ioasid_t pasid)
{
	struct pdom_pasid_data *pasid_data;
	struct protection_domain *sva_pdom = to_pdomain(domain);
	struct iommu_dev_data *dev_data = dev_iommu_priv_get(dev);
	unsigned long flags;
	int ret = -EINVAL;

	/* PASID zero is used for requests from the I/O device without PASID */
	if (pasid == 0 || pasid >= dev->iommu->max_pasids)
		return ret;

	/* Make sure PASID/PRI is enabled */
	ret = iommu_setup_pasid_pri(dev_data);
	if (ret)
		return ret;

	/* Add PASID to protection domain pasid list */
	pasid_data = kzalloc(sizeof(*pasid_data), GFP_KERNEL);
	if (pasid_data == NULL)
		return ret;

	pasid_data->pasid = pasid;
	pasid_data->dev_data = dev_data;

	/* Setup GCR3 table */
	ret = amd_iommu_set_gcr3(dev_data, pasid,
				 iommu_virt_to_phys(domain->mm->pgd));
	if (ret) {
		kfree(pasid_data);
		return ret;
	}

	spin_lock_irqsave(&sva_pdom->lock, flags);
	list_add(&pasid_data->pdom_link, &sva_pdom->pasid_list);
	spin_unlock_irqrestore(&sva_pdom->lock, flags);

	return ret;
}

void amd_iommu_remove_dev_pasid(struct device *dev, ioasid_t pasid)
{
	struct protection_domain *sva_pdom;
	struct iommu_domain *domain;
	struct iommu_dev_data *dev_data = dev_iommu_priv_get(dev);
	unsigned long flags;

	if (pasid == 0 || pasid >= dev->iommu->max_pasids)
		return;

	/* Get protection domain */
	domain = iommu_get_domain_for_dev_pasid(dev, pasid, IOMMU_DOMAIN_SVA);
	if (!domain)
		return;
	sva_pdom = to_pdomain(domain);

	/* Ensure that all queued faults have been processed */
	iopf_queue_flush_dev(dev);

	spin_lock_irqsave(&sva_pdom->lock, flags);

	/* Remove PASID */
	remove_pdom_dev_pasid(sva_pdom, dev, pasid);

	/* Remove GCR3 table */
	if (is_gcr3_table_empty(dev_data))
		iommu_pasid_disable(dev_data);

	spin_unlock_irqrestore(&sva_pdom->lock, flags);
}

static void iommu_sva_domain_free(struct iommu_domain *domain)
{
	struct protection_domain *sva_pdom = to_pdomain(domain);

	if (sva_pdom->mn.ops)
		mmu_notifier_unregister(&sva_pdom->mn, domain->mm);

	amd_iommu_domain_free(domain);
}

static const struct iommu_domain_ops amd_sva_domain_ops = {
	.set_dev_pasid = iommu_sva_set_dev_pasid,
	.free	       = iommu_sva_domain_free
};

struct iommu_domain *amd_iommu_domain_alloc_sva(struct device *dev,
						struct mm_struct *mm)
{
	struct protection_domain *pdom;
	int ret;

	pdom = protection_domain_alloc(IOMMU_DOMAIN_SVA);
	if (!pdom)
		return ERR_PTR(-ENOMEM);

	pdom->domain.ops = &amd_sva_domain_ops;
	pdom->mn.ops = &sva_mn;

	ret = mmu_notifier_register(&pdom->mn, mm);
	if (ret) {
		protection_domain_free(pdom);
		return ERR_PTR(ret);
	}

	return &pdom->domain;
}
