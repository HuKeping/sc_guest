/*
 * sc_guset.h
 *
 * Secure container with EPT isolation
 *
 * Copyright (C) 2017 Huawei Technologies Co., Ltd.
 * Copyright (C) 2017 Intel Corporation
 *
 * Authors:
 *   Chunyan Liu <liuchunyan9@huawei.com>
 *   Jason CJ Chen <jason.cj.chen@intel.com>
 *   Liu, Jingqi <jingqi.liu@intel.com>
 *   Ye, Weize <weize.ye@intel.com>
 *   Gu, jixing <jixing.gu@intel.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#ifndef __LINUX_SC_GUSET_H
#define __LINUX_SC_GUEST_H

#ifdef CONFIG_SC_GUEST
#include <asm/sc.h>

/* for free pages in SC EPT table */
int vmm_free_pages(struct page *page, int numpages);
/* check if current process in in secure container */
bool vmm_is_in_sc(void);
/* for create EPT view */
int vmm_create_ept_view(unsigned long clusterid);
/* for set shared file page cache */
int vmm_set_shared_page(struct page *page);
/* hereafter for data exchange between SC userspace<->kernelspace */
phys_addr_t uvirt_to_phys(const volatile void *addr, int write);
int vmm_data_move(const void *src, const void *dst, uint64_t size);
int vmm_data_xchg(int *oldval, u32 __user *uaddr, int *oparg);
int vmm_data_add(int *oldval, u32 __user *uaddr, int oparg);
int vmm_data_or(int *oldval, u32 __user *uaddr, int oparg);
int vmm_data_and(int *oldval, u32 __user *uaddr, int oparg);
int vmm_data_xor(int *oldval, u32 __user *uaddr, int oparg);
int vmm_data_cmpxchg(void *ptr, uint64_t old, uint64_t new, int size);
unsigned long vmm_data_copy(const void *to, const void *from, unsigned long len);
unsigned long vmm_clear_user(void __user *addr, unsigned long len);
#endif

#endif
