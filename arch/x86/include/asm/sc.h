/*
 * sc.h
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

#ifndef __LINUX_SC_H
#define __LINUX_SC_H

#include <linux/types.h>

/* SC hypercall IDs */
#define HC_INIT_SC		1
#define HC_CREATE_VIEW		2
#define HC_SET_SHARED_PAGE	3
#define HC_SET_FREED_PAGE	4
#define HC_DATA_EXCHANGE	5

enum data_exchg_type {
	SC_DATA_EXCHG_MOV  = 1,
	SC_DATA_EXCHG_SET,
	SC_DATA_EXCHG_XCHG,
	SC_DATA_EXCHG_ADD,
	SC_DATA_EXCHG_OR,
	SC_DATA_EXCHG_AND,
	SC_DATA_EXCHG_XOR,
	SC_DATA_EXCHG_CMPXCHG,
	SC_DATA_EXCHG_MAX,
};

struct sc_cfg {
	/*
	 * VM HW config:
	 * - is 32bit?
	 * - total phys memory page numbers
	 */
	uint8_t is_x32;
	uint64_t total_npages;
	/*
	 * VM OS config:
	 * - kernel text range (gpa)
	 * - vdso/vvar/zero page range (gpa)
	 * - free page status bitmap (gpa)
	 * - user virtual addr max (gva)
	 * - kernel virtual addr range (gva)
	 * - module virtual addr range (gva)
	 * - current task config
	 * - physical to virtual mapping config (kernel space)
	 */
	uint64_t kernel_text_start, kernel_text_end;
	uint64_t vdso_start, vdso_end;
	uint64_t vvar_start, vvar_end;
	uint64_t zero_start, zero_end;
	uint64_t free_page_bitmap_start, free_page_bitmap_end;
	uint64_t user_vrange_max;
	uint64_t kernel_vrange_start, kernel_vrange_end;
	uint64_t module_vrange_start, module_vrange_end;
	struct task_cfg {
		int smp_cpu;
		uint64_t *percpu_task;
		int task_size;
		int task2pid_off;
		int task2viewid_off;
		uint32_t task2comm_off;
		uint32_t task2thread_off;
	} task_cfg;
	struct pv_cfg {
		uint64_t phys_base;
		uint64_t start_kernel_map;
		uint64_t page_offset;
	} pv_cfg;
	/*
	 * Misc config:
	 * - erase freed page
	 */
	bool erase_freed_page;
};

struct view_cfg {
	uint64_t first_pfn;
	uint8_t enable_cluster;
	uint32_t cluster_id;
};

struct data_ex_cfg {
	enum data_exchg_type op;
	union {
		struct {
			uint64_t mov_src;
			uint64_t mov_dst;
			uint64_t mov_size;
		};
		struct {
			uint64_t set_ptr;
			uint8_t set_val;
			uint64_t set_size;
		};
		struct {
			uint32_t ptr1;
			uint32_t ptr2;
			uint32_t oldval;
		};
		struct {
			uint64_t cmpxchg_ptr1;
			uint64_t cmpxchg_ptr2;
			uint64_t cmpxchg_new;
			uint32_t cmpxchg_size;
		};
	};
};

struct free_page_cfg {
	uint64_t start_gfn;
	uint32_t numpages;
};

#endif
