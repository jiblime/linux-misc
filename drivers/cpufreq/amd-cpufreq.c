// SPDX-License-Identifier: GPL-2.0-only
/*
 * AMD CPUFREQ driver for Family 17h or greater AMD processors.
 *
 * Copyright (C) 2019 Advanced Micro Devices, Inc.
 *
 * Author: Janakarajan Natarajan <janakarajan.natarajan@amd.com>
 *
 * Additional ITMT code:
 * (C) Copyright 2012 Intel Corporation
 * Author: Dirk Brandewie <dirk.j.brandewie@intel.com>
 *
 */
#define pr_fmt(fmt)	"AMD Cpufreq: " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/cpu.h>
#include <linux/vmalloc.h>
#include <linux/cpufreq.h>
#include <linux/acpi.h>
#include <linux/delay.h>

#include <asm/unaligned.h>

#include <acpi/cppc_acpi.h>

struct amd_desc {
	int cpu_id;
	struct cppc_ctrls ctrls;
	struct kobject kobj;
};

struct amd_desc **all_cpu_data;

static unsigned int cppc_enable;
static unsigned int itmt_enable;
module_param(cppc_enable, uint, 0644);
module_param(itmt_enable, uint, 0644);
MODULE_PARM_DESC(cppc_enable,
		 "1 - enable AMD CpuFreq, create CPPC sysfs entries.");
MODULE_PARM_DESC(itmt_enable,
		 "2 - enable preferred cores based on CPPC information");

#define to_amd_desc(a) container_of(a, struct amd_desc, kobj)

#define show_func(access_fn, struct_name, member_name)			\
	static ssize_t show_##member_name(struct kobject *kobj,		\
					  struct kobj_attribute *attr,	\
					  char *buf)			\
	{								\
		struct amd_desc *desc = to_amd_desc(kobj);		\
		struct struct_name st_name = {0};			\
		int ret;						\
									\
		ret = access_fn(desc->cpu_id, &st_name);		\
		if (ret)						\
			return ret;					\
									\
		return scnprintf(buf, PAGE_SIZE, "%llu\n",		\
				 (u64)st_name.member_name);		\
	}								\

#define store_func(struct_name, member_name, reg_idx)			\
	static ssize_t store_##member_name(struct kobject *kobj,	\
					   struct kobj_attribute *attr,	\
					   const char *buf, size_t count)\
	{								\
		struct amd_desc *desc = to_amd_desc(kobj);		\
		struct struct_name st_name = {0};			\
		u32 val;						\
		int ret;						\
									\
		ret = kstrtou32(buf, 0, &val);				\
		if (ret)						\
			return ret;					\
									\
		st_name.member_name = val;				\
									\
		ret = cppc_set_reg(desc->cpu_id, &st_name, reg_idx);	\
		if (ret)						\
			return ret;					\
									\
		return count;						\
	}								\

#define define_one_rw(struct_name, access_fn, member_name, reg_idx)	\
	show_func(access_fn, struct_name, member_name)			\
	store_func(struct_name, member_name, reg_idx)			\
	define_one_global_rw(member_name)

define_one_rw(cppc_ctrls, cppc_get_ctrls, enable, ENABLE);
define_one_rw(cppc_ctrls, cppc_get_ctrls, max_perf, MAX_PERF);
define_one_rw(cppc_ctrls, cppc_get_ctrls, min_perf, MIN_PERF);
define_one_rw(cppc_ctrls, cppc_get_ctrls, desired_perf, DESIRED_PERF);
define_one_rw(cppc_ctrls, cppc_get_ctrls, auto_sel_enable, AUTO_SEL_ENABLE);

static struct attribute *amd_cpufreq_attributes[] = {
	&enable.attr,
	&max_perf.attr,
	&min_perf.attr,
	&desired_perf.attr,
	&auto_sel_enable.attr,
	NULL
};

static const struct attribute_group amd_cpufreq_attr_group = {
	.attrs = amd_cpufreq_attributes,
};

static struct kobj_type amd_cpufreq_type = {
	.sysfs_ops = &kobj_sysfs_ops,
	.default_attrs = amd_cpufreq_attributes,
};

#ifdef CONFIG_ACPI_CPPC_LIB

/* The work item is needed to avoid CPU hotplug locking issues */
static void amd_cpufreq_sched_itmt_work_fn(struct work_struct *work)
{
	sched_set_itmt_support();
}

static DECLARE_WORK(sched_itmt_work, amd_cpufreq_sched_itmt_work_fn);

static void amd_cpufreq_set_itmt_prio(int cpu)
{
	struct cppc_perf_caps cppc_perf;
	static u32 max_highest_perf = 0, min_highest_perf = U32_MAX;
	int ret;

	ret = cppc_get_perf_caps(cpu, &cppc_perf);
	if (ret)
		return;

	/*
	 * The priorities can be set regardless of whether or not
	 * sched_set_itmt_support(true) has been called and it is valid to
	 * update them at any time after it has been called.
	 */
	pr_info("CPU %d perf %d\n", cpu, (int)cppc_perf.highest_perf);
	sched_set_itmt_core_prio(cppc_perf.highest_perf, cpu);

	if (max_highest_perf <= min_highest_perf) {
		if (cppc_perf.highest_perf > max_highest_perf)
			max_highest_perf = cppc_perf.highest_perf;

		if (cppc_perf.highest_perf < min_highest_perf)
			min_highest_perf = cppc_perf.highest_perf;

		if (max_highest_perf > min_highest_perf) {
			/*
			 * This code can be run during CPU online under the
			 * CPU hotplug locks, so sched_set_itmt_support()
			 * cannot be called from here.  Queue up a work item
			 * to invoke it.
			 */
			pr_info("CPU %d ITMT enable\n", cpu);
			schedule_work(&sched_itmt_work);
		}
	}
}

#else /* CONFIG_ACPI_CPPC_LIB */
static void amd_cpufreq_set_itmt_prio(int cpu)
{
}
#endif /* CONFIG_ACPI_CPPC_LIB */

static void amd_cpufreq_init_acpi_perf_limits(struct cpufreq_policy *policy)
{
	if (!itmt_enable)
		return;

	amd_cpufreq_set_itmt_prio(policy->cpu);
}

static int amd_cpufreq_cpu_init(struct cpufreq_policy *policy)
{
	amd_cpufreq_init_acpi_perf_limits(policy);
	return 0;
}

static int amd_cpufreq_cpu_exit(struct cpufreq_policy *policy)
{
	return 0;
}

static int amd_cpufreq_cpu_verify(struct cpufreq_policy_data *policy_data)
{
	return 0;
}

static int amd_cpufreq_cpu_target_index(struct cpufreq_policy *policy,
					unsigned int index)
{
	return 0;
}

static struct cpufreq_driver amd_cpufreq_driver = {
	.name = "amd_cpufreq",
	.init = amd_cpufreq_cpu_init,
	.exit = amd_cpufreq_cpu_exit,
	.verify = amd_cpufreq_cpu_verify,
	.target_index = amd_cpufreq_cpu_target_index,
};

static void amd_cpufreq_sysfs_delete_params(void)
{
	int i;

	for_each_possible_cpu(i) {
		if (all_cpu_data[i]) {
			kobject_del(&all_cpu_data[i]->kobj);
			kfree(all_cpu_data[i]);
		}
	}

	kfree(all_cpu_data);
}

static int __init amd_cpufreq_sysfs_expose_params(void)
{
	struct device *cpu_dev;
	int i, ret;

	all_cpu_data = kcalloc(num_possible_cpus(), sizeof(void *),
			       GFP_KERNEL);

	if (!all_cpu_data)
		return -ENOMEM;

	for_each_possible_cpu(i) {
		all_cpu_data[i] = kzalloc(sizeof(struct amd_desc), GFP_KERNEL);
		if (!all_cpu_data[i]) {
			ret = -ENOMEM;
			goto free;
		}

		all_cpu_data[i]->cpu_id = i;
		cpu_dev = get_cpu_device(i);
		ret = kobject_init_and_add(&all_cpu_data[i]->kobj, &amd_cpufreq_type,
					   &cpu_dev->kobj, "amd_cpufreq");
		if (ret)
			goto free;
	}

	return 0;
free:
	amd_cpufreq_sysfs_delete_params();
	return ret;
}

static int __init amd_cpufreq_init(void)
{
	int ret = 0;

	/*
	 * Use only if:
	 * - AMD,
	 * - Family 17h (or) newer and,
	 * - Explicitly enabled
	 */
	if (boot_cpu_data.x86_vendor != X86_VENDOR_AMD ||
	    boot_cpu_data.x86 < 0x17 || !cppc_enable)
		return -ENODEV;

	ret = cpufreq_register_driver(&amd_cpufreq_driver);
	if (ret) {
		pr_info("Failed to register driver\n");
		goto out;
	}

	ret = amd_cpufreq_sysfs_expose_params();
	if (ret) {
		pr_info("Could not create sysfs entries\n");
		cpufreq_unregister_driver(&amd_cpufreq_driver);
		goto out;
	}

	pr_info("Using amd-cpufreq driver\n");
	return ret;

out:
	return ret;
}

static void __exit amd_cpufreq_exit(void)
{
	amd_cpufreq_sysfs_delete_params();
	cpufreq_unregister_driver(&amd_cpufreq_driver);
}

static const struct acpi_device_id amd_acpi_ids[] __used = {
	{ACPI_PROCESSOR_DEVICE_HID, },
	{}
};

device_initcall(amd_cpufreq_init);
module_exit(amd_cpufreq_exit);
MODULE_DEVICE_TABLE(acpi, amd_acpi_ids);

MODULE_AUTHOR("Janakarajan Natarajan");
MODULE_DESCRIPTION("AMD CPUFreq driver based on ACPI CPPC v6.1 spec");
MODULE_LICENSE("GPL");
