// SPDX-License-Identifier: GPL-2.0
/*
 * Author: Huacai Chen <chenhuacai@loongson.cn>
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */
#include <linux/bitops.h>
#include <linux/bug.h>
#include <linux/compiler.h>
#include <linux/context_tracking.h>
#include <linux/entry-common.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kexec.h>
#include <linux/module.h>
#include <linux/extable.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/sched/debug.h>
#include <linux/smp.h>
#include <linux/spinlock.h>
#include <linux/kallsyms.h>
#include <linux/memblock.h>
#include <linux/interrupt.h>
#include <linux/ptrace.h>
#include <linux/kgdb.h>
#include <linux/kdebug.h>
#include <linux/kprobes.h>
#include <linux/notifier.h>
#include <linux/irq.h>
#include <linux/perf_event.h>

#include <asm/addrspace.h>
#include <asm/bootinfo.h>
#include <asm/branch.h>
#include <asm/break.h>
#include <asm/cpu.h>
#include <asm/fpu.h>
#include <asm/loongarch.h>
#include <asm/mmu_context.h>
#include <asm/pgtable.h>
#include <asm/ptrace.h>
#include <asm/sections.h>
#include <asm/siginfo.h>
#include <asm/stacktrace.h>
#include <asm/tlb.h>
#include <asm/types.h>
#include <asm/unwind.h>

#include "access-helper.h"

extern asmlinkage void handle_ade(void);
extern asmlinkage void handle_ale(void);
extern asmlinkage void handle_sys(void);
extern asmlinkage void handle_bp(void);
extern asmlinkage void handle_ri(void);
extern asmlinkage void handle_fpu(void);
extern asmlinkage void handle_fpe(void);
extern asmlinkage void handle_lbt(void);
extern asmlinkage void handle_lsx(void);
extern asmlinkage void handle_lasx(void);
extern asmlinkage void handle_reserved(void);
extern asmlinkage void handle_watch(void);
extern asmlinkage void handle_vint(void);

struct handler_reloc_entry {
	unsigned long offset;
	unsigned long sym;
};

struct handler_reloc {
	unsigned long cnt;
	struct handler_reloc_entry entries[];
};

extern struct handler_reloc rel_handle_tlb_load;
extern struct handler_reloc rel_handle_tlb_store;
extern struct handler_reloc rel_handle_tlb_modify;
extern struct handler_reloc rel_handle_tlb_protect;
extern struct handler_reloc rel_handle_ade;
extern struct handler_reloc rel_handle_ale;
extern struct handler_reloc rel_handle_sys;
extern struct handler_reloc rel_handle_bp;
extern struct handler_reloc rel_handle_ri;
extern struct handler_reloc rel_handle_fpu;
extern struct handler_reloc rel_handle_lsx;
extern struct handler_reloc rel_handle_lasx;
extern struct handler_reloc rel_handle_fpe;
extern struct handler_reloc rel_handle_lbt;
extern struct handler_reloc rel_handle_watch;
extern struct handler_reloc rel_handle_reserved;
extern struct handler_reloc rel_handle_vint;

struct handler_reloc *eentry_reloc[128] = {
	[0] = NULL, /* merr handler */
	[EXCCODE_TLBL] = &rel_handle_tlb_load,
	[EXCCODE_TLBS] = &rel_handle_tlb_store,
	[EXCCODE_TLBI] = &rel_handle_tlb_load,
	[EXCCODE_TLBM] = &rel_handle_tlb_modify,
	[EXCCODE_TLBNR] = &rel_handle_tlb_protect,
	[EXCCODE_TLBNX] = &rel_handle_tlb_protect,
	[EXCCODE_TLBPE] = &rel_handle_tlb_protect,
	[EXCCODE_ADE] = &rel_handle_ade,
	[EXCCODE_ALE] = &rel_handle_ale,
	[EXCCODE_SYS] = &rel_handle_sys,
	[EXCCODE_BP] = &rel_handle_bp,
	[EXCCODE_INE] = &rel_handle_ri,
	[EXCCODE_IPE] = &rel_handle_ri,
	[EXCCODE_FPDIS] = &rel_handle_fpu,
	[EXCCODE_LSXDIS] = &rel_handle_lsx,
	[EXCCODE_LASXDIS] = &rel_handle_lasx,
	[EXCCODE_FPE] = &rel_handle_fpe,
	[EXCCODE_BTDIS] = &rel_handle_lbt,
	[EXCCODE_WATCH] = &rel_handle_watch,
	[(EXCCODE_WATCH + 1) ... (EXCCODE_INT_START - 1)] = &rel_handle_reserved,
	[EXCCODE_INT_START ... (EXCCODE_INT_END - 1)] = &rel_handle_vint,
};

void reloc_handler(unsigned long handler, struct handler_reloc *rel)
{
	if (!rel)
		return;

	for (unsigned long i = 0; i < rel->cnt; i++) {
		unsigned long pc = handler + rel->entries[i].offset;
		union loongarch_instruction *insn =
			(union loongarch_instruction *)pc;
		u32 imm[4];
		unsigned long v = rel->entries[i].sym;

		/* GNU ld > 2.40 uses pcalau12i for la.pcrel, but GNU ld <= 2.39
		   uses pcaddu12i.  */
		if (insn->reg1i20_format.opcode == pcalau12i_op) {
			/* Use s32 deliberately for sign extension. */
			s32 offset_hi20 = ((v + 0x800) & ~0xfff) -
					  (pc & ~0xfff);
			unsigned long anchor = (pc & ~0xfff) + offset_hi20;
			unsigned long offset_rem = v - anchor;

			imm[0] = (offset_hi20 >> 12) & 0xfffff;
			imm[1] = v & 0xfff;
			imm[2] = (offset_rem >> 32) & 0xfffff;
			imm[3] = offset_rem >> 52;
		} else if (insn->reg1i20_format.opcode == pcaddu12i_op) {
			/* Use s32 deliberately for sign extension. */
			s32 offset_lo = v - pc;
			unsigned long offset_hi = v - pc - offset_lo;

			imm[0] = (offset_lo >> 12) & 0xfffff;
			imm[1] = offset_lo & 0xfff;
			imm[2] = (offset_hi >> 32) & 0xfffff;
			imm[3] = offset_hi >> 52;
		} else
		    panic("Cannot fixup la.pcrel for exception handler at %lu: "
			  "unexpected instruction %d!", pc, insn->word);

		insn[0].reg1i20_format.immediate = imm[0];
		insn[1].reg2i12_format.immediate = imm[1];
		insn[2].reg1i20_format.immediate = imm[2];
		insn[3].reg2i12_format.immediate = imm[3];
	}
}

/* Install CPU exception handler */
static void do_set_handler(unsigned long exccode, void *addr,
			   struct handler_reloc *rel)
{
	unsigned long dest_addr = eentry + exccode * VECSIZE;

	memcpy((void *)dest_addr, addr, VECSIZE);
	reloc_handler(dest_addr, rel);
	local_flush_icache_range(dest_addr, dest_addr + VECSIZE);
}

/* Install CPU exception handler, with the reloc table from eentry_reloc */
void set_handler(unsigned long exccode, void *addr)
{
	do_set_handler(exccode, addr, eentry_reloc[exccode]);
}

static void set_handler_reserved(unsigned long exccode)
{
	do_set_handler(exccode, handle_reserved, &rel_handle_reserved);
}

static void show_backtrace(struct task_struct *task, const struct pt_regs *regs,
			   const char *loglvl, bool user)
{
	unsigned long addr;
	struct unwind_state state;
	struct pt_regs *pregs = (struct pt_regs *)regs;

	if (!task)
		task = current;

	printk("%sCall Trace:", loglvl);
	for (unwind_start(&state, task, pregs);
	      !unwind_done(&state); unwind_next_frame(&state)) {
		addr = unwind_get_return_address(&state);
		print_ip_sym(loglvl, addr);
	}
	printk("%s\n", loglvl);
}

static void show_stacktrace(struct task_struct *task,
	const struct pt_regs *regs, const char *loglvl, bool user)
{
	int i;
	const int field = 2 * sizeof(unsigned long);
	unsigned long stackdata;
	unsigned long *sp = (unsigned long *)regs->regs[3];

	printk("%sStack :", loglvl);
	i = 0;
	while ((unsigned long) sp & (PAGE_SIZE - 1)) {
		if (i && ((i % (64 / field)) == 0)) {
			pr_cont("\n");
			printk("%s       ", loglvl);
		}
		if (i > 39) {
			pr_cont(" ...");
			break;
		}

		if (__get_addr(&stackdata, sp++, user)) {
			pr_cont(" (Bad stack address)");
			break;
		}

		pr_cont(" %0*lx", field, stackdata);
		i++;
	}
	pr_cont("\n");
	show_backtrace(task, regs, loglvl, user);
}

void show_stack(struct task_struct *task, unsigned long *sp, const char *loglvl)
{
	struct pt_regs regs;

	regs.csr_crmd = 0;
	if (sp) {
		regs.csr_era = 0;
		regs.regs[1] = 0;
		regs.regs[3] = (unsigned long)sp;
	} else {
		if (!task || task == current)
			prepare_frametrace(&regs);
		else {
			regs.csr_era = task->thread.reg01;
			regs.regs[1] = 0;
			regs.regs[3] = task->thread.reg03;
			regs.regs[22] = task->thread.reg22;
		}
	}

	show_stacktrace(task, &regs, loglvl, false);
}

static void show_code(unsigned int *pc, bool user)
{
	long i;
	unsigned int insn;

	printk("Code:");

	for(i = -3 ; i < 6 ; i++) {
		if (__get_inst(&insn, pc + i, user)) {
			pr_cont(" (Bad address in era)\n");
			break;
		}
		pr_cont("%c%08x%c", (i?' ':'<'), insn, (i?' ':'>'));
	}
	pr_cont("\n");
}

static void __show_regs(const struct pt_regs *regs)
{
	const int field = 2 * sizeof(unsigned long);
	unsigned int excsubcode;
	unsigned int exccode;
	int i;

	show_regs_print_info(KERN_DEFAULT);

	/*
	 * Saved main processor registers
	 */
	for (i = 0; i < 32; ) {
		if ((i % 4) == 0)
			printk("$%2d   :", i);
		pr_cont(" %0*lx", field, regs->regs[i]);

		i++;
		if ((i % 4) == 0)
			pr_cont("\n");
	}

	/*
	 * Saved csr registers
	 */
	printk("era   : %0*lx %pS\n", field, regs->csr_era,
	       (void *) regs->csr_era);
	printk("ra    : %0*lx %pS\n", field, regs->regs[1],
	       (void *) regs->regs[1]);

	printk("CSR crmd: %08lx	", regs->csr_crmd);
	printk("CSR prmd: %08lx	", regs->csr_prmd);
	printk("CSR euen: %08lx	", regs->csr_euen);
	printk("CSR ecfg: %08lx	", regs->csr_ecfg);
	printk("CSR estat: %08lx	", regs->csr_estat);

	pr_cont("\n");

	exccode = ((regs->csr_estat) & CSR_ESTAT_EXC) >> CSR_ESTAT_EXC_SHIFT;
	excsubcode = ((regs->csr_estat) & CSR_ESTAT_ESUBCODE) >> CSR_ESTAT_ESUBCODE_SHIFT;
	printk("ExcCode : %x (SubCode %x)\n", exccode, excsubcode);

	if (exccode >= EXCCODE_TLBL && exccode <= EXCCODE_ALE)
		printk("BadVA : %0*lx\n", field, regs->csr_badvaddr);

	printk("PrId  : %08x (%s)\n", read_cpucfg(LOONGARCH_CPUCFG0),
	       cpu_family_string());
}

void show_regs(struct pt_regs *regs)
{
	__show_regs((struct pt_regs *)regs);
	dump_stack();
}

void show_registers(struct pt_regs *regs)
{
	__show_regs(regs);
	print_modules();
	printk("Process %s (pid: %d, threadinfo=%p, task=%p)\n",
	       current->comm, current->pid, current_thread_info(), current);

	show_stacktrace(current, regs, KERN_DEFAULT, user_mode(regs));
	show_code((void *)regs->csr_era, user_mode(regs));
	printk("\n");
}

static DEFINE_RAW_SPINLOCK(die_lock);

void __noreturn die(const char *str, struct pt_regs *regs)
{
	static int die_counter;
	int sig = SIGSEGV;

	oops_enter();

	if (notify_die(DIE_OOPS, str, regs, 0, current->thread.trap_nr,
		       SIGSEGV) == NOTIFY_STOP)
		sig = 0;

	console_verbose();
	raw_spin_lock_irq(&die_lock);
	bust_spinlocks(1);

	printk("%s[#%d]:\n", str, ++die_counter);
	show_registers(regs);
	add_taint(TAINT_DIE, LOCKDEP_NOW_UNRELIABLE);
	raw_spin_unlock_irq(&die_lock);

	oops_exit();

	if (regs && kexec_should_crash(current))
		crash_kexec(regs);

	if (in_interrupt())
		panic("Fatal exception in interrupt");

	if (panic_on_oops)
		panic("Fatal exception");

	make_task_dead(sig);
}

static inline void setup_vint_size(unsigned int size)
{
	unsigned int vs;

	vs = ilog2(size/4);

	if (vs == 0 || vs > 7)
		panic("vint_size %d Not support yet", vs);

	csr_xchg32(vs<<CSR_ECFG_VS_SHIFT, CSR_ECFG_VS, LOONGARCH_CSR_ECFG);
}

/*
 * Send SIGFPE according to FCSR Cause bits, which must have already
 * been masked against Enable bits.  This is impotant as Inexact can
 * happen together with Overflow or Underflow, and `ptrace' can set
 * any bits.
 */
void force_fcsr_sig(unsigned long fcsr, void __user *fault_addr,
		     struct task_struct *tsk)
{
	int si_code = FPE_FLTUNK;

	if (fcsr & FPU_CSR_INV_X)
		si_code = FPE_FLTINV;
	else if (fcsr & FPU_CSR_DIV_X)
		si_code = FPE_FLTDIV;
	else if (fcsr & FPU_CSR_OVF_X)
		si_code = FPE_FLTOVF;
	else if (fcsr & FPU_CSR_UDF_X)
		si_code = FPE_FLTUND;
	else if (fcsr & FPU_CSR_INE_X)
		si_code = FPE_FLTRES;

	force_sig_fault(SIGFPE, si_code, fault_addr);
}

int process_fpemu_return(int sig, void __user *fault_addr, unsigned long fcsr)
{
	int si_code;

	switch (sig) {
	case 0:
		return 0;

	case SIGFPE:
		force_fcsr_sig(fcsr, fault_addr, current);
		return 1;

	case SIGBUS:
		force_sig_fault(SIGBUS, BUS_ADRERR, fault_addr);
		return 1;

	case SIGSEGV:
		mmap_read_lock(current->mm);
		if (vma_lookup(current->mm, (unsigned long)fault_addr))
			si_code = SEGV_ACCERR;
		else
			si_code = SEGV_MAPERR;
		mmap_read_unlock(current->mm);
		force_sig_fault(SIGSEGV, si_code, fault_addr);
		return 1;

	default:
		force_sig(sig);
		return 1;
	}
}

/*
 * Delayed fp exceptions when doing a lazy ctx switch
 */
asmlinkage void noinstr do_fpe(struct pt_regs *regs, unsigned long fcsr)
{
	int sig;
	void __user *fault_addr;
	irqentry_state_t state = irqentry_enter(regs);

	if (notify_die(DIE_FP, "FP exception", regs, 0, current->thread.trap_nr,
		       SIGFPE) == NOTIFY_STOP)
		goto out;

	/* Clear FCSR.Cause before enabling interrupts */
	write_fcsr(LOONGARCH_FCSR0, fcsr & ~mask_fcsr_x(fcsr));
	local_irq_enable();

	die_if_kernel("FP exception in kernel code", regs);

	sig = SIGFPE;
	fault_addr = (void __user *) regs->csr_era;

	/* Send a signal if required.  */
	process_fpemu_return(sig, fault_addr, fcsr);

out:
	local_irq_disable();
	irqentry_exit(regs, state);
}

asmlinkage void noinstr do_ade(struct pt_regs *regs)
{
	irqentry_state_t state = irqentry_enter(regs);

	die_if_kernel("Kernel ade access", regs);
	force_sig_fault(SIGBUS, BUS_ADRERR, (void __user *)regs->csr_badvaddr);

	irqentry_exit(regs, state);
}

/* sysctl hooks */
int unaligned_enabled __read_mostly = 1;	/* Enabled by default */
int no_unaligned_warning __read_mostly = 1;	/* Only 1 warning by default */

asmlinkage void noinstr do_ale(struct pt_regs *regs)
{
	unsigned int *pc;
	irqentry_state_t state = irqentry_enter(regs);

	perf_sw_event(PERF_COUNT_SW_ALIGNMENT_FAULTS, 1, regs, regs->csr_badvaddr);

	/*
	 * Did we catch a fault trying to load an instruction?
	 */
	if (regs->csr_badvaddr == regs->csr_era)
		goto sigbus;
	if (user_mode(regs) && !test_thread_flag(TIF_FIXADE))
		goto sigbus;
	if (!unaligned_enabled)
		goto sigbus;
	if (!no_unaligned_warning)
		show_registers(regs);

	pc = (unsigned int *)exception_era(regs);

	emulate_load_store_insn(regs, (void __user *)regs->csr_badvaddr, pc);

	goto out;

sigbus:
	die_if_kernel("Kernel ale access", regs);
	force_sig_fault(SIGBUS, BUS_ADRALN, (void __user *)regs->csr_badvaddr);

out:
	irqentry_exit(regs, state);
}

#ifdef CONFIG_GENERIC_BUG
int is_valid_bugaddr(unsigned long addr)
{
	return 1;
}
#endif /* CONFIG_GENERIC_BUG */

static void bug_handler(struct pt_regs *regs)
{
	switch (report_bug(regs->csr_era, regs)) {
	case BUG_TRAP_TYPE_BUG:
	case BUG_TRAP_TYPE_NONE:
		die_if_kernel("Oops - BUG", regs);
		force_sig(SIGTRAP);
		break;

	case BUG_TRAP_TYPE_WARN:
		/* Skip the BUG instruction and continue */
		regs->csr_era += LOONGARCH_INSN_SIZE;
		break;
	}
}

asmlinkage void noinstr do_bp(struct pt_regs *regs)
{
	bool user = user_mode(regs);
	unsigned int opcode, bcode;
	unsigned long era = exception_era(regs);
	irqentry_state_t state = irqentry_enter(regs);

	local_irq_enable();
	current->thread.trap_nr = read_csr_excode();
	if (__get_inst(&opcode, (u32 *)era, user))
		goto out_sigsegv;

	bcode = (opcode & 0x7fff);

	/*
	 * notify the kprobe handlers, if instruction is likely to
	 * pertain to them.
	 */
	switch (bcode) {
	case BRK_KPROBE_BP:
		if (notify_die(DIE_BREAK, "Kprobe", regs, bcode,
			       current->thread.trap_nr, SIGTRAP) == NOTIFY_STOP)
			goto out;
		else
			break;
	case BRK_KPROBE_SSTEPBP:
		if (notify_die(DIE_SSTEPBP, "Kprobe_SingleStep", regs, bcode,
			       current->thread.trap_nr, SIGTRAP) == NOTIFY_STOP)
			goto out;
		else
			break;
	case BRK_UPROBE_BP:
		if (notify_die(DIE_UPROBE, "Uprobe", regs, bcode,
			       current->thread.trap_nr, SIGTRAP) == NOTIFY_STOP)
			goto out;
		else
			break;
	case BRK_UPROBE_XOLBP:
		if (notify_die(DIE_UPROBE_XOL, "Uprobe_XOL", regs, bcode,
			       current->thread.trap_nr, SIGTRAP) == NOTIFY_STOP)
			goto out;
		else
			break;
	default:
		if (notify_die(DIE_TRAP, "Break", regs, bcode,
			       current->thread.trap_nr, SIGTRAP) == NOTIFY_STOP)
			goto out;
		else
			break;
	}

	switch (bcode) {
	case BRK_BUG:
		bug_handler(regs);
		break;
	case BRK_DIVZERO:
		die_if_kernel("Break instruction in kernel code", regs);
		force_sig_fault(SIGFPE, FPE_INTDIV, (void __user *)regs->csr_era);
		break;
	case BRK_OVERFLOW:
		die_if_kernel("Break instruction in kernel code", regs);
		force_sig_fault(SIGFPE, FPE_INTOVF, (void __user *)regs->csr_era);
		break;
	default:
		die_if_kernel("Break instruction in kernel code", regs);
		force_sig_fault(SIGTRAP, TRAP_BRKPT, (void __user *)regs->csr_era);
		break;
	}

out:
	local_irq_disable();
	irqentry_exit(regs, state);
	return;

out_sigsegv:
	force_sig(SIGSEGV);
	goto out;
}

asmlinkage void noinstr do_watch(struct pt_regs *regs)
{
	pr_warn("Hardware watch point handler not implemented!\n");
}

asmlinkage void noinstr do_ri(struct pt_regs *regs)
{
	int status = SIGILL;
	unsigned int opcode = 0;
	unsigned int __user *era = (unsigned int __user *)exception_era(regs);
	irqentry_state_t state = irqentry_enter(regs);

	local_irq_enable();
	current->thread.trap_nr = read_csr_excode();

	if (notify_die(DIE_RI, "RI Fault", regs, 0, current->thread.trap_nr,
		       SIGILL) == NOTIFY_STOP)
		goto out;

	die_if_kernel("Reserved instruction in kernel code", regs);

	if (unlikely(get_user(opcode, era) < 0)) {
		status = SIGSEGV;
		current->thread.error_code = 1;
	}

	force_sig(status);

out:
	local_irq_disable();
	irqentry_exit(regs, state);
}

static void init_restore_fp(void)
{
	if (!used_math()) {
		/* First time FP context user. */
		init_fpu();
	} else {
		/* This task has formerly used the FP context */
		if (!is_fpu_owner())
			own_fpu_inatomic(1);
	}

	BUG_ON(!is_fp_enabled());
}

asmlinkage void noinstr do_fpu(struct pt_regs *regs)
{
	irqentry_state_t state = irqentry_enter(regs);

	local_irq_enable();
	die_if_kernel("do_fpu invoked from kernel context!", regs);

	preempt_disable();
	init_restore_fp();
	preempt_enable();

	local_irq_disable();
	irqentry_exit(regs, state);
}

asmlinkage void noinstr do_lsx(struct pt_regs *regs)
{
	irqentry_state_t state = irqentry_enter(regs);

	local_irq_enable();
	force_sig(SIGILL);
	local_irq_disable();

	irqentry_exit(regs, state);
}

asmlinkage void noinstr do_lasx(struct pt_regs *regs)
{
	irqentry_state_t state = irqentry_enter(regs);

	local_irq_enable();
	force_sig(SIGILL);
	local_irq_disable();

	irqentry_exit(regs, state);
}

asmlinkage void noinstr do_lbt(struct pt_regs *regs)
{
	irqentry_state_t state = irqentry_enter(regs);

	local_irq_enable();
	force_sig(SIGILL);
	local_irq_disable();

	irqentry_exit(regs, state);
}

asmlinkage void noinstr do_reserved(struct pt_regs *regs)
{
	irqentry_state_t state = irqentry_enter(regs);

	local_irq_enable();
	/*
	 * Game over - no way to handle this if it ever occurs.	Most probably
	 * caused by a fatal error after another hardware/software error.
	 */
	pr_err("Caught reserved exception %u on pid:%d [%s] - should not happen\n",
		read_csr_excode(), current->pid, current->comm);
	die_if_kernel("do_reserved exception", regs);
	force_sig(SIGUNUSED);

	local_irq_disable();

	irqentry_exit(regs, state);
}

asmlinkage void cache_parity_error(void)
{
	/* For the moment, report the problem and hang. */
	pr_err("Cache error exception:\n");
	pr_err("csr_merrctl == %08x\n", csr_read32(LOONGARCH_CSR_MERRCTL));
	pr_err("csr_merrera == %016llx\n", csr_read64(LOONGARCH_CSR_MERRERA));
	panic("Can't handle the cache error!");
}

asmlinkage void noinstr handle_loongarch_irq(struct pt_regs *regs)
{
	struct pt_regs *old_regs;

	irq_enter_rcu();
	old_regs = set_irq_regs(regs);
	handle_arch_irq(regs);
	set_irq_regs(old_regs);
	irq_exit_rcu();
}

asmlinkage void noinstr do_vint(struct pt_regs *regs, unsigned long sp)
{
	register int cpu;
	register unsigned long stack;
	irqentry_state_t state = irqentry_enter(regs);

	cpu = smp_processor_id();

	if (on_irq_stack(cpu, sp))
		handle_loongarch_irq(regs);
	else {
		stack = per_cpu(irq_stack, cpu) + IRQ_STACK_START;

		/* Save task's sp on IRQ stack for unwinding */
		*(unsigned long *)stack = sp;

		__asm__ __volatile__(
		"move	$s0, $sp		\n" /* Preserve sp */
		"move	$sp, %[stk]		\n" /* Switch stack */
		"move	$a0, %[regs]		\n"
		"bl	handle_loongarch_irq	\n"
		"move	$sp, $s0		\n" /* Restore sp */
		: /* No outputs */
		: [stk] "r" (stack), [regs] "r" (regs)
		: "$a0", "$a1", "$a2", "$a3", "$a4", "$a5", "$a6", "$a7", "$s0",
		  "$t0", "$t1", "$t2", "$t3", "$t4", "$t5", "$t6", "$t7", "$t8",
		  "memory");
	}

	irqentry_exit(regs, state);
}

unsigned long eentry;
unsigned long tlbrentry;

long exception_handlers[VECSIZE * 128 / sizeof(long)] __aligned(SZ_64K);

static void configure_exception_vector(void)
{
	eentry    = (unsigned long)exception_handlers;
	tlbrentry = (unsigned long)exception_handlers + 80*VECSIZE;

	csr_write64(eentry, LOONGARCH_CSR_EENTRY);
	csr_write64(eentry, LOONGARCH_CSR_MERRENTRY);
	csr_write64(tlbrentry, LOONGARCH_CSR_TLBRENTRY);
}

void per_cpu_trap_init(int cpu)
{
	unsigned int i;

	setup_vint_size(VECSIZE);

	configure_exception_vector();

	if (!cpu_data[cpu].asid_cache)
		cpu_data[cpu].asid_cache = asid_first_version(cpu);

	mmgrab(&init_mm);
	current->active_mm = &init_mm;
	BUG_ON(current->mm);
	enter_lazy_tlb(&init_mm, current);

	/* Initialise exception handlers */
	if (cpu == 0)
		for (i = 0; i < 64; i++)
			set_handler_reserved(i);

	tlb_init(cpu);
	cpu_cache_init();
}

static const char panic_null_cerr[] =
	"Trying to set NULL cache error exception handler\n";

/*
 * Install uncached CPU exception handler.
 * This is suitable only for the cache error exception which is the only
 * exception handler that is being run uncached.
 */
void set_merr_handler(unsigned long offset, void *addr, unsigned long size)
{
	unsigned long uncached_eentry = TO_UNCACHE(__pa(eentry));

	if (!addr)
		panic(panic_null_cerr);

	memcpy((void *)(uncached_eentry + offset), addr, size);
}

void __init trap_init(void)
{
	long i;

	/* Set interrupt vector handler */
	for (i = EXCCODE_INT_START; i < EXCCODE_INT_END; i++)
		set_handler(i, handle_vint);

	set_handler(EXCCODE_ADE, handle_ade);
	set_handler(EXCCODE_ALE, handle_ale);
	set_handler(EXCCODE_SYS, handle_sys);
	set_handler(EXCCODE_BP, handle_bp);
	set_handler(EXCCODE_INE, handle_ri);
	set_handler(EXCCODE_IPE, handle_ri);
	set_handler(EXCCODE_FPDIS, handle_fpu);
	set_handler(EXCCODE_LSXDIS, handle_lsx);
	set_handler(EXCCODE_LASXDIS, handle_lasx);
	set_handler(EXCCODE_FPE, handle_fpe);
	set_handler(EXCCODE_BTDIS, handle_lbt);
	set_handler(EXCCODE_WATCH, handle_watch);

	cache_error_setup();

	local_flush_icache_range(eentry, eentry + 0x400);
}
