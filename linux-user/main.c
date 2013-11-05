/*
 *  qemu user main
 *
 *  Copyright (c) 2003-2008 Fabrice Bellard
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/resource.h>

#include "qemu.h"
#include "qemu-common.h"
#include "cache-utils.h"
/* For tb_lock */
#include "exec-all.h"
#include "qemu-timer.h"
#include "envlist.h"

#define DEBUG_LOGFILE "/tmp/qemu.log"

char *exec_path;
extern bool prof_run;

int singlestep;
unsigned long mmap_min_addr;

static const char *interp_prefix = CONFIG_QEMU_INTERP_PREFIX;
const char *qemu_uname_release = CONFIG_UNAME_RELEASE;

/* XXX: on x86 MAP_GROWSDOWN only works if ESP <= address + 32, so
   we allocate a bigger stack. Need a better solution, for example
   by remapping the process stack directly at the right place */
unsigned long guest_stack_size = 8 * 1024 * 1024UL;


void gemu_log(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

#if defined(CONFIG_USE_NPTL)
/***********************************************************/
/* Helper routines for implementing atomic operations.  */

/* To implement exclusive operations we force all cpus to syncronise.
   We don't require a full sync, only that no cpus are executing guest code.
   The alternative is to map target atomic ops onto host equivalents,
   which requires quite a lot of per host/target work.  */
static pthread_mutex_t cpu_list_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t exclusive_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t exclusive_cond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t exclusive_resume = PTHREAD_COND_INITIALIZER;
static int pending_cpus;

/* Make sure everything is in a consistent state for calling fork().  */
void fork_start(void)
{
    pthread_mutex_lock(&tb_lock);
    pthread_mutex_lock(&exclusive_lock);
    mmap_fork_start();
}

void fork_end(int child)
{
    mmap_fork_end(child);
    if (child) {
        /* Child processes created by fork() only have a single thread.
           Discard information about the parent threads.  */
        first_cpu = thread_env;
        thread_env->next_cpu = NULL;
        pending_cpus = 0;
        pthread_mutex_init(&exclusive_lock, NULL);
        pthread_mutex_init(&cpu_list_mutex, NULL);
        pthread_cond_init(&exclusive_cond, NULL);
        pthread_cond_init(&exclusive_resume, NULL);
        pthread_mutex_init(&tb_lock, NULL);
        ///gdbserver_fork(thread_env);
    } else {
        pthread_mutex_unlock(&exclusive_lock);
        pthread_mutex_unlock(&tb_lock);
    }
}

/* Wait for pending exclusive operations to complete.  The exclusive lock
   must be held.  */
static inline void exclusive_idle(void)
{
    while (pending_cpus) {
        pthread_cond_wait(&exclusive_resume, &exclusive_lock);
    }
}

/* Start an exclusive operation.
   Must only be called from outside cpu_arm_exec.   */
static inline void start_exclusive(void)
{
    CPUState *other;
    pthread_mutex_lock(&exclusive_lock);
    exclusive_idle();

    pending_cpus = 1;
    /* Make all other cpus stop executing.  */
    for (other = first_cpu; other; other = other->next_cpu) {
        if (other->running) {
            pending_cpus++;
            cpu_exit(other);
        }
    }
    if (pending_cpus > 1) {
        pthread_cond_wait(&exclusive_cond, &exclusive_lock);
    }
}

/* Finish an exclusive operation.  */
static inline void end_exclusive(void)
{
    pending_cpus = 0;
    pthread_cond_broadcast(&exclusive_resume);
    pthread_mutex_unlock(&exclusive_lock);
}

/* Wait for exclusive ops to finish, and begin cpu execution.  */
static inline void cpu_exec_start(CPUState *env)
{
    pthread_mutex_lock(&exclusive_lock);
    exclusive_idle();
    env->running = 1;
    pthread_mutex_unlock(&exclusive_lock);
}

/* Mark cpu as not executing, and release pending exclusive ops.  */
static inline void cpu_exec_end(CPUState *env)
{
    pthread_mutex_lock(&exclusive_lock);
    env->running = 0;
    if (pending_cpus > 1) {
        pending_cpus--;
        if (pending_cpus == 1) {
            pthread_cond_signal(&exclusive_cond);
        }
    }
    exclusive_idle();
    pthread_mutex_unlock(&exclusive_lock);
}

void cpu_list_lock(void)
{
    pthread_mutex_lock(&cpu_list_mutex);
}

void cpu_list_unlock(void)
{
    pthread_mutex_unlock(&cpu_list_mutex);
}
#else /* if !CONFIG_USE_NPTL */
/* These are no-ops because we are not threadsafe.  */
static inline void cpu_exec_start(CPUState *env)
{
}

static inline void cpu_exec_end(CPUState *env)
{
}

static inline void start_exclusive(void)
{
}

static inline void end_exclusive(void)
{
}

void fork_start(void)
{
}

void fork_end(int child)
{
    if (child) {
        ///gdbserver_fork(thread_env);
    }
}

void cpu_list_lock(void)
{
}

void cpu_list_unlock(void)
{
}
#endif


#ifdef TARGET_I386
/***********************************************************/
/* CPUX86 core interface */

void cpu_smm_update(CPUState *env)
{
}

uint64_t cpu_get_tsc(CPUX86State *env)
{
    return cpu_get_real_ticks();
}
static void write_dt(void *ptr, unsigned long addr, unsigned long limit,
        int flags)
{
    unsigned int e1, e2;
    uint32_t *p;
    e1 = (addr << 16) | (limit & 0xffff);
    e2 = ((addr >> 16) & 0xff) | (addr & 0xff000000) | (limit & 0x000f0000);
    e2 |= flags;
    p = ptr;
    p[0] = tswap32(e1);
    p[1] = tswap32(e2);
}

static uint64_t *idt_table;
static void set_gate(void *ptr, unsigned int type, unsigned int dpl,
        uint32_t addr, unsigned int sel)
{
    uint32_t *p, e1, e2;
    e1 = (addr & 0xffff) | (sel << 16);
    e2 = (addr & 0xffff0000) | 0x8000 | (dpl << 13) | (type << 8);
    p = ptr;
    p[0] = tswap32(e1);
    p[1] = tswap32(e2);
}

/* only dpl matters as we do only user space emulation */
static void set_idt(int n, unsigned int dpl)
{
    set_gate(idt_table + n, 0, dpl, 0, 0);
}

void cpu_loop(CPUX86State *env)
{
    int trapnr;
    abi_ulong pc;
    target_siginfo_t info;

    memset (tb_phys_hash, 0, CODE_GEN_PHYS_HASH_SIZE * sizeof (void *));
    codecache_prologue_init(env);

    for(;;) {
        trapnr = cpu_x86_exec(env);
        switch(trapnr) {
#if 00
        case 0x80:
            /* linux syscall from int $0x80 */
            env->regs[R_EAX] = do_syscall(env,
                                          env->regs[R_EAX],
                                          env->regs[R_EBX],
                                          env->regs[R_ECX],
                                          env->regs[R_EDX],
                                          env->regs[R_ESI],
                                          env->regs[R_EDI],
                                          env->regs[R_EBP]);
            break;
        case EXCP0B_NOSEG:
        case EXCP0C_STACK:
            info.si_signo = SIGBUS;
            info.si_errno = 0;
            info.si_code = TARGET_SI_KERNEL;
            info._sifields._sigfault._addr = 0;
            queue_signal(env, info.si_signo, &info);
            break;
        case EXCP0D_GPF:
            /* XXX: potential problem if ABI32 */
#ifndef TARGET_X86_64
            if (env->eflags & VM_MASK) {
                handle_vm86_fault(env);
            } else
#endif
            {
                info.si_signo = SIGSEGV;
                info.si_errno = 0;
                info.si_code = TARGET_SI_KERNEL;
                info._sifields._sigfault._addr = 0;
                queue_signal(env, info.si_signo, &info);
            }
            break;
        case EXCP0E_PAGE:
            info.si_signo = SIGSEGV;
            info.si_errno = 0;
            if (!(env->error_code & 1))
                info.si_code = TARGET_SEGV_MAPERR;
            else
                info.si_code = TARGET_SEGV_ACCERR;
            info._sifields._sigfault._addr = env->cr[2];
            queue_signal(env, info.si_signo, &info);
            break;
        case EXCP00_DIVZ:
#ifndef TARGET_X86_64
            if (env->eflags & VM_MASK) {
                handle_vm86_trap(env, trapnr);
            } else
#endif
            {
                /* division by zero */
                info.si_signo = SIGFPE;
                info.si_errno = 0;
                info.si_code = TARGET_FPE_INTDIV;
                info._sifields._sigfault._addr = env->eip;
                queue_signal(env, info.si_signo, &info);
            }
            break;
        case EXCP01_DB:
        case EXCP03_INT3:
#ifndef TARGET_X86_64
            if (env->eflags & VM_MASK) {
                handle_vm86_trap(env, trapnr);
            } else
#endif
            {
                info.si_signo = SIGTRAP;
                info.si_errno = 0;
                if (trapnr == EXCP01_DB) {
                    info.si_code = TARGET_TRAP_BRKPT;
                    info._sifields._sigfault._addr = env->eip;
                } else {
                    info.si_code = TARGET_SI_KERNEL;
                    info._sifields._sigfault._addr = 0;
                }
                queue_signal(env, info.si_signo, &info);
            }
            break;
        case EXCP04_INTO:
        case EXCP05_BOUND:
#ifndef TARGET_X86_64
            if (env->eflags & VM_MASK) {
                handle_vm86_trap(env, trapnr);
            } else
#endif
            {
                info.si_signo = SIGSEGV;
                info.si_errno = 0;
                info.si_code = TARGET_SI_KERNEL;
                info._sifields._sigfault._addr = 0;
                queue_signal(env, info.si_signo, &info);
            }
            break;
        case EXCP06_ILLOP:
            info.si_signo = SIGILL;
            info.si_errno = 0;
            info.si_code = TARGET_ILL_ILLOPN;
            info._sifields._sigfault._addr = env->eip;
            queue_signal(env, info.si_signo, &info);
            break;
        case EXCP_INTERRUPT:
            /* just indicate that signals should be handled asap */
            break;
        case EXCP_DEBUG:
#if 0 /* ningjia */
            {
                int sig;

                sig = gdb_handlesig (env, TARGET_SIGTRAP);
                if (sig)
                  {
                    info.si_signo = sig;
                    info.si_errno = 0;
                    info.si_code = TARGET_TRAP_BRKPT;
                    queue_signal(env, info.si_signo, &info);
                  }
            }
#endif
            break;
        default:
            pc = env->segs[R_CS].base + env->eip;
            fprintf(stderr, "qemu: 0x%08lx: unhandled CPU exception 0x%x - aborting\n",
                    (long)pc, trapnr);
            abort();
#endif
        }
    process_pending_signals(env);
    }
}
#endif


static void usage(void)
{
    printf("qemu-" TARGET_ARCH " version " QEMU_VERSION QEMU_PKGVERSION ", Copyright (c) 2003-2008 Fabrice Bellard\n"
           "usage: qemu-" TARGET_ARCH " [options] program [arguments...]\n"
           "Linux CPU emulator (compiled for %s emulation)\n"
           "\n"
           "Standard options:\n"
           "-h                print this help\n"
           "-g port           wait gdb connection to port\n"
           "-L path           set the elf interpreter prefix (default=%s)\n"
           "-s size           set the stack size in bytes (default=%ld)\n"
           "-cpu model        select CPU (-cpu ? for list)\n"
           "-drop-ld-preload  drop LD_PRELOAD for target process\n"
           "-E var=value      sets/modifies targets environment variable(s)\n"
           "-U var            unsets targets environment variable(s)\n"
           "-0 argv0          forces target process argv[0] to be argv0\n"
#if defined(CONFIG_USE_GUEST_BASE)
           "-B address        set guest_base address to address\n"
           "-R size           reserve size bytes for guest virtual address space\n"
#endif
           "\n"
           "Debug options:\n"
           "-d options   activate log (logfile=%s)\n"
           "-p pagesize  set the host page size to 'pagesize'\n"
           "-singlestep  always run in singlestep mode\n"
           "-strace      log system calls\n"
           "\n"
           "Environment variables:\n"
           "QEMU_STRACE       Print system calls and arguments similar to the\n"
           "                  'strace' program.  Enable by setting to any value.\n"
           "You can use -E and -U options to set/unset environment variables\n"
           "for target process.  It is possible to provide several variables\n"
           "by repeating the option.  For example:\n"
           "    -E var1=val2 -E var2=val2 -U LD_PRELOAD -U LD_DEBUG\n"
           "Note that if you provide several changes to single variable\n"
           "last change will stay in effect.\n"
           ,
           TARGET_ARCH,
           interp_prefix,
           guest_stack_size,
           DEBUG_LOGFILE);
    exit(1);
}

THREAD CPUState *thread_env;

void task_settid(TaskState *ts)
{
    if (ts->ts_tid == 0) {
#ifdef CONFIG_USE_NPTL
        ts->ts_tid = (pid_t)syscall(SYS_gettid);
#else
        /* when no threads are used, tid becomes pid */
        ts->ts_tid = getpid();
#endif
    }
}

void stop_all_tasks(void)
{
    /*
     * We trust that when using NPTL, start_exclusive()
     * handles thread stopping correctly.
     */
    start_exclusive();
}

/* Assumes contents are already zeroed.  */
void init_task_state(TaskState *ts)
{
    int i;
 
    ts->used = 1;
    ts->first_free = ts->sigqueue_table;
    for (i = 0; i < MAX_SIGQUEUE_SIZE - 1; i++) {
        ts->sigqueue_table[i].next = &ts->sigqueue_table[i + 1];
    }
    ts->sigqueue_table[i].next = NULL;
}

int main(int argc, char **argv, char **envp)
{
    const char *filename;
    const char *cpu_model;
    struct target_pt_regs regs1, *regs = &regs1;
    struct image_info info1, *info = &info1;
    struct linux_binprm bprm;
    TaskState ts1, *ts = &ts1;
    CPUState *env;
    int optind;
    const char *r;
    int gdbstub_port = 0;
    char **target_environ, **wrk;
    char **target_argv;
    int target_argc;
    envlist_t *envlist = NULL;
    const char *argv0 = NULL;
    int i;
    int ret;

    if (argc <= 1)
        usage();

    //qemu_cache_utils_init(envp);

    /* init debug */
    cpu_set_log_filename(DEBUG_LOGFILE);

    if ((envlist = envlist_create()) == NULL) {
        (void) fprintf(stderr, "Unable to allocate envlist\n");
        exit(1);
    }

    /* add current environment into the list */
    for (wrk = environ; *wrk != NULL; wrk++) {
        (void) envlist_setenv(envlist, *wrk);
    }

    /* Read the stack limit from the kernel.  If it's "unlimited",
       then we can do little else besides use the default.  */
    {
        struct rlimit lim;
        if (getrlimit(RLIMIT_STACK, &lim) == 0
            && lim.rlim_cur != RLIM_INFINITY
            && lim.rlim_cur == (target_long)lim.rlim_cur) {
            guest_stack_size = lim.rlim_cur;
        }
    }

    cpu_model = NULL;
#if 1
#if defined(cpudef_setup)
    //cpudef_setup(); /* parse cpu definitions in target config file (TBD) */
#endif
#endif

    optind = 1;
    for(;;) {
        if (optind >= argc)
            break;
        r = argv[optind];
        if (r[0] != '-')
            break;
        optind++;
        r++;
        if (!strcmp(r, "-")) {
            break;
        } else if (!strcmp(r, "d")) {
            int mask;
            const CPULogItem *item;

	    if (optind >= argc)
		break;

	    r = argv[optind++];
            mask = cpu_str_to_log_mask(r);
            if (!mask) {
                printf("Log items (comma separated):\n");
                for(item = cpu_log_items; item->mask != 0; item++) {
                    printf("%-10s %s\n", item->name, item->help);
                }
                exit(1);
            }
            cpu_set_log(mask);
        } else if (!strcmp(r, "E")) {
            r = argv[optind++];
            if (envlist_setenv(envlist, r) != 0)
                usage();
        } else if (!strcmp(r, "U")) {
            r = argv[optind++];
            if (envlist_unsetenv(envlist, r) != 0)
                usage();
        } else if (!strcmp(r, "0")) {
            r = argv[optind++];
            argv0 = r;
        } else if (!strcmp(r, "s")) {
            if (optind >= argc)
                break;
            r = argv[optind++];
            guest_stack_size = strtoul(r, (char **)&r, 0);
            if (guest_stack_size == 0)
                usage();
            if (*r == 'M')
                guest_stack_size *= 1024 * 1024;
            else if (*r == 'k' || *r == 'K')
                guest_stack_size *= 1024;
        } else if (!strcmp(r, "L")) {
            interp_prefix = argv[optind++];
        } else if (!strcmp(r, "p")) {
            if (optind >= argc)
                break;
            qemu_host_page_size = atoi(argv[optind++]);
            if (qemu_host_page_size == 0 ||
                (qemu_host_page_size & (qemu_host_page_size - 1)) != 0) {
                fprintf(stderr, "page size must be a power of two\n");
                exit(1);
            }
        } else if (!strcmp(r, "g")) {
            if (optind >= argc)
                break;
            gdbstub_port = atoi(argv[optind++]);
	} else if (!strcmp(r, "r")) {
	    qemu_uname_release = argv[optind++];
        } else if (!strcmp(r, "cpu")) {
            cpu_model = argv[optind++];
            if (cpu_model == NULL || strcmp(cpu_model, "?") == 0) {
                exit(1);
            }
        } else if (!strcmp(r, "drop-ld-preload")) {
            (void) envlist_unsetenv(envlist, "LD_PRELOAD");
        } else if (!strcmp(r, "singlestep")) {
            singlestep = 1;
        } else if (!strcmp(r, "strace")) {
            do_strace = 1;
        } else if (!strcmp(r, "prof")) {
            prof_run = true;
        } else
        {
            usage();
        }
    }
    if (optind >= argc)
        usage();
    filename = argv[optind];
    exec_path = argv[optind];

    /* Zero out regs */
    memset(regs, 0, sizeof(struct target_pt_regs));

    /* Zero out image_info */
    memset(info, 0, sizeof(struct image_info));

    memset(&bprm, 0, sizeof (bprm));

    /* Scan interp_prefix dir for replacement files. */
    init_paths(interp_prefix);

    if (cpu_model == NULL) {
        cpu_model = "qemu32";
    }

    cpu_exec_init_all(0);
    /* NOTE: we need to init the CPU at this stage to get
       qemu_host_page_size */
    env = cpu_init(cpu_model);
    if (!env) {
        fprintf(stderr, "Unable to find CPU definition\n");
        exit(1);
    }
#if defined(TARGET_I386) || defined(TARGET_SPARC) || defined(TARGET_PPC)
    ///cpu_reset(env);
#endif

    thread_env = env;

    target_environ = envlist_to_environ(envlist, NULL);
    envlist_free(envlist);


    /*
     * Read in mmap_min_addr kernel parameter.  This value is used
     * When loading the ELF image to determine whether guest_base
     * is needed.  It is also used in mmap_find_vma.
     */
    {
        FILE *fp;

        if ((fp = fopen("/proc/sys/vm/mmap_min_addr", "r")) != NULL) {
            unsigned long tmp;
            if (fscanf(fp, "%lu", &tmp) == 1) {
                mmap_min_addr = tmp;
                qemu_log("host mmap_min_addr=0x%lx\n", mmap_min_addr);
            }
            fclose(fp);
        }
    }

    /*
     * Prepare copy of argv vector for target.
     */
    target_argc = argc - optind;
    target_argv = calloc(target_argc + 1, sizeof (char *));
    if (target_argv == NULL) {
	(void) fprintf(stderr, "Unable to allocate memory for target_argv\n");
	exit(1);
    }

    /*
     * If argv0 is specified (using '-0' switch) we replace
     * argv[0] pointer with the given one.
     */
    i = 0;
    if (argv0 != NULL) {
        target_argv[i++] = strdup(argv0);
    }
    for (; i < target_argc; i++) {
        target_argv[i] = strdup(argv[optind + i]);
    }
    target_argv[target_argc] = NULL;

    memset(ts, 0, sizeof(TaskState));
    init_task_state(ts);
    /* build Task State */
    ts->info = info;
    ts->bprm = &bprm;
    env->opaque = ts;
    task_settid(ts);

    ret = loader_exec(filename, target_argv, target_environ, regs,
        info, &bprm);
    if (ret != 0) {
        printf("Error %d while loading %s\n", ret, filename);
        _exit(1);
    }

    for (i = 0; i < target_argc; i++) {
        free(target_argv[i]);
    }
    free(target_argv);

    for (wrk = target_environ; *wrk; wrk++) {
        free(*wrk);
    }

    free(target_environ);

    if (qemu_log_enabled()) {
        log_page_dump();

        qemu_log("start_brk   0x" TARGET_ABI_FMT_lx "\n", info->start_brk);
        qemu_log("end_code    0x" TARGET_ABI_FMT_lx "\n", info->end_code);
        qemu_log("start_code  0x" TARGET_ABI_FMT_lx "\n",
                 info->start_code);
        qemu_log("start_data  0x" TARGET_ABI_FMT_lx "\n",
                 info->start_data);
        qemu_log("end_data    0x" TARGET_ABI_FMT_lx "\n", info->end_data);
        qemu_log("start_stack 0x" TARGET_ABI_FMT_lx "\n",
                 info->start_stack);
        qemu_log("brk         0x" TARGET_ABI_FMT_lx "\n", info->brk);
        qemu_log("entry       0x" TARGET_ABI_FMT_lx "\n", info->entry);
    }

    target_set_brk(info->brk);
    syscall_init();
    signal_init();

#if 0 /* ningjia */
    syscall_init();
    signal_init();
#endif

    /* ningjia dummy init CS */
    env->segs[R_CS].base = 0x0;
    env->regs[R_EAX] = regs->eax;
    env->regs[R_EBX] = regs->ebx;
    env->regs[R_ECX] = regs->ecx;
    env->regs[R_EDX] = regs->edx;
    env->regs[R_ESI] = regs->esi;
    env->regs[R_EDI] = regs->edi;
    env->regs[R_EBP] = regs->ebp;
    env->regs[R_ESP] = regs->esp;
    env->eip = regs->eip;

#ifdef SIEVE_OPT
    map_exec(env->sieve_hashtable, sizeof(env->sieve_hashtable));
#if 0
    map_exec(env->sieve_jmptable, sizeof(env->sieve_jmptable));
    map_exec(env->sieve_rettable, sizeof(env->sieve_rettable));
#endif
#endif

#if 0
    /* linux interrupt setup */
#ifndef TARGET_ABI32
    env->idt.limit = 511;
#else
    env->idt.limit = 255;
#endif
    env->idt.base = target_mmap(0, sizeof(uint64_t) * (env->idt.limit + 1),
            PROT_READ|PROT_WRITE,
            MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    idt_table = g2h(env->idt.base);
    set_idt(0, 0);
    set_idt(1, 0);
    set_idt(2, 0);
    set_idt(3, 3);
    set_idt(4, 3);
    set_idt(5, 0);
    set_idt(6, 0);
    set_idt(7, 0);
    set_idt(8, 0);
    set_idt(9, 0);
    set_idt(10, 0);
    set_idt(11, 0);
    set_idt(12, 0);
    set_idt(13, 0);
    set_idt(14, 0);
    set_idt(15, 0);
    set_idt(16, 0);
    set_idt(17, 0);
    set_idt(18, 0);
    set_idt(19, 0);
    set_idt(0x80, 3);
#endif

    /* linux segment setup */
    {
        uint64_t *gdt_table;
        env->gdt.base = target_mmap(0, sizeof(uint64_t) * TARGET_GDT_ENTRIES,
                PROT_READ|PROT_WRITE,
                MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
        fprintf(stderr, "env->gdt.base is %x\n", env->gdt.base);
        env->gdt.limit = sizeof(uint64_t) * TARGET_GDT_ENTRIES - 1;
        gdt_table = g2h(env->gdt.base);
#ifdef TARGET_ABI32
        write_dt(&gdt_table[__USER_CS >> 3], 0, 0xfffff,
                DESC_G_MASK | DESC_B_MASK | DESC_P_MASK | DESC_S_MASK |
                (3 << DESC_DPL_SHIFT) | (0xa << DESC_TYPE_SHIFT));
#else
        /* 64 bit code segment */
        write_dt(&gdt_table[__USER_CS >> 3], 0, 0xfffff,
                DESC_G_MASK | DESC_B_MASK | DESC_P_MASK | DESC_S_MASK |
                DESC_L_MASK |
                (3 << DESC_DPL_SHIFT) | (0xa << DESC_TYPE_SHIFT));
#endif
        write_dt(&gdt_table[__USER_DS >> 3], 0, 0xfffff,
                DESC_G_MASK | DESC_B_MASK | DESC_P_MASK | DESC_S_MASK |
                (3 << DESC_DPL_SHIFT) | (0x2 << DESC_TYPE_SHIFT));
    }
#if 0
    cpu_x86_load_seg(env, R_CS, __USER_CS);
    cpu_x86_load_seg(env, R_SS, __USER_DS);
    cpu_x86_load_seg(env, R_DS, __USER_DS);
    cpu_x86_load_seg(env, R_ES, __USER_DS);
    cpu_x86_load_seg(env, R_FS, __USER_DS);
    cpu_x86_load_seg(env, R_GS, __USER_DS);
#endif
    /* This hack makes Wine work... */
    //env->segs[R_FS].selector = 0;

    fprintf(stderr, "here is %s\n", __FUNCTION__);
    cpu_loop(env);
    /* never exits */
    return 0;
}

