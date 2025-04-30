#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/cred.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/uidgid.h>
#include <linux/pid.h>
#include <linux/signal.h>
#include <linux/random.h>
#include <linux/rcupdate.h>

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("qbitroot (Adapted from LKRG concepts)");
MODULE_DESCRIPTION("Minimal Credential Integrity Detector using LKRG-style hooks and validation");
MODULE_VERSION("0.6");

// --- Configuration ---
#define HASH_TABLE_BITS 8
#define P_NORMALIZE_LONG ((unsigned long)0x0101010101010101ULL) // For 64-bit, ensure no null bytes
#define P_MASK_COUNTER   ((unsigned long)0x07FFFFFFFFFFFFFFULL) // For 64-bit, ensure counter part fits
#define P_ED_PROCESS_OFF_MAX 100 // Threshold for consecutive off states

// --- Global Variables ---
static unsigned long mini_global_off_cookie;
static unsigned long mini_global_cnt_cookie;

// --- Data Structures ---

struct mini_cred {
	kuid_t uid;
	kgid_t gid;
	kuid_t suid;
	kgid_t sgid;
	kuid_t euid;
	kgid_t egid;
	kuid_t fsuid;
	kgid_t fsgid;
};

struct mini_proc_info {
	pid_t pid;
	struct task_struct *p_task;
	const struct cred *cred_ptr;
	const struct cred *real_cred_ptr;
	struct mini_cred baseline_cred;
	struct mini_cred baseline_real_cred;
	unsigned long p_off; // Encoded validation flag
	unsigned int p_off_count;
	struct hlist_node hash_node;
	struct rcu_head rcu;
};

static DEFINE_HASHTABLE(proc_info_table, HASH_TABLE_BITS);
static DEFINE_SPINLOCK(proc_info_lock);

// --- Helper Functions ---

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
static inline uid_t mini_get_uid(kuid_t kuid) { return __kuid_val(kuid); }
static inline gid_t mini_get_gid(kgid_t kgid) { return __kgid_val(kgid); }
#else
static inline uid_t mini_get_uid(uid_t uid) { return uid; }
static inline gid_t mini_get_gid(gid_t gid) { return gid; }
#endif

static void mini_dump_single_cred(struct mini_cred *baseline, const struct cred *live_cred)
{
	baseline->uid = live_cred->uid;
	baseline->gid = live_cred->gid;
	baseline->suid = live_cred->suid;
	baseline->sgid = live_cred->sgid;
	baseline->euid = live_cred->euid;
	baseline->egid = live_cred->egid;
	baseline->fsuid = live_cred->fsuid;
	baseline->fsgid = live_cred->fsgid;
}

/* MUST be called with proc_info_lock held. */
static void mini_update_baseline(struct mini_proc_info *info, struct task_struct *task)
{
	const struct cred *live_cred;
	const struct cred *live_real_cred;

	rcu_read_lock();
	live_cred = rcu_dereference(task->cred);
	live_real_cred = rcu_dereference(task->real_cred);

	if (info->cred_ptr && info->cred_ptr != live_cred) {
		put_cred(info->cred_ptr);
	}
	if (info->real_cred_ptr && info->real_cred_ptr != live_real_cred) {
		put_cred(info->real_cred_ptr);
	}

	if (live_cred) get_cred(live_cred);
	if (live_real_cred) get_cred(live_real_cred);

	info->cred_ptr = live_cred;
	info->real_cred_ptr = live_real_cred;

	if (live_cred) {
		mini_dump_single_cred(&info->baseline_cred, live_cred);
	} else {
		pr_warn("minidetect: [update_baseline] PID %d: Failed to get current cred\n", info->pid);
	}
	if (live_real_cred) {
		mini_dump_single_cred(&info->baseline_real_cred, live_real_cred);
	} else {
		pr_warn("minidetect: [update_baseline] PID %d: Failed to get current real_cred\n", info->pid);
	}
	rcu_read_unlock();

	info->p_task = task;
}


/* Returns 0 if match, >0 if mismatch. */
static int mini_cmp_single_cred(struct mini_cred *baseline, const struct cred *current_cred, pid_t pid, const char *cred_type, const char *context)
{
	int mismatch = 0;

#define CMP_CRED_FIELD(field, type, eq_func, get_func)                         \
	if (!eq_func(baseline->field, current_cred->field)) {                      \
		pr_warn("minidetect: [%s][PID %d] Mismatch in %s->%s: Expected %u, Got %u\n", \
			context, pid, cred_type, #field,                            \
			get_func(baseline->field),                                 \
			get_func(current_cred->field));                        \
		mismatch++;                                                    \
	}

	CMP_CRED_FIELD(uid, kuid_t, uid_eq, mini_get_uid);
	CMP_CRED_FIELD(gid, kgid_t, gid_eq, mini_get_gid);
	CMP_CRED_FIELD(suid, kuid_t, uid_eq, mini_get_uid);
	CMP_CRED_FIELD(sgid, kgid_t, gid_eq, mini_get_gid);
	CMP_CRED_FIELD(euid, kuid_t, uid_eq, mini_get_uid);
	CMP_CRED_FIELD(egid, kgid_t, gid_eq, mini_get_gid);
	CMP_CRED_FIELD(fsuid, kuid_t, uid_eq, mini_get_uid);
	CMP_CRED_FIELD(fsgid, kgid_t, gid_eq, mini_get_gid);

#undef CMP_CRED_FIELD

	return mismatch;
}

static void mini_kill_task(struct task_struct *task, const char *reason)
{
	int ret;
	struct kernel_siginfo info;

	if (!task || (task->flags & PF_EXITING) || (task->exit_state != 0)) {
		pr_warn("minidetect: Attempted to kill task PID %d (%s) which is already exiting or invalid.\n",
			task ? task->pid : -1, task ? task->comm : "N/A");
		return;
	}

	pr_alert("minidetect: *** Killing PID %d (%s) due to: %s ***\n", task->pid, task->comm, reason);

	clear_siginfo(&info);
	info.si_signo = SIGKILL;
	info.si_errno = 0;
	info.si_code = SI_KERNEL;

	ret = send_sig_info(SIGKILL, &info, task);

	if (ret < 0) {
		pr_err("minidetect: Failed to send SIGKILL to PID %d, error %d\n", task->pid, ret);
	}
}

// --- LKRG-style Validation Flag Management ---

/*
 * Checks if validation is OFF.
 * If ret_ptr != NULL (validation context): increments *ret_ptr on corruption.
 * Returns 1 if OFF (legit or corrupt), 0 if ON.
 */
static inline int mini_is_validation_off(struct mini_proc_info *info, int *ret_ptr) {
	register unsigned long p_off = info->p_off ^ mini_global_off_cookie; // Decode

	if (likely(p_off == mini_global_cnt_cookie)) { // Validation ON
		info->p_off_count = 0;
		return 0;
	}

	// Check if legitimately OFF (multiple of cnt_cookie > 1)
	if (p_off > mini_global_cnt_cookie && (p_off % mini_global_cnt_cookie) == 0) {
		info->p_off_count++;
		if (info->p_off_count > P_ED_PROCESS_OFF_MAX) {
			pr_warn("minidetect: [validation_flag] Validation OFF %u times for PID %d\n", info->p_off_count, info->pid);
			// Consider action if off too long?
		}
		return 1; // Legitimately OFF
	} else { // Corrupted state
		pr_alert("minidetect: [validation_flag] CORRUPTION detected for PID %d (p_off=0x%lx, expected multiple of 0x%lx or exactly 0x%lx)\n",
			 info->pid, p_off, mini_global_cnt_cookie, mini_global_cnt_cookie);
		if (ret_ptr) {
			(*ret_ptr)++; // Signal corruption during validation
		}
		return 1; // Corrupted (effectively OFF)
	}
}

/* Turn validation ON. */
static inline void mini_set_validation_on(struct mini_proc_info *info) {
	register unsigned long p_off = info->p_off ^ mini_global_off_cookie; // Decode
	register unsigned long original_p_off = p_off;

	if (p_off > mini_global_cnt_cookie && (p_off % mini_global_cnt_cookie) == 0) { // Legitimately OFF
		p_off -= mini_global_cnt_cookie; // Decrement
	} else if (p_off == mini_global_cnt_cookie) { // Already ON
		pr_warn("minidetect: [validation_flag] Trying to turn ON validation for PID %d, but it's already ON (p_off=0x%lx)\n", info->pid, original_p_off);
		info->p_off_count = 0;
		return;
	} else { // Corrupted or unexpected state
		pr_alert("minidetect: [validation_flag] Trying to turn ON validation for PID %d from unexpected state (p_off=0x%lx)! Forcing ON.\n", info->pid, original_p_off);
		p_off = mini_global_cnt_cookie; // Force ON
	}

	if (unlikely(p_off != mini_global_cnt_cookie)) {
		pr_err("minidetect: [validation_flag] Logic error in set_validation_on for PID %d! State is 0x%lx, expected 0x%lx. Forcing ON again.\n",
			info->pid, p_off, mini_global_cnt_cookie);
		p_off = mini_global_cnt_cookie; // Force ON state
	}

	info->p_off = p_off ^ mini_global_off_cookie; // Encode
	info->p_off_count = 0;
}

/* Turn validation OFF. */
static inline void mini_set_validation_off(struct mini_proc_info *info) {
	register unsigned long p_off = info->p_off ^ mini_global_off_cookie; // Decode
	register unsigned long original_p_off = p_off;

	if (likely(p_off == mini_global_cnt_cookie)) { // Currently ON
		p_off += mini_global_cnt_cookie; // Increment
	} else { // Already OFF or corrupted
		if (p_off > mini_global_cnt_cookie && (p_off % mini_global_cnt_cookie) == 0) { // Legitimately OFF (nested call?)
			pr_warn("minidetect: [validation_flag] Nested call to turn OFF validation for PID %d? (p_off=0x%lx)\n", info->pid, original_p_off);
			p_off += mini_global_cnt_cookie; // Increment for nesting
		} else { // Corrupted state
			pr_alert("minidetect: [validation_flag] Trying to turn OFF validation for PID %d from unexpected state (p_off=0x%lx)! Forcing OFF(1).\n", info->pid, original_p_off);
			p_off = 2 * mini_global_cnt_cookie; // Force to first OFF state
		}
	}

	info->p_off = p_off ^ mini_global_off_cookie; // Encode
}

/* Reset validation flags to ON state */
static inline void mini_reset_validation_flags(struct mini_proc_info *info) {
	info->p_off = mini_global_cnt_cookie ^ mini_global_off_cookie; // Encode ON state
	info->p_off_count = 0;
}


// --- Core Validation Logic ---

/* MUST be called with proc_info_lock held. Returns 0 if valid, >0 if mismatch. */
static int mini_validate_task_lkrg_style(struct mini_proc_info *info, struct task_struct *task, const char *context)
{
	int mismatch = 0;
	const struct cred *current_cred;
	const struct cred *current_real_cred;

	// 1. Check validation flag
	if (mini_is_validation_off(info, &mismatch)) {
		if (mismatch > 0) { // Flag corruption detected
			mini_kill_task(task, "Validation flag corruption");
		}
		// Return mismatch count (0 if legitimately off, >0 if corrupted).
		return mismatch;
	}
	// Validation is ON.

	// 2. Get current credentials
	rcu_read_lock();
	current_cred = rcu_dereference(task->cred);
	current_real_cred = rcu_dereference(task->real_cred);
	if (current_cred) get_cred(current_cred);
	if (current_real_cred) get_cred(current_real_cred);
	rcu_read_unlock();

	if (!current_cred || !current_real_cred) {
		pr_warn("minidetect: [%s][PID %d] Failed to get current creds for validation\n", context, info->pid);
		if (current_cred) put_cred(current_cred);
		if (current_real_cred) put_cred(current_real_cred);
		mismatch++;
		mini_kill_task(task, "Failed to get creds during validation");
		return mismatch;
	}

	// 3. Compare pointers
	if (info->cred_ptr != current_cred) {
		pr_warn("minidetect: [%s][PID %d] cred pointer changed! Expected %px, Got %px\n",
			context, info->pid, info->cred_ptr, current_cred);
		mismatch++;
	}
	if (info->real_cred_ptr != current_real_cred) {
		pr_warn("minidetect: [%s][PID %d] real_cred pointer changed! Expected %px, Got %px\n",
			context, info->pid, info->real_cred_ptr, current_real_cred);
		mismatch++;
	}

	// 4. Compare content
	mismatch += mini_cmp_single_cred(&info->baseline_cred, current_cred, info->pid, "cred", context);
	mismatch += mini_cmp_single_cred(&info->baseline_real_cred, current_real_cred, info->pid, "real_cred", context);

	put_cred(current_cred);
	put_cred(current_real_cred);

	if (mismatch > 0) {
		pr_alert("minidetect: [%s] !!! Credential mismatch detected for PID %d (%s) !!!\n",
			 context, info->pid, task->comm);
		mini_kill_task(task, context); // KILL ENABLED
	}

	return mismatch;
}


// --- Task Tracking ---

static int mini_add_task(struct task_struct *task)
{
    struct mini_proc_info *info;
    unsigned long flags;

    if (task->flags & PF_KTHREAD || !task->mm) // Ignore kernel threads and tasks without mm
        return 0;

    info = kmalloc(sizeof(*info), GFP_ATOMIC);
    if (!info) {
        pr_err("minidetect: Failed to allocate memory for PID %d\n", task->pid);
        return -ENOMEM;
    }

    info->pid = task->pid;
    info->cred_ptr = NULL;
    info->real_cred_ptr = NULL;

    spin_lock_irqsave(&proc_info_lock, flags);

    // Check if already exists
    {
        struct mini_proc_info *existing_info;
        hash_for_each_possible(proc_info_table, existing_info, hash_node, task->pid) {
            if (existing_info->pid == task->pid) {
                // Already exists, but update baseline anyway to ensure fresh state
                mini_update_baseline(existing_info, task);
                spin_unlock_irqrestore(&proc_info_lock, flags);
                kfree(info);
                return 0;
            }
        }
    }

    // New task, add it
    hash_add(proc_info_table, &info->hash_node, info->pid);
    mini_reset_validation_flags(info);
    mini_update_baseline(info, task);

    spin_unlock_irqrestore(&proc_info_lock, flags);
    
    pr_info("minidetect: Started monitoring new task PID %d (%s)\n", task->pid, task->comm);
    return 0;
}

static void mini_remove_task(pid_t pid)
{
	struct mini_proc_info *info;
	struct hlist_node *tmp;
	unsigned long flags;

	spin_lock_irqsave(&proc_info_lock, flags);
	hash_for_each_possible_safe(proc_info_table, info, tmp, hash_node, pid)
	{
		if (info->pid == pid) {
			hash_del(&info->hash_node);
			if (info->cred_ptr) {
				put_cred(info->cred_ptr);
			}
			if (info->real_cred_ptr) {
				put_cred(info->real_cred_ptr);
			}
			kfree(info);
			break;
		}
	}
	spin_unlock_irqrestore(&proc_info_lock, flags);
}


// --- Kprobes ---

static inline struct mini_proc_info *mini_find_task_info_locked(pid_t pid)
{
	struct mini_proc_info *info;
	hash_for_each_possible(proc_info_table, info, hash_node, pid) {
		if (info->pid == pid) {
			return info;
		}
	}
	return NULL;
}

// Kretprobe for wake_up_new_task (adding new tasks)
static int kret_wake_up_new_task_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_struct *new_task = (struct task_struct *)regs_return_value(regs);
	if (new_task) {
		get_task_struct(new_task);
		mini_add_task(new_task);
		put_task_struct(new_task);
	}
	return 0;
}

static struct kretprobe kret_wake_up_new_task = {
	.handler = kret_wake_up_new_task_handler,
	.kp.symbol_name = "wake_up_new_task",
	.maxactive = NR_CPUS * 2,
};

// Kprobe for do_exit (removing tasks)
static int kp_do_exit_handler(struct kprobe *p, struct pt_regs *regs)
{
	mini_remove_task(current->pid);
	return 0;
}

static struct kprobe kp_do_exit = {
	.pre_handler = kp_do_exit_handler,
	.symbol_name = "do_exit",
};


// --- LKRG-style Credential Change Hooks ---

// Kprobe for prepare_creds (entry) - Turn validation OFF
static int kp_prepare_creds_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct task_struct *task = current;
	struct mini_proc_info *info;
	unsigned long flags;

	if (task->flags & PF_KTHREAD || !task->mm) return 0;

	spin_lock_irqsave(&proc_info_lock, flags);
	info = mini_find_task_info_locked(task->pid);
	if (info) {
		mini_set_validation_off(info);
	}
	spin_unlock_irqrestore(&proc_info_lock, flags);

	return 0;
}

static struct kprobe kp_prepare_creds = {
	.pre_handler = kp_prepare_creds_handler,
	.symbol_name = "prepare_creds",
};


// Kretprobe for commit_creds (exit) - Turn ON, Validate, Update Baseline
static int kret_commit_creds_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_struct *task = current;
	struct mini_proc_info *info;
	unsigned long flags;
	int validation_result = 0;

	if (task->flags & PF_KTHREAD || !task->mm) return 0;

	spin_lock_irqsave(&proc_info_lock, flags);
	info = mini_find_task_info_locked(task->pid);
	if (info) {
		mini_set_validation_on(info); // Turn ON first
		validation_result = mini_validate_task_lkrg_style(info, task, "commit_creds"); // Validate new state vs old baseline

		if (validation_result == 0) { // If valid
			mini_update_baseline(info, task); // Update baseline
		} else {
			pr_alert("minidetect: [commit_creds] Validation failed for PID %d, baseline NOT updated.\n", task->pid);
		}
	}
	spin_unlock_irqrestore(&proc_info_lock, flags);

	return 0;
}

static struct kretprobe kret_commit_creds = {
	.handler = kret_commit_creds_handler,
	.kp.symbol_name = "commit_creds",
	.maxactive = NR_CPUS * 4,
};


// Kretprobe for revert_creds (exit) - Turn ON, Validate, Update Baseline
static int kret_revert_creds_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_struct *task = current;
	struct mini_proc_info *info;
	unsigned long flags;
	int validation_result = 0;

	if (task->flags & PF_KTHREAD || !task->mm) return 0;

	spin_lock_irqsave(&proc_info_lock, flags);
	info = mini_find_task_info_locked(task->pid);
	if (info) {
		mini_set_validation_on(info);
		validation_result = mini_validate_task_lkrg_style(info, task, "revert_creds");

		if (validation_result == 0) {
			mini_update_baseline(info, task);
		} else {
			pr_alert("minidetect: [revert_creds] Validation failed for PID %d, baseline NOT updated.\n", task->pid);
		}
	}
	spin_unlock_irqrestore(&proc_info_lock, flags);

	return 0;
}

static struct kretprobe kret_revert_creds = {
	.handler = kret_revert_creds_handler,
	.kp.symbol_name = "revert_creds",
	.maxactive = NR_CPUS * 4,
};


// Kretprobe for security_bprm_committed_creds (exit) - Post-execve cred change
static int kret_security_bprm_committed_creds_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct task_struct *task = current;
    struct mini_proc_info *info;
    unsigned long flags;

    if (task->flags & PF_KTHREAD || !task->mm) return 0;

    spin_lock_irqsave(&proc_info_lock, flags);
    info = mini_find_task_info_locked(task->pid);
    if (!info) {
        // Task is new from execve, add it first
        spin_unlock_irqrestore(&proc_info_lock, flags);
        mini_add_task(task);  // This will create new baseline
        return 0;
    }

    // Existing task, validate and update baseline
    mini_set_validation_on(info);
    if (mini_validate_task_lkrg_style(info, task, "bprm_committed_creds") == 0) {
        mini_update_baseline(info, task);
    } else {
        pr_alert("minidetect: [bprm_committed_creds] Validation failed for PID %d post-exec, baseline NOT updated.\n", task->pid);
    }
    spin_unlock_irqrestore(&proc_info_lock, flags);

    return 0;
}

static struct kretprobe kret_security_bprm_committed_creds = {
    .handler = kret_security_bprm_committed_creds_handler,
    .kp.symbol_name = "security_bprm_committed_creds",
    .maxactive = NR_CPUS * 2,
};


// --- Module Init / Exit ---

static int __init minidetect_init(void)
{
	int ret;
	struct task_struct *task;

	pr_info("minidetect: Loading Minimal Credential Detector (LKRG-style v%s).\n", THIS_MODULE->version);

	// Initialize random cookies for validation flag
	mini_global_off_cookie = (unsigned long)get_random_long();
	mini_global_cnt_cookie = (unsigned long)get_random_long();
	mini_global_off_cookie |= P_NORMALIZE_LONG;
	mini_global_cnt_cookie |= P_NORMALIZE_LONG;
	mini_global_cnt_cookie &= P_MASK_COUNTER;
	if (mini_global_cnt_cookie == 0) mini_global_cnt_cookie |= P_NORMALIZE_LONG; // Avoid 0

	pr_info("minidetect: Validation cookies initialized (cnt=0x%lx, off=0x%lx).\n", mini_global_cnt_cookie, mini_global_off_cookie);

	// Register kprobes
	ret = register_kretprobe(&kret_wake_up_new_task);
	if (ret < 0) { pr_err("minidetect: Failed register wake_up_new_task: %d\n", ret); return ret; }
	ret = register_kprobe(&kp_do_exit);
	if (ret < 0) { pr_err("minidetect: Failed register do_exit: %d\n", ret); unregister_kretprobe(&kret_wake_up_new_task); return ret; }
	ret = register_kprobe(&kp_prepare_creds);
	if (ret < 0) { pr_err("minidetect: Failed register prepare_creds: %d\n", ret); unregister_kprobe(&kp_do_exit); unregister_kretprobe(&kret_wake_up_new_task); return ret; }
	ret = register_kretprobe(&kret_commit_creds);
	if (ret < 0) { pr_err("minidetect: Failed register commit_creds: %d\n", ret); unregister_kprobe(&kp_prepare_creds); unregister_kprobe(&kp_do_exit); unregister_kretprobe(&kret_wake_up_new_task); return ret; }
	ret = register_kretprobe(&kret_revert_creds);
	if (ret < 0) { pr_err("minidetect: Failed register revert_creds: %d\n", ret); unregister_kretprobe(&kret_commit_creds); unregister_kprobe(&kp_prepare_creds); unregister_kprobe(&kp_do_exit); unregister_kretprobe(&kret_wake_up_new_task); return ret; }
    ret = register_kretprobe(&kret_security_bprm_committed_creds);
    if (ret < 0) { pr_err("minidetect: Failed register security_bprm_committed_creds: %d\n", ret); unregister_kretprobe(&kret_revert_creds); unregister_kretprobe(&kret_commit_creds); unregister_kprobe(&kp_prepare_creds); unregister_kprobe(&kp_do_exit); unregister_kretprobe(&kret_wake_up_new_task); return ret; }

	pr_info("minidetect: Kprobes registered.\n");

	// Add existing tasks
	pr_info("minidetect: Monitoring existing tasks...\n");
	rcu_read_lock();
	for_each_process(task) {
		get_task_struct(task);
		mini_add_task(task);
		put_task_struct(task);
	}
	rcu_read_unlock();
	pr_info("minidetect: Finished monitoring existing tasks.\n");

	pr_info("minidetect: Module loaded successfully.\n");
	return 0;
}

static void __exit minidetect_exit(void)
{
	struct mini_proc_info *info;
	struct hlist_node *tmp;
	unsigned long flags;
	int bkt;

	pr_info("minidetect: Unloading Minimal Credential Detector.\n");

	// Unregister kprobes
    unregister_kretprobe(&kret_security_bprm_committed_creds);
	unregister_kretprobe(&kret_revert_creds);
	unregister_kretprobe(&kret_commit_creds);
	unregister_kprobe(&kp_prepare_creds);
	unregister_kprobe(&kp_do_exit);
	unregister_kretprobe(&kret_wake_up_new_task);
	pr_info("minidetect: Kprobes unregistered.\n");

	rcu_barrier(); // Wait for RCU grace period

	// Clean up hash table
	pr_info("minidetect: Cleaning up monitored task list...\n");
	spin_lock_irqsave(&proc_info_lock, flags);
	hash_for_each_safe(proc_info_table, bkt, tmp, info, hash_node)
	{
		hash_del(&info->hash_node);
		if (info->cred_ptr) {
			put_cred(info->cred_ptr);
		}
		if (info->real_cred_ptr) {
			put_cred(info->real_cred_ptr);
		}
		kfree(info);
	}
	spin_unlock_irqrestore(&proc_info_lock, flags);
	pr_info("minidetect: Cleanup complete.\n");

	pr_info("minidetect: Module unloaded.\n");
}

module_init(minidetect_init);
module_exit(minidetect_exit);
