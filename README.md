# minidetect - Minimal Credential Integrity Detector

This Linux kernel module monitors process credentials (`struct cred`) for unauthorized modifications. It aims to detect credential tampering attempts, inspired by techniques used in LKRG (Linux Kernel Runtime Guard).

[minidetect.webm](https://github.com/user-attachments/assets/3779385f-b17e-4248-8ae8-2366b654ad97)

## How it works

1.  **Task tracking:**

    - Uses kprobes (`wake_up_new_task`, `do_exit`) to track user-space processes (excluding kernel threads).
    - Maintains a hash table (`proc_info_table`) storing baseline credential information (`struct mini_proc_info`) for each monitored process.

2.  **Baseline establishment:**

    - When a task is added, its initial `cred` and `real_cred` pointers and contents are stored as a baseline. References (`get_cred`) are taken to these credential structures.

3.  **Hooking credential changes:**

    - Uses kprobes/kretprobes to instrument key functions involved in credential modification:
      - `prepare_creds`: Entry point for creating new credentials.
      - `commit_creds`: Applies new credentials.
      - `revert_creds`: Reverts to previous credentials.
      - `security_bprm_committed_creds`: Hook after `execve` applies new credentials.

4.  **LKRG-style validation flags:**

    - Each tracked process has a validation flag (`p_off`) XORed with a global random cookie (`mini_global_off_cookie`).
    - The decoded flag state is compared against another global random cookie (`mini_global_cnt_cookie`).
    - **ON State:** Decoded `p_off == mini_global_cnt_cookie`. Validation occurs.
    - **OFF State:** Decoded `p_off` is a multiple (>1) of `mini_global_cnt_cookie`. Validation is skipped.
    - The `prepare_creds` kprobe handler turns validation OFF.
    - The `commit_creds`, `revert_creds`, and `security_bprm_committed_creds` kretprobe handlers turn validation back ON.

5.  **Validation & Detection:**
    - In the kretprobe handlers (`commit_creds`, `revert_creds`, `security_bprm_committed_creds`), _after_ turning validation ON:
      - The current `cred` and `real_cred` pointers and contents are compared against the stored baseline.
      - Any mismatch triggers an alert and attempts to kill the process (`SIGKILL`).
      - If validation succeeds, the baseline is updated (`mini_update_baseline`) to reflect the new, legitimate credentials.
    - The validation flag itself is checked for corruption (i.e., not matching the expected ON or OFF states). Flag corruption also triggers an alert and kill attempt.

## Building and Installing

Uses a standard kernel module `Makefile`:

- `make`: Build `minidetect.ko`.
- `make clean`: Remove build artifacts.
- `sudo make install`: Build, copy the module to the kernel drivers directory, and run `depmod`.
- `sudo make uninstall`: Remove the module from the kernel drivers directory and run `depmod`.

Load/Unload with `modprobe minidetect` / `rmmod minidetect`. View logs via `dmesg`. `insmod` / `rmmod` works too.
