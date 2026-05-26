---
layout: post
title: "From CTF Heap Pwn to Falco Rules — Reading Memory Corruption as a Defender"
date: 2026-05-26 16:30:00 +0800
categories: [detection-engineering, methodology]
tags: [falco, sysmon, ebpf, glibc, tcache, heap-exploitation]
---

A common pushback I get when people see my GitHub: *"You spend a lot of time on CTF pwn writeups. How is heap exploitation `defensive` work?"* It's a fair question, and the honest answer takes a while. This post is the long version.

The short version: every heap exploitation primitive — tcache poisoning, unsorted bin attacks, House of Botcake, House of Einherjar — has a **runtime-observable signature** that almost no defender bothers to instrument. Read enough offensive writeups and that observability gap stops being hypothetical. You can write the Falco rule that catches the next variant of `__free_hook` overwrite in 15 lines.

I will work through one concrete example end-to-end — the [CISCN 2019 c_3 challenge](https://github.com/1392081456/ctf-notes/blob/main/pwn/ciscn_2019_c_3.md) — and pull out the detection rules that fall out of it. Then I'll generalize to the five exploit families that cover most modern Linux heap CVEs.

## The example: tcache poison → `__free_hook` = `one_gadget`

CISCN 2019 c_3 is a deliberately simple challenge — a UAF-based heap exploit against glibc 2.27. The intended exploitation chain is:

1. Free the same chunk eight times. The first seven freed copies fill the size-0x110 tcache bin via self-loop; the eighth gets pushed into the unsorted bin and exposes a libc address in its `fd` pointer, leaked through a UAF `show`.
2. Double-free a smaller chunk, then use the binary's `backdoor` menu (an attack-count incrementer) as an *accumulator* to advance the tcache `fd` pointer by exactly `0x60` bytes — landing the fake `fd` on the next chunk's start.
3. Walk the poisoned chain through three `alloc` calls: get back the corrupted slot, then a chunk whose backing storage is in fact the **first byte after `__free_hook - 0x10`**.
4. Write `one_gadget` (a function pointer that executes `/bin/sh` with no arguments) into `__free_hook`.
5. Trigger any subsequent `free()` → the libc dispatcher sees `__free_hook != NULL` and jumps to `one_gadget`. Shell.

Why `one_gadget` rather than `system("/bin/sh")`? Because the challenge's `create` function quietly zeroes `chunk[0]` after every allocation, so `system(weapon[idx])` always receives an empty string. `one_gadget` takes no arguments and dodges the issue. This is the kind of subtle initializer side effect that decides whether a real exploit goes anywhere — and it's the kind of detail you only notice if you've read the disassembly yourself.

## What this looks like to a defender

Forget for a moment that this is a CTF challenge. Imagine the same primitive lives in a CVE — say, a Java application using a native cryptographic library with a heap UAF. An attacker exploits it on your server. The five-stage chain above produces these observable side effects in order:

| Stage | Observable signature | Where you'd see it |
|---|---|---|
| 1 (libc leak) | Process reads its own `/proc/self/maps`, OR the program produces unexpectedly large numeric output | strace, eBPF `tracepoint:syscalls:sys_enter_openat` filtered on `/proc/self/maps` |
| 2 (tcache fd corruption) | Mid-process write inside `glibc.tcache_perthread_struct`, which lives in libc data, not the program heap | ❌ Not directly observable from outside the process |
| 3 (chunk handed out at fake address) | Subsequent `malloc()` returns an address inside libc's data section | ❌ Not directly observable from outside |
| 4 (write to `__free_hook`) | A write to libc's `.bss` from non-libc code | ✅ **eBPF uprobe on `__libc_malloc`, watch `__free_hook` symbol** |
| 5 (hook fires) | `execve("/bin/sh", ...)` from a process that should never spawn shells | ✅ **Falco / Sysmon — this is the bread and butter** |

The middle three stages happen entirely inside one process's address space. From outside the process they are invisible. Stage 5 is where every well-known monitoring stack lights up, but by then the attacker has a shell. **Stage 4 is the bottleneck.** Anyone monitoring stage 4 catches the exploit before the shell, regardless of the specific primitive used to reach it.

## Building a stage-4 detector

`__free_hook`, `__malloc_hook`, and `__realloc_hook` are libc global function pointers that exist for one historical reason: letting valgrind and dmalloc swap in their own allocator. **Real production code has not written to them in fifteen years.** That is the cleanest detection target in the entire heap-exploitation landscape:

> Alert on any write to the bytes occupied by `__free_hook`, `__malloc_hook`, or `__realloc_hook` from a non-libc code path.

The cleanest implementation is an eBPF uprobe attached to libc directly. Sketch:

```c
// hook-write-watch.bpf.c (illustrative)
SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:__libc_calloc")
int BPF_KPROBE(probe_calloc_enter) {
    u64 fh = bpf_get_libc_sym("__free_hook");
    u64 val;
    bpf_probe_read_user(&val, sizeof(val), (void *)fh);
    if (val != 0) {
        bpf_printk("__free_hook is non-NULL (= 0x%lx) at calloc entry\n", val);
    }
    return 0;
}
```

You can drop this from Cilium's bpftool or run it standalone via `libbpf-bootstrap`. The check is cheap enough to run on every allocation path in any application that links libc.

If eBPF feels heavy, **Falco does the job at a coarser granularity** without instrumentation:

```yaml
- rule: Shell Spawned from Java or Python Web Process
  desc: >
    Detects /bin/sh, /bin/bash, or other shells being spawned by a
    process whose comm is in a typical web-app set. This is the post-
    exploitation tail of every heap RCE chain — if you catch this, you
    catch CVE-2021-44228, CVE-2022-22965, the CISCN c_3-class UAF, and
    any future variant they share with.
  condition: >
    spawned_process and
    proc.name in (sh, bash, dash, zsh, ksh) and
    proc.pname in (java, python, python3, node, gunicorn, uwsgi, php-fpm)
    and not user.name in (root)
  output: >
    Shell %proc.name spawned from web process %proc.pname
    (user=%user.name, container=%container.name,
    cmdline=%proc.cmdline, parent_cmdline=%proc.pcmdline)
  priority: WARNING
  tags: [post-exploit, container, glibc-heap]
```

This rule will not catch every exploit (an attacker who only needs to read `/etc/shadow` doesn't need a shell), but it catches the overwhelming majority. The CISCN c_3-style `__free_hook = one_gadget` chain ends in exactly this `execve` and would trip the rule immediately.

## Five exploit families, five detection ideas

The c_3 example is one path among many. A defender who has read maybe ten public heap-exploit writeups can sketch a coverage matrix that fits on one page:

| Family | Typical primitive | Stage-4 detection idea |
|---|---|---|
| **tcache poison → hook** | `__free_hook` / `__malloc_hook` write | eBPF uprobe watching the three hook symbols at every alloc/free entry (sketch above) |
| **House of Botcake / Force / Einherjar** | Forge `top_chunk` size or fake chunk near libc | eBPF uprobe on `_int_malloc`, alert on returned pointer landing in `[libc_data .. libc_data+0x4000]` |
| **Unsafe unlink** | Write attacker-chosen `fd` and `bk`, exploit linked-list update | Same as above — the unlink result is a malloc returning a pointer into a non-heap mmap region |
| **File-stream attacks (`_IO_2_1_stdout_`, vtable overwrite)** | Overwrite an IO_FILE struct, often `stdin->_fileno` or `stdout->vtable` | Read-only the relevant fields via mprotect at process startup (a libc-modification trick) OR Sysmon-style file-table anomaly: process reads `/proc/self/fd/666` it never opened |
| **Stack pivot via SROP / mprotect** | Mark heap region executable | Falco rule on `mprotect(... , PROT_EXEC)` from any non-JIT-aware process |

Each row is one ~15-line eBPF program or Falco rule. The whole table is maybe three afternoons of work. The reason almost no one does it: people who *can* read the exploit writeups well enough to extract the signatures usually do not have a SOC mandate, and people with a SOC mandate usually do not read pwn writeups.

That gap is exactly where my work sits. Every `pwn/*.md` in [ctf-notes](https://github.com/1392081456/ctf-notes) is not (for me) an exploitation portfolio — it is the **source material** for the kind of detection content that ends up in [sigma-detection-rules](https://github.com/1392081456/sigma-detection-rules) and the table above.

## What I wish I had known three years ago

Two things, in retrospect.

First, **the lesson of stage 4 generalizes far past heap exploitation.** Most security-critical bugs have an analogous "no legitimate code path writes here" invariant. SSRF? No legitimate web process initiates outbound IMDS requests. Java deserialization? No legitimate Tomcat process loads `javax.naming.InitialContext` lazily. SQL injection at scale? No legitimate connection emits `UNION SELECT` against the same table twice in 100ms. The defender's job is to find the invariant; the exploit writeups are how you find it.

Second, **read offensive writeups as *failed-detection retrospectives*.** Every paragraph that says "the attacker bypasses X by doing Y" is also a paragraph that says "X failed to detect Y." Reading with that lens turns a one-direction "how was it broken" narrative into a two-direction "what would have caught this" exercise, and it changes the kind of detection rules you write.

---

The CISCN c_3 writeup is at [ctf-notes/pwn/ciscn_2019_c_3.md](https://github.com/1392081456/ctf-notes/blob/main/pwn/ciscn_2019_c_3.md). The five-family detection table will land as its own page in the next refactor of [sigma-detection-rules](https://github.com/1392081456/sigma-detection-rules) — currently the repo ships the 23 N-day CVE rules but not the runtime-monitoring sketch above. Adding it is on the 5/30 todo.
