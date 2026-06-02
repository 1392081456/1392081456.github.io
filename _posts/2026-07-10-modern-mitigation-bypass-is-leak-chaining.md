---
layout: post
title: "Modern Mitigation Bypass Is Leak Chaining"
date: 2026-07-10 09:30:00 +0800
categories: [pwn, methodology]
tags: [pwn-college, ret2libc, got-overwrite, aslr, canary, libc]
related_posts:
  - constrained-shellcode-is-interface-design
  - reverse-engineering-is-model-recovery
---

The last four levels of pwn.college's Program Security module were the hardest to finish, and they share a single shape. None of them falls to one clever trick. Each one runs the full mitigation stack — stack canary, PIE, NX, RELRO, sometimes SUID privilege separation — and the only way through is to **chain small leaks until every mitigation has been turned back into a known value**.

That is the durable lesson of the closing four (`can-it-fizz`, `does-it-buzz`, `make-it-fizzbuzz`, `latent-leak-hard`):

**A mitigation is only a defense while the value behind it is unknown. Every byte you leak is a mitigation you remove.**

## The workhorse: a one-byte partial overwrite is a leak primitive

Three of the four levels share a FizzBuzz skeleton: a loop that reads input, then `strcpy(dst, src)` and prints the result. Because `src` lives in the input window, you can repoint it one byte at a time.

The trick is that a single low-byte overwrite never crosses a page boundary, so it can only redirect a pointer to a neighbor in the *same* page. So you hunt for a useful neighbor:

- In `can-it-fizz`, the GOT sits on one page but a `stdout` copy variable (`R_X86_64_COPY`, holding `&_IO_2_1_stdout_`) sits on the globals page next to `fuzzbuzz`. One byte (`0x18 -> 0x30`) repoints `src` at it, and the next print leaks a libc address.
- In `does-it-buzz`, the same one-byte pivots reach `puts@got` (libc) and a self-referential RELATIVE entry (PIE).
- In `make-it-fizzbuzz`, the same idea leaks libc, PIE, the stack base, and the canary in four loop iterations.

The point is not the specific offsets. The point is that **partial overwrite + same-page pivot is the cheapest leak primitive available**, and it works precisely because PIE only randomizes the high bits you never touch.

## Turn the leak interface into an arbitrary write

`does-it-buzz` shows the next move. If you can control both `src` and `dst` of the `strcpy` in the same iteration, the "print a leak" interface is also an "arbitrary byte-wise write" interface. Read becomes write for free.

From there the canary is irrelevant — the overflow never reaches it — and the solve is pure GOT surgery: stage the address of `win`, then a single `strcpy(strcpy@got, scratch)` redirects the next call into it. The family name `BabyFizzGOT` is the hint; the read primitive and the write primitive are the same code path used twice.

## Keep the loop alive long enough to finish the chain

Leak chaining only works if the program stays in the loop while you collect values. `make-it-fizzbuzz` adds a subtlety: the loop counter `i` sits inside the readable window, and a `%s` print stops at the first NUL.

Writing `i = 0xfefefefe` solves both problems at once. As a signed integer it is negative, so the loop never reaches its exit condition; and because all four bytes are non-NULL, the `%s` print walks straight past the counter into the pointer you actually want to leak. **A counter is not just control flow; under a string-printing leak it is also a NUL barrier you can dissolve.**

## SUID separation is its own mitigation — handle it explicitly

`can-it-fizz` has a quiet trap. A clean `ret2libc` into `system("/bin/sh")` runs a shell, but the shell has dropped privileges, so `/flag` stays unreadable.

The binary is SUID root, which means `euid = 0` but `ruid != 0`, and `system` runs `/bin/sh` which drops to the real uid. The fix is to treat privilege separation as a mitigation to undo before the payoff:

```text
setuid(0)            // collapse ruid to 0 while euid is still 0
system("/bin/sh")    // now the shell keeps root
```

One extra gadget in the ROP chain, but skipping it is the difference between a shell and a useless shell. (Watch stack alignment too: with `A = rbp+8`, the chain is already 16-byte aligned and needs no extra `ret`.)

## NX is a placement problem, not a wall

`make-it-fizzbuzz` ships a never-called `mprotect_stack()` that flips its own stack page to RWX. NX says "no code on the stack"; this gadget says "unless I ask nicely." The chain becomes leak everything, pre-copy shellcode via `strcpy` to a high stack slot, then `ret -> mprotect_stack -> shellcode`.

The non-obvious failure mode — the same one the constrained-shellcode levels teach — is staging. `mprotect_stack`'s own frame executes below `rbp` and clears the low part of the buffer, so shellcode placed at `buffer[0]` is destroyed by the very call that makes the stack executable. The fix is to place the payload at `B+0x80`: past the region the setup code zeroes, but still inside the page that becomes RWX. **Code execution is not enough; the code has to survive the transition into executability.**

## The residual canary, and a verification lesson worth keeping

`latent-leak-hard` is the cleanest leak-chaining puzzle, and it almost beat me with a bad measurement.

The output format is `%.318s`, which caps at buffer offset `0x13e`, while the canary is at `0x148` — so the live frame's canary is *never* printable. It is not a fork service either, so each connection is a fresh canary and byte-by-byte brute force is out. The canary must be leaked within one connection.

The recursion provides it. The child frame's buffer overlaps the deep stack the parent's libc calls (`scanf`, `printf`) used, and those functions leave a canary copy in their own frames. On the remote `libc-2.31`, a copy lands at child buffer offset `0x38`. Fill `0x39` to overwrite its leading NUL and `%s` prints `canary[1..7]`.

The lesson is in how I confirmed it. My first verifier brute-forced the offset and judged success by "no smash message + SIGSEGV = wrong canary." That criterion is **unfalsifiable**: `__stack_chk_fail`'s abort path itself crashes with a SIGSEGV, so a *correct* canary that fails later looks identical to a wrong one. Sixty-four parallel attempts, zero hits, and I nearly concluded `0x38` was not the canary.

The fix was a positive criterion: send `'A'*0x148 + candidate` — an overflow that touches *only* the canary and never the return address. If the candidate is right, the frame returns cleanly (`Goodbye!`, no crash). That test isolates the one variable and immediately confirmed `0x38`. (My local newer libc had no such residual, which is why local GDB never found it — **a leak can be libc-version-specific, so scan the target's environment, not your own.**)

PIE then needs no full leak: at recursion depth >= 1 the saved RIP is a fixed `challenge` return site, so a two-byte partial overwrite to `0x?dc9` brute-forces a single nibble (1/16) to hit `win_authed+0x1c`.

## Defender notes

The closing four map to recurring real-world mistakes:

- copy-relocation and GOT entries adjacent to attacker-influenced pointers, where a one-byte nudge becomes an infoleak;
- the same code path serving as both a disclosure and a write primitive (`strcpy` with attacker-controlled src and dst);
- SUID binaries that call `system`/`exec` without reasoning about ruid/euid;
- self-modifying permission gadgets (`mprotect` to RWX) reachable from a corrupted return address;
- secrets left in reused stack regions by library calls, with leak behavior that varies across libc builds.

For detection, the high-value signals are: a SUID-root process spawning an interactive shell after `setuid(0)`; `mprotect(..., PROT_EXEC)` on stack/anon pages followed immediately by execution there; and crash clustering on `__stack_chk_fail` consistent with canary brute forcing.

The capstone takeaway for the whole Program Security module:

**Mitigations defend unknowns. Exploitation is the work of making each unknown known — one partial-overwrite leak at a time — until the protected control transfer is just arithmetic.**
