---
layout: post
title: "A Return Address Is a Partially-Known Pointer - 30 pwn.college ROP Challenges, One Idea"
date: 2026-06-24 09:30:00 +0800
categories: [binary-exploitation, methodology, detection-engineering]
tags: [rop, pwn-college, aslr, pie, partial-overwrite, one-gadget, forking-server, ret2libc, glibc]
related_posts:
  - pwn-to-falco-rules
  - 23-vulhub-labs-three-things-i-would-redo
---

The pwn.college *Return Oriented Programming* module is 30 real challenges (plus an optional demo). I finished all 30. People treat a sequence like that as 30 separate puzzles. It isn't. It is one idea, stretched until it breaks, then patched and stretched again.

The idea is small enough to put in a sentence:

> **A saved return address on the stack is a pointer whose low bits you already know and whose high bits are random. Every "ROP without a leak" technique is just a different way to avoid having to know the high bits.**

Once you hold that framing, the whole module — `ret2win`, syscall chains, `ret2libc`, stack pivots, partial overwrites, the forking-server finale — stops looking like a difficulty ladder and starts looking like a single argument about *where ASLR's entropy actually lives*. This post walks that argument, then turns it around and asks what these leak-less exploits look like from the blue side, because the answer is "extremely loud."

## The entropy budget of a pointer

Take any code pointer in a PIE binary or in libc. Split it into bytes:

```
0x0000_7f3a_b412_4083
        \________/\__/
         randomized  fixed
```

- The **low 12 bits** (`0x083` here) are the *page offset*. Paging works in 4 KB units, so the loader can never randomize them. If you know the symbol, you know these bits for free.
- The **high bits** are ASLR. On x86-64 Linux a libc mapping has roughly 28 bits of entropy, all living in bytes 1 through 5.
- The **top two bytes** are `0x0000` (user-space canonical addresses).

A "leak" is just a way to learn the random middle bytes. The entire module is a tour of what you can do when the binary refuses to hand them over.

## Stage one: when you don't need the high bytes at all

The first third of the module (`ret2win`, stacked-return chains, argument-passing chains, syscall `execve`, `read`-to-`.bss`) is **No-PIE**. The binary's base is fixed, so every "random" byte is actually a constant you can read out of the ELF. There is nothing to leak.

What these teach is the *grammar* of a chain, independent of ASLR:

- a function epilogue's `ret` pops the next stack qword into RIP, so stacked addresses execute in sequence;
- `pop rdi; ret` loads an argument before each call;
- with no `/bin/sh` string and no leak, you `read(0, .bss, 16)` to *write* the string into a fixed writable address, then `execve` it.

One detail from this stage outlives it and quietly decides half the later challenges: **on a SUID-root binary, `execve("/bin/sh")` gives you an unprivileged shell.** dash sees `euid != ruid` at startup and drops back to `ruid`. You read root's `/flag` only if you call `setuid(0)` *first*. Hold that thought; the finale turns on it.

## Stage two: the high bytes exist, so leak them

Then PIE switches on and the module's real subject arrives. Now the high bytes are random and you need them. The classic move — *Leaky Libc*, *Putsception* — is `puts(puts@got)`: call `puts` on its own GOT entry, print six bytes of a live libc pointer, subtract the known offset, and you have the base. Standard two-stage `ret2libc` follows: `setuid(0)` then `system("/bin/sh")`.

But the interesting challenges are the ones that **take the leak away**, and force you to ask how few of the random bytes you can get away with knowing.

The answer is often *zero or one*. A **partial overwrite** writes only the low byte (or low two bytes) of a saved return address and leaves the high bytes as they sit on the stack. Because the low 12 bits are fixed, a one-byte overwrite redirects a pointer *within its own page* with no brute force at all — that is the "0 bits" end of the bracket the challenges keep mentioning. A two-byte overwrite reaches further but now you are gambling on the one random nibble in bits 12-15: roughly a 1-in-16 retry. ASLR's entropy didn't go away; you just stopped paying for the bytes you don't disturb.

*Guarded Gadgets* is the cleanest expression of this. Canary, PIE, SUID, no win function, and only **one arbitrary read per run**. You need two secrets (the canary and a libc address) but you can only take one before the overflow corrupts you. The trick: overwrite a *single byte* of `main`'s saved return address, `0x..083 → 0x..069`, landing back inside `__libc_start_call_main` just before its `call main`. `main` runs a second time — same process, same canary, same base — and hands you a second arbitrary read. Stage one takes the canary, stage two takes libc. The randomized high bytes were never needed; you re-entered using a byte you already knew.

## Stage three: the forking server, where crashes become a side channel

The last six challenges (*ROP Roulette*, *Libc Lottery*) are network daemons: `socket / bind / listen / accept / fork`, one child per connection. This changes the physics of the problem in two ways that matter more than any gadget.

First, **`fork()` does not re-randomize.** Every child inherits the parent's canary, PIE base, and libc base. The secrets are now *constant across connections*. A value you could never brute inside a single process becomes brute-forceable across a thousand connections.

Second, **a crashing child doesn't take down the server.** That turns a segfault into a free oracle. You can read a secret one byte at a time: send the known prefix plus one guess byte, and ask "did this child reach the normal exit, or did it print `*** stack smashing detected ***`?" The canary falls in about `7 × 128` connections. With a pre-check print (a string emitted *before* the canary comparison) you can even read the saved return address back byte by byte — BROP, basically, against a stack canary instead of a function table.

There is a sharp little trap here worth stating plainly, because it cost me a wrong answer. If the service prints `### Goodbye!` *before* it checks the canary, then "Goodbye appeared" is **not** a success signal — every connection prints it. The only honest oracle is the *presence* of the smashing message, read all the way to connection close. Break early on "Goodbye" and you will confidently brute-force a canary of `00 00 02 01 00 02 01 00` and wonder why nothing works.

## The finale: libc is small, and a shell can leak the rest

*Libc Lottery (Hard)* removes every leak and the crash oracle stops discriminating — a wrong return address and a clean exit close the socket identically. The module's hint says *"partial overwrite of the saved instruction pointer to execute 1 gadget... 0-12 bits of bruteforce."* That phrasing is the whole solution if you read it literally.

`main`'s saved return address is a libc pointer (`__libc_start_main+0xf3`). Here is the observation that makes it work: **the entire libc image is smaller than 16 MB.** Every address in libc therefore shares its top bytes (bits 24 and up) with that saved return address. So a **three-byte** partial overwrite — reusing the original high five bytes off the stack — can redirect the return into *any* libc gadget at all. The only unknown is ASLR bits 12-23: 12 bits, 4096 tries. That is the "lottery," and because the forking server keeps the base constant, exactly one of the 4096 lands on the gadget you chose.

The gadget to choose is a `one_gadget` — a single libc address that does `execve("/bin/sh")` with no setup — because a partial overwrite jumps straight there with no chance to stage registers. You can verify statically that at `main`'s `ret` the registers a one_gadget needs (`r12`, `r15`) are zero: `__libc_start_main` never reloads them before calling `main`, and `main` never touches them. The 4096-try sweep hits.

And then it hands you a shell that **can't read the flag** — because, exactly as stage one warned, the SUID child's dash dropped privileges. `uid=1000`. `/flag: Permission denied`.

This is the moment the series has been building to, and the resolution is my favorite idea in the whole module. *The deprivileged shell is itself the leak.* The one_gadget hit proved the low three bytes of the libc address. Keep them fixed, overwrite **byte 3**, and brute it 256 ways: only the byte that reconstructs the real address keeps the shell alive (any other value shifts the target 16 MB into unmapped memory and crashes). Walk bytes 3, 4, 5 — and you have read the **entire libc base**, one byte at a time, using "did I get a shell" as the oracle. Now you know the base completely, so you abandon the partial overwrite, write a *full* `setuid(0); system("/bin/sh")` chain with absolute addresses, and read the flag as root.

A single self-contained gadget, upgraded into a full leak, upgraded into a privileged chain. No `puts`, no format string, no information disclosure bug anywhere. Just the structure of the pointer.

## What this looks like to a defender

Now flip it. Forget the flag. Imagine this exploit class running against a real forking network service — a parser daemon, a legacy RPC endpoint, an embedded device's update server. Offense people obsess over how *clever* leak-less exploitation is. From the blue side the striking thing is how **loud** it is.

Every technique in stage three is a brute force, and a brute force against a forking server is a crash storm:

| Exploit step | What the host sees | Where it shows up |
|---|---|---|
| Canary byte brute | ~900 children dying with `*** stack smashing detected ***` in seconds, all from one peer | `kernel: ... segfault` / glibc fortify log spam; per-process `__stack_chk_fail` |
| one_gadget lottery | up to 4096 child **segfaults** in a tight loop, one source IP | `dmesg` segfault flood; auditd `SIGSEGV`; abnormal `fork`/`exit` churn on one PID tree |
| base byte-by-byte leak | hundreds more crashes, then a child that *doesn't* crash and runs `/bin/sh` | the transition itself is the signal |
| final chain | `execve("/bin/sh")` from a network daemon that has no business spawning a shell | Falco/Sysmon `spawned_process` under a listener |

None of this is subtle. A network service whose children segfault hundreds of times per minute from a single peer is not "having a bad day" — it is being byte-brute-forced, and that pattern is trivial to alert on:

- **Crash-rate per service per source IP.** Almost every leak-less exploit needs hundreds to thousands of crashes against a *constant* target. Rate-limit or alert on child segfaults grouped by parent service and peer. This one signal covers canary brute, ASLR brute, and BROP simultaneously.
- **`*** stack smashing detected ***` is a detection, not just a mitigation.** Each line is a *failed* attempt. A burst of them is an attack in progress, not noise to suppress.
- **Shells under listeners.** The terminal event of nearly every memory-corruption chain is `execve` of a shell (or `setuid(0)` immediately before it) from a process whose job is to answer sockets. This is the highest-signal, lowest-volume rule you can write, and it is the same Falco rule that catches the heap CVEs I [wrote about earlier]({% post_url 2026-05-26-pwn-to-falco-rules %}).

The offensive lesson of the series is that you can defeat full ASLR with nothing but the structure of a pointer and a server that forks. The defensive lesson is the dual of it: **the very thing that makes leak-less exploitation possible — a forking server that survives its children's crashes — is what makes it screamingly observable.** The attacker needs thousands of crashes against a constant base. Count the crashes.

---

*Full Chinese working notes and exploit scripts for all 30 challenges are in my [ctf-notes repo](https://github.com/1392081456/ctf-notes/blob/main/pwn/pwn_college_program_security_rop.md); this post is the retrospective, not the walkthrough.*
