---
layout: post
title: "Reverse Engineering Is Model Recovery"
date: 2026-07-08 09:30:00 +0800
categories: [reverse-engineering, methodology]
tags: [pwn-college, yan85, virtual-machines, patching, file-formats]
related_posts:
  - pwn-to-falco-rules
  - api-testing-is-contract-drift-hunting
  - deserialization-restores-code-paths
---

The pwn.college Program Security reverse-engineering module is a clean progression from strings to models.

The same question keeps repeating:

**What model does this program use to decide that my input is correct?**

Sometimes the model is a byte transform. Sometimes it is a branch. Sometimes it is a virtual machine. Sometimes it is a file format plus a constraint solver.

## Start with the verifier

The early crackmes are small enough to solve by reading constants, but that is not the habit worth keeping.

The useful habit is to write the verifier as:

```text
input -> transform -> comparison -> decision
```

If the transform is reversible, invert it. If it includes a sort, stop looking for a unique original order. A sort validates a multiset, not a string.

This matters because many wrong reverse-engineering attempts are over-specific. They try to recover *the* intended input when the binary only checks an equivalence class.

## Patch the decision, not the program

The patching levels look like a license to change code freely. They are really a lesson in minimality.

When the check is:

```asm
call memcmp
test eax, eax
jne fail
```

one byte can invert the decision. But the integrity-check variants punish that move. A better patch changes the comparison length:

```text
memcmp(a, b, 0) == 0
```

That is a smaller semantic change. It preserves the surrounding control flow and passes both the integrity comparison and the final license comparison.

## A VM is just another model

Yan85 turns the verifier into a custom machine. The trap is thinking that VM reversing is a new category of magic.

It is still model recovery:

```text
3-byte instruction -> register state -> memory state -> syscall state
```

The easy variants print traces. Use them to build the semantic table: opcodes, registers, flag bits, and syscall masks. The hard variants remove the trace, but the bytecode still has structure.

The workflow that held up:

- extract the yancode section;
- disassemble in 3-byte chunks;
- implement `IMM`, `ADD`, `STK`, `STM`, `LDM`, `CMP`, `JMP`, and `SYS`;
- print every compare and syscall;
- solve constraints or assemble VM shellcode.

The later levels flip the task. Instead of understanding their yancode, you write yours:

```text
write "/flag\0" into VM memory
open(path)
read(fd, buf, size)
write(1, buf, n)
exit()
```

Yansanity adds randomized VM mappings. That kills hardcoded practice-mode bytecode, but not the method. Recover the current mapping, then assemble for that mapping.

## File formats beat guessing

The Cows and Bulls levels look interactive. They are not.

`gamefile.bin` starts with a `CBGF` magic and contains the round data. The right interface is not the program prompt. The right interface is the file parser.

The progression is:

- parse the header and records;
- solve Bulls/Cows constraints offline;
- reproduce the migration or ordering state;
- for hash variants, enumerate fixed-length guesses and compare SHA256;
- for salted variants, recover the salt placement before hashing.

Once the file format is the model, the terminal prompt is only an output adapter.

## Defender notes

Reverse engineering writeups often end at "here is the key." That misses the durable part.

For defenders and analysts, the useful artifacts are:

- the transform model;
- the decision point;
- the VM instruction semantics;
- the syscall surface exposed by an interpreter;
- the file format schema;
- the observable failure and success channels.

Those artifacts survive challenge-specific flags. They are also the parts that transfer to malware loaders, protected installers, game anti-cheat components, custom protocol parsers, and fragile validation code.

Reverse engineering is model recovery. Once the model is explicit, the rest of the work becomes ordinary engineering: invert it, patch it, emulate it, generate code for it, or solve constraints against it.
