+++
title = "How an Operating System Decides to Let You Watch It"
date = "2026-08-10"
draft = true
description = "Windows, Linux, and macOS expose endpoint telemetry through three different trust models—and make sensor failures surface at different times."

[extra]
toc = true
keywords = "EDR architecture, endpoint telemetry, Windows drivers, eBPF, macOS Endpoint Security"

[taxonomies]
tags = ["EDR", "Architecture", "Windows", "Linux", "macOS"]
+++

*Building an EDR from scratch, essay 1 of 13.*

Here is an awkward fact about endpoint security software: the program you
want to install and the program you want to catch are asking the operating
system for the same things.

Both want to see every process that starts. Both want to know when files
are written. Both want to watch the network. Both want to survive reboots,
resist termination, and run before the user logs in. If you squint at the
capability list of an EDR agent and the capability list of a competent
rootkit, they are the same list. The difference is intent, and intent is
not something a kernel can typecheck.

So every operating system has had to answer a question that has no clean
technical answer: *how do we let someone watch everything, without letting
everyone watch everything?*

Windows, Linux, and macOS each answered it differently. Not slightly
differently — differently in kind, from different first principles, with
different ideas about where trust comes from. And because the answer is a
trust model rather than an API, it propagates upward. It shapes what your
sensor can observe, what it costs to be wrong, and — this is the part I
did not expect — *when in the software lifecycle your mistakes become
visible*.

That last one turned out to be the most useful lens I found. Let me get
there the long way.

## Three answers to one question

I'll name the three models before defending them, because having the words
makes the rest of this readable:

- **Windows trusts by ceremony.** You may enter the kernel. First, perform
  the rituals.
- **Linux trusts by proof.** You may not be trusted, so submit your program
  for mechanical verification and it will run only if safety is provable.
- **macOS trusts by brokerage.** You may not enter the kernel at all.
  Apple will go inside, look around, and tell you what it saw.

Each is internally coherent. Each is, I think, defensible. And each one
extracts a completely different tax.

## Windows: the bet on ceremony

The Windows model is the oldest and the most straightforward: security
software runs in the kernel, with the same privileges as the kernel,
because that is where the information is. There is no sandbox. If your
driver dereferences a bad pointer at `DISPATCH_LEVEL`, the machine
bugchecks, and every user of that machine finds out at once.

Given that, Windows does not try to make your code safe. It tries to make
sure that only code someone was willing to *sign their name to* gets to be
unsafe. Trust is established out of band — a signing certificate, an
attestation process, a company with a legal identity — and enforced at load
time.

What I find architecturally interesting is how thoroughly that ceremony is
woven into the APIs themselves. It isn't a single check at the door. The
privileged APIs individually refuse to work for a driver that hasn't
performed the ritual. From the header comment in
`windows/driver/edr_driver.c`:

```c
 * MUST be linked /INTEGRITYCHECK or PsSetCreateProcessNotifyRoutineEx
 * fails with STATUS_ACCESS_DENIED (0xC0000022).
```

`/INTEGRITYCHECK` is a flag that marks the image as requiring signature
verification at load. Note what's happening: the process-notification API
won't talk to you unless your binary has *asked to be held to a stricter
standard*. It's an opt-in that gates a capability. You can't accidentally
get process-creation visibility; you have to declare, in your link line,
that you intend to be the kind of code that is checked.

The other half of the Windows model is stranger and more human. Filesystem
minifilters — the mechanism for seeing file operations — stack in an order
determined by a number called an **altitude**:

```
 *   reg add HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Instances\EdrAgentInstance
 *       /v Altitude /t REG_SZ /d 385100 /f
 * (385100 sits in the FSFilter Activity Monitor range 360000-389999;
```

Think about what an altitude actually is. Every filter driver on the system
sits at a point in a global, numeric, totally-ordered namespace. Antivirus
lives around 320000. Activity monitors live in 360000–389999. Encryption
drivers live lower, so they see plaintext. Replication drivers live higher.
Your position determines whether you observe a write before or after some
other vendor's product transforms it — which means it determines whether
your product *works* in the presence of theirs.

And the allocation of these numbers is not enforced by the kernel. It is
administered by Microsoft, by request, as a registry of reserved ranges.
It's a social protocol wearing a `REG_SZ`.

I love this as a design artifact, because it's an honest admission that the
hard problem in kernel-mode security software was never memory safety — it
was *coordination between mutually distrustful vendors who all want to be
first*. Windows solved it with a phone book. My driver uses 385100 because
it's in the right neighborhood and nobody else on my lab machine is home;
a shipping product would have that number assigned to it, in writing.

The payoff for all this ceremony is that Windows gives you the sharpest
semantics of the three platforms. When `PsSetCreateProcessNotifyRoutineEx`
fires, you are inside process creation, holding structures the kernel is
using, before the first instruction of the new image runs. Nothing is
inferred. Nothing is a heuristic. You are standing in the room where it
happens.

The tax is that the room has no railings.

## Linux: the bet on proof

Linux, arriving at the same problem two decades later and with a very
different culture, made close to the opposite bet. Rather than deciding
*who* may run unsafe code in the kernel, it asked whether the code could be
made safe enough that the question doesn't matter.

eBPF is the answer, and the verifier is the mechanism. You submit a program
in a restricted instruction set; a static analyzer in the kernel simulates
every reachable path and refuses to load anything it can't prove terminates,
stays in bounds, and touches only what it's allowed to touch. If the proof
succeeds, the program is JIT-compiled and runs at native speed in kernel
context. If it fails, you get a rejection and a stack trace, and nothing
happens to the machine.

This inverts the cost structure completely. On Windows, the cost of a
mistake is paid at runtime, by the customer, as a blue screen. On Linux,
it's paid at development time, by me, as an argument with a program that
cannot be talked out of its position.

What makes this more than a sandbox story is where the verifier's
constraints show up in the *design* of the sensor. Consider a snippet from
the exec probe in
`linux/bpf/edr_probes.bpf.c`:

```c
	/* Stack copies: key/value pointers into the ringbuf reservation are
	 * a verifier gamble across kernels; the stack is always legal. */
	pid = ev->pid;
	ppid = ev->ppid;
	bpf_map_update_elem(&exec_ppid, &pid, &ppid, BPF_ANY);
```

There is a perfectly good copy of `pid` sitting in the ring buffer
reservation two lines up. Copying it to the stack first is redundant work
in any normal program. But whether the verifier accepts a pointer into a
ring-buffer reservation as a map key varies across kernel versions, and a
program that loads on my laptop and is rejected on a customer's 5.10 kernel
is a support incident, not a bug report. So the code carries an extra
assignment forever, as a compatibility hedge.

That's the real shape of eBPF development. You are not writing C for a
machine; you are writing C for a proof checker whose exact reasoning powers
differ between the kernels your program must run on. The verifier is a
compiler audience with opinions.

The second half of the Linux answer addresses a different problem, and it's
one Windows never had to solve. Kernel data structures on Linux are not a
stable ABI. `struct task_struct` is laid out differently in every kernel
build, sometimes differently between two distributions of the same version.
A sensor that reads `task->start_boottime` at a hardcoded offset is
correct exactly once.

**CO-RE** — Compile Once, Run Everywhere — fixes this by shipping type
information with the kernel (BTF) and having the loader relocate every
field access at load time against the layout the running kernel actually
has. `BPF_CORE_READ(bprm, filename)` compiles to a relocation entry, not
an offset. The kernel tells you where `filename` lives on *this* machine,
today.

Step back and notice what those two mechanisms together represent. The
verifier says: *I don't trust your code, so prove it.* CO-RE says: *I don't
trust your assumptions about me, so ask at runtime.* Linux replaced the
vendor-trust relationship with a pair of machine-checked contracts. That's
a genuinely different theory of how to make a kernel extensible, and it
puts the burden on the extension author rather than on a certificate
authority.

## macOS: the bet on brokerage

Apple looked at kernel extensions and concluded the entire category was a
mistake.

Not "risky." Not "in need of better tooling." A mistake — third-party code
in the kernel was a permanent, unfixable source of instability and
compromise, and the right move was to remove the capability from the
platform. Kexts were deprecated, then walled off behind boot-policy changes
that a normal user will never make.

But security software still needs the data. So Apple built
**Endpoint Security**: Apple's own code sits at the kernel hook points, and
your agent — running in *user space*, as an ordinary process — subscribes to
a stream of events over a framework API. You get the semantics of kernel
instrumentation with the failure domain of a user process. If your ES
client segfaults, your ES client segfaults. The machine keeps running.

Here's the subscription from the shim in
`macos/esf/edr_esf_shim.c`:

```c
    es_event_type_t events[] = {
        ES_EVENT_TYPE_NOTIFY_EXEC,     ES_EVENT_TYPE_NOTIFY_EXIT,
        ES_EVENT_TYPE_NOTIFY_CREATE,   ES_EVENT_TYPE_NOTIFY_CLOSE,
        ES_EVENT_TYPE_NOTIFY_TRUNCATE, ES_EVENT_TYPE_NOTIFY_UNLINK,
        ES_EVENT_TYPE_NOTIFY_RENAME,   ES_EVENT_TYPE_NOTIFY_MMAP,
```

That reads like a config file. On Windows the equivalent capability is a
signed kernel driver with a registered altitude and a callback running at
elevated IRQL. On macOS it's an array of enum values passed to a library
function from a process that could, in principle, be a shell script's
child. The complexity didn't vanish — Apple absorbed it, and now maintains
it on your behalf.

The tax is subtle and it comes due in two places.

The first is that **the broker decides what exists**. On Windows or Linux
you can, with enough determination, hook something nobody anticipated you'd
want. Under ES, if Apple hasn't modeled an event type, that event is not
merely hard to observe — it is unobservable, and your options are a feature
request and a wait measured in major OS releases.

The interesting flip side is that a broker can also model things the other
platforms *don't have words for*. Two entries further down that same array:

```c
        /* Mach task-port acquisition (macOS 10.15 / 12.0). CONTROL + READ
         * only — INSPECT/NAME are dominated by diagnostics tooling. */
        ES_EVENT_TYPE_NOTIFY_GET_TASK, ES_EVENT_TYPE_NOTIFY_GET_TASK_READ,
```

A Mach task port is a capability handle to another process's address space.
Acquiring one is the macOS injection primitive — the thing that stands
where `OpenProcess` + `WriteProcessMemory` stands on Windows. There is no
equivalent event on the other two platforms in this codebase, because Mach
ports are a macOS abstraction and Apple chose to model access to them
explicitly. The broker can be *more* expressive than raw hooking, when the
broker understands its own OS's semantics better than an outsider would.

The second tax is the one that turned out to matter most in practice, and
it's the reason I ended up thinking about all of this in terms of *time*.

## Where your mistakes surface

Under Endpoint Security, permission is not a runtime check that returns an
error code. Permission is an **entitlement**: a cryptographic grant, issued
by Apple, to a specific developer account, after a review. Your binary
carries it in its signature.

Development builds can fake this. With System Integrity Protection relaxed
and `amfi_get_out_of_my_way` set, an ad-hoc-signed client with a synthetic
entitlement will be accepted by `es_new_client`, and events flow. Every
category in that array above is delivered on my dev VM.

Except one. TCC-modification events — notifications that a privacy grant
(camera, microphone, full disk access) changed — are gated more strictly
than the rest. The client connects. The subscription succeeds. No error is
returned anywhere. And no `TCC_MODIFY` event is ever delivered, because
the faked entitlement clears the door but not that particular room.

There is no bug to find. The code is right. The only fix is a genuine
Apple-issued entitlement, which is a business process, not an engineering
one.

And that, finally, is the pattern I want to leave you with. Line the three
models up by *when a mistake becomes visible*:

| | Trust model | Mistakes surface at | Failure mode |
|---|---|---|---|
| **Windows** | Ceremony — sign, register, enter | **Runtime**, on the customer's machine | Loud and catastrophic (bugcheck) |
| **Linux** | Proof — submit to the verifier | **Load time**, on your machine | Loud and safe (rejection with a trace) |
| **macOS** | Brokerage — Apple looks for you | **Deployment**, at organizational scale | *Silent* — an event class that simply never arrives |

Windows fails at the worst time in the worst way, but tells you
unambiguously. Linux fails at the best possible time, before anything is at
risk, and the price is that you argue with a proof checker for an afternoon.
macOS fails at the strangest time — long after the code is written and
tested — and the failure is an absence, which is the hardest thing in the
world to notice.

Every one of these is a coherent engineering position. But they aren't
interchangeable, and this is why an EDR agent cannot have one unified
sensor abstraction that "handles platform differences." The differences
aren't in the API surface. They're in what the platform believes about you,
and belief doesn't refactor.

What *can* be unified is everything downstream. Once an event exists — a
process started, a file was written, a task port was acquired — the
questions become identical everywhere: how do you not lose it, how do you
name the thing it happened to, who is allowed to act on it. Three sensors,
three trust models, one contract from there on.

The next essay follows that contract downstream and asks why telemetry
pipelines keep converging on the same shape.
