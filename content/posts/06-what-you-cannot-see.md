+++
title = "What You Cannot See"
date = "2026-09-14"
draft = true
description = "Every endpoint sensor has structural blind spots. The important skill is identifying, testing, and documenting them."

[extra]
toc = true
keywords = "EDR blind spots, endpoint telemetry, sensor coverage, threat detection"

[taxonomies]
tags = ["EDR", "Architecture", "Telemetry", "Detection Engineering"]
+++

*Building an EDR from scratch, essay 6 of 13.*

Every sensor in this series watches an operating system abstraction.
Process creation. File open. Socket connect. Module load. The events are
delivered because the kernel maintains those abstractions and offers hooks
where they're maintained.

Which implies something uncomfortable, and it's the honest starting point
for this essay: **anything that accomplishes its goal without going through
the abstraction you're watching is invisible to you.** Not hard to see. Not
low-fidelity. Invisible, structurally, in a way no amount of tuning fixes.

An attacker who understands your sensor's hook points is not trying to
evade your detection logic. They're trying to accomplish their goal via a
path that never touches your hook. That's a completely different game, and
it's why the interesting question for a telemetry system isn't "what does
it catch" but "what is it *incapable* of catching, and do we know?"

This essay is about the boundary. It ends up being a lesson in
epistemology more than in kernels.

## When the obvious field lies to you

Start with something that looks like solid ground. A process starts, and
you record the path of the executable. Every EDR does this; most detection
logic is built on it.

Then consider `memfd_create`. It gives you a file descriptor backed by
anonymous memory — a "file" that exists only in RAM, with no directory
entry anywhere on disk. You can write an ELF binary into it and `execve` it.
The process runs. Nothing was ever written to the filesystem.

What does your sensor report for the image path? Something like
`/dev/fd/3`. That's not a lie exactly, but it's useless: it's a synthetic
path naming a file descriptor in a process that is about to be replaced. It
tells you nothing about what ran. Your hash of the image can't be computed
from it. Your allowlist can't match it. Your analyst sees a path that
resolves to nothing.

The field is present, well-formed, and empty of meaning. Those are the worst
kind of blind spot, because a null would at least announce itself.

The fix, from `linux/bpf/edr_probes.bpf.c`,
is to stop asking the path and start asking the inode:

```c
		if (BPF_CORE_READ(file, f_inode, i_nlink) == 0)
			ev->exec_flags |= EDR_LX_EXEC_UNLINKED;
```

`i_nlink` is the number of directory entries pointing at this inode. Zero
means *nothing on the filesystem names this file*. It might be a memfd. It
might be a normal binary that was unlinked after being opened — the classic
"drop, execute, delete" that leaves a running process with no file behind
it. Either way, one integer answers a question the path could not: is this
executable reachable by name?

A second read distinguishes the specific case:

```c
		if (dn &&
		    bpf_probe_read_kernel(dname, sizeof(dname), dn) == 0 &&
		    dname[0] == 'm' && dname[1] == 'e' && dname[2] == 'm' &&
		    dname[3] == 'f' && dname[4] == 'd' && dname[5] == ':')
			ev->exec_flags |= EDR_LX_EXEC_MEMFD | EDR_LX_EXEC_UNLINKED;
```

That's a manually unrolled six-character string comparison, which looks
absurd next to `strncmp` until you remember it's running under the eBPF
verifier, where a fixed-size read at a constant offset is provable and a
variable-length loop is an argument. The comment says exactly that: "A short
fixed read keeps the verifier out of variable-offset territory."

But the technique is what I want to underline. The path was unreliable, so
the probe moved *closer to the mechanism* — from a rendered string to the
kernel structure the string was rendered from. Sensor design is full of
this. When the convenient field is derived, ask what it's derived from, and
whether the source is harder to lie about.

Two boolean flags, and a class of execution that used to be indistinguishable
from a normal process start becomes a query you can write. The attacker's
goal was to run code without leaving a file. They achieved it. They just
couldn't do it without producing an inode with zero links, which is the one
thing the technique fundamentally requires.

**Look for what the technique cannot avoid.** Anything else is a signature,
and signatures get bypassed.

## Absence as a signal

There's a stranger version of this, and it's my favorite piece of design in
the whole codebase.

Loading a kernel module is the rootkit's move — it's the transition from
"code running on the machine" to "code *inside* the machine." Linux offers
two syscalls for it. `finit_module` takes a file descriptor. `init_module`
takes a memory buffer.

The file-based path is straightforward to instrument, and the probe grabs
the name:

```c
	dn = BPF_CORE_READ(file, f_path.dentry, d_name.name);
	n = bpf_probe_read_kernel_str(ev->name, sizeof(ev->name), dn);
```

The memory-based path has no file at all, and therefore nothing to name:

```c
/* init_module: the module image is a user buffer — no file, so no name.
 * The absence IS the signal (a fileless kernel-module load). */
```

That comment is doing real philosophical work. There is no name to report,
and rather than treating that as a data-quality problem to paper over, the
design treats *the shape of the missing data* as the finding. An event that
says "a kernel module was loaded and I cannot tell you from where" is not
a degraded event. It is a high-signal one, because the legitimate path —
`modprobe`, `insmod`, the distro's own tooling — uses the file-based
syscall. The nameless variant is the interesting one almost by definition.

There's an even neater trick layered on top, which relies on *ordering*
rather than content. The attempt hooks fire when a load is requested; a
separate tracepoint fires when a module is actually accepted. So an attempt
with no matching acceptance means the kernel refused the load — a signature
check failing, lockdown mode engaging, a malformed module.

Nobody emits a "module load refused" event. That fact is constructed by
noticing that a thing which should have followed didn't.

The general move: **you can detect an event by observing the hole where its
consequence should be.** It requires knowing the normal causal chain well
enough to notice a missing link, which is a much deeper form of
instrumentation than pattern-matching on fields. Missed connections. Absent
heartbeats. Requests without responses. Once you start looking for holes,
they're everywhere, and they're often where the interesting things hide.

## Choosing your blindness

Now the uncomfortable kind of blind spot: the one you build yourself,
knowingly, because the alternative is worse.

Watching executable memory mappings would be a superb detection surface. A
DLL being mapped into a process is how sideloading works, how injection
works, how a malicious plugin gets in. So: report every file mapped
executable.

Try it and the sensor dies. Every process launch maps dozens of system
libraries — 30 to 100 DLLs on Windows, dyld's whole flood on macOS. The
event rate is orders of magnitude above anything interesting, the ring
buffer overflows, and you lose events *including the ones you cared about*.
A firehose of noise doesn't just bury the signal; it evicts it.

So you filter. And here's the thing worth sitting with: **filtering is
deliberately choosing what to be blind to.** The filter isn't a performance
detail, it's a coverage decision with a security consequence, and it should
be argued rather than tuned into place.

The story of choosing this particular filter is recorded in the
`README`, and it's a good one because the elegant idea lost:

```
a pure W^X filter was tried first and rejected — `max_protection` is `RWX`
for nearly every mapping on recent macOS, and a *current* RWX mapping is
hardware-blocked on Apple Silicon
```

The elegant idea was W^X: report mappings that are both writable and
executable, since legitimate code is generally one or the other. Principled,
mechanism-based, exactly the kind of filter this essay has been praising.

It doesn't work, for two independent reasons that only reality could have
supplied. `max_protection` — the *maximum* protection a mapping could ever
be granted — is RWX for almost everything on modern macOS, so the field
doesn't discriminate. And *current* RWX is hardware-blocked on Apple
Silicon, so the thing you'd actually want to catch can't exist in that form
anyway. The theory was clean and the platform simply doesn't behave the way
the theory assumed.

What shipped instead is a crude path exclusion: skip `/System` and `/usr` on
macOS, skip the Windows directory on Windows. It's an inelegant heuristic
and everyone involved knows it. The README says so plainly — Apple's own
developer tooling reports as a non-system code load, and on Windows every
application's own DLLs under `Program Files` report too.

But it's honest about its own nature, it's cheap enough to run in kernel
context, and it reduces the volume enough that the interesting events
survive. Sometimes the crude filter that works beats the beautiful one that
doesn't, and the professional skill is noticing which situation you're in.

One structural point, easy to miss and load-bearing: this filtering happens
**in the kernel**, before the event is written to the ring. Filtering in
user space would move the drop counter, not the load. The kernel would still
produce the events, the ring would still overflow, and you'd still lose data
— you'd just discard it after paying for it. A high-volume callback needs its
filter at the source.

## The floor

And finally, the blind spot with no clever workaround. From the README's
limitations:

```
**Manually mapped ("reflective") images are invisible** on Windows: a DLL
written into memory and relocated by hand creates no image section, so no
load-image notification is ever delivered.
```

Reflective DLL loading works by doing the loader's job yourself. Allocate
memory, copy in the PE, walk the relocation table, resolve imports, jump to
the entry point. The result is functioning code in a process — and the
operating system's loader was never involved, so there is no image section,
so `PsSetLoadImageNotifyRoutine` has nothing to notify about. The hook isn't
failing. The event genuinely does not exist.

macOS has the identical hole from the other direction: `MAP_ANON` memory
with shellcode in it is anonymous, file-backed by nothing, and there is no
"file mapped executable" event to deliver.

The README's framing is the right one:

```
in both cases the sensor sees code loads that pass through the OS loader,
not code that bypasses it.
```

That single sentence defines the sensor's epistemic boundary better than any
feature list could. You are not watching "code execution." You are watching
*the operating system's code-loading machinery*, and the difference is
exactly the set of techniques that skip it.

Knowing the boundary changes what you do about it. You stop trying to make
the file-mapping sensor catch reflective loading — it cannot, ever — and you
start looking for the *consequences* an in-memory payload can't avoid: the
network connection it eventually makes, the process it injects into, the
persistence it establishes, the child it spawns. The technique evades one
sensor. It rarely evades the whole system, because it still has to
accomplish something, and accomplishing things means using abstractions.

## Why writing them down is the actual skill

The `README` has a "Known limitations" section that runs for
over a hundred lines. Memory-mapped writes attributed at mapping time rather
than at write time. Linux MODIFY firing on open-intent rather than first
write. DNS invisible on macOS loopback because content filters never see it.
TCC events that need an entitlement the build doesn't have. Windows UDPv6
decoded from documentation but never ground-truthed against a real capture.

That list is, I'd argue, the most valuable artifact in the repository, and
it's worth being explicit about why.

An analyst investigating an incident is constantly making inferences from
absence. "There's no network connection from that process, so it never
called home." "There's no file write, so nothing was dropped." Those
inferences are only valid if the sensor would have seen it. Absence of
evidence is evidence of absence *only* when you have coverage — and the
limitations list is precisely the document that tells you when you don't.

This is the same principle as the counted ring drops from
[essay 2](@/posts/02-the-shape-of-a-pipeline.md), one level up. There, the pipeline
made data loss *known* rather than silent. Here, the documentation makes
coverage gaps known rather than implied. In both cases the underlying value
is the same: a system that tells you what it doesn't know is trustworthy in
a way that a system implying total coverage never is.

And there's a professional dimension. Vendors are structurally incentivized
to describe coverage and stay quiet about gaps, because gaps read as
weakness in a bake-off. The result is a market full of tools whose users
systematically overestimate what they can conclude from silence. Writing the
gaps down, next to the code that causes them, is the opposite bet: it makes
the tool less impressive and considerably more useful.

Which sets up the next question. Given a stream of events with known
coverage and known holes, how do you actually turn it into a claim that
something bad is happening? That turns out to be much less about clever
rules than about the shape of the data underneath them. That data model is
the subject of the next essay.
