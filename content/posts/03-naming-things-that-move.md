+++
title = "Naming Things That Move"
date = "2026-08-19"
draft = false
description = "Why PIDs and paths are not identities, and how an EDR can name processes and files safely across time."

[extra]
toc = true
keywords = "process identity, PID reuse, file identity, EDR response, endpoint security"

[taxonomies]
tags = ["EDR", "Architecture", "Process Monitoring", "Filesystems"]
+++

*Building an EDR from scratch, essay 3 of 13.*

An analyst looks at an alert and clicks *kill this process*.

Between that click and the signal, a few hundred milliseconds pass. In
those milliseconds the process exits on its own — it was a short-lived
script, it was always going to exit — and the kernel, being a good steward
of a small resource, hands its process ID to the next thing that asks. On a
busy machine that might be a database backend, a session manager, or the
SSH daemon holding the connection your incident responder is sitting in.

The signal arrives. It is delivered, correctly and successfully, to
something that has nothing to do with the alert.

This is not an exotic race. It's the ordinary consequence of a fact so
familiar that it hides in plain sight: **a PID is not an identity. It's a
name, drawn from a small pool, that gets recycled.**

Endpoint telemetry is full of this. Almost everything you want to talk
about is short-lived, and almost every name you have for those things is
either recycled, mutable, or both. Getting this wrong doesn't produce a
crash — it produces a system that is confidently, quietly, wrong about
which thing it's discussing. This essay is about the general shape of the
problem and the handful of moves that solve it.

## What makes a name an identity

Three properties separate a usable identity from a mere label:

- **Unique** at any instant. Two live things never share it.
- **Stable** for the lifetime of what it names. It doesn't change underneath
  you.
- **Non-recycled** across lifetimes. Once a thing is gone, its identity is
  never issued to a different thing.

PIDs have the first two and spectacularly fail the third. Filesystem paths
fail the second *and* the third — a path is a lookup, resolved fresh every
time you use it, and someone else can change what it resolves to between
your two uses. Names that fail the third property are the dangerous ones,
because failure looks like success: you get an answer, it's just about a
different object than you meant.

The recurring fix, in every case below, is the same: **pair the unrecycled
name with something that pins down *which* lifetime you meant.**

## The pair that doesn't recycle

For processes, the second half of the pair is the start time. PIDs cycle;
the *combination* of a PID and the moment that PID began doesn't, because
time doesn't run backwards.

The kill action in `shipper/src/kill.rs` builds its
entire safety story on this:

```rust
//! PID reuse is the whole problem (see proto KillProcessAction): the task
//! carries the intended victim's start time, and a kill proceeds only if the
//! LIVE process at that pid has a matching start time (within tolerance).
//! A recycled pid always starts later than the one the operator saw, so it
//! never matches — the guard refuses instead of killing an innocent process.
```

The operator's task doesn't say "kill PID 4823." It says "kill PID 4823,
which started at 14:22:07.431." Before signalling, the agent reads the start
time of whatever is *currently* living at 4823 and compares. Mismatch means
the thing you meant is already gone, and the correct action is to refuse.

Note the asymmetry that makes this airtight: a recycled PID always starts
*later* than the one the operator observed. The comparison can never be
fooled by a reused PID, because reuse only ever moves the timestamp forward,
past any plausible measurement error.

Which is what licenses something that would otherwise look sloppy:

```rust
/// How far a live process's start time may differ from the requested one and
/// still count as the same process. Absorbs the observation-vs-start skew and
/// cross-platform rounding; it does NOT need to distinguish reuse, since
/// reuse moves the start time by far more than any measurement jitter.
const DEFAULT_TOLERANCE: Duration = Duration::from_secs(2);
```

A fuzzy comparison in a security guard should make you nervous. It doesn't
here, and the comment explains exactly why: the tolerance absorbs *jitter*,
and the threat it defends against operates at a completely different
magnitude. Nobody's PID gets recycled within two seconds *and* lands within
two seconds of the original start time. The signal and the noise live orders
of magnitude apart, so a sloppy-looking threshold is in fact a precise one.

That's a reusable habit for any threshold you're tempted to add: don't ask
"is this value right," ask "what's the ratio between what I'm tolerating and
what I'm detecting." If it's small, you don't have a threshold problem, you
have a design problem.

There's a subtler trap underneath, and it's the kind of thing that only
shows up in production. A start time is meaningless without knowing *which
clock* produced it. Linux offers several — `CLOCK_REALTIME` jumps when NTP
corrects it, `CLOCK_MONOTONIC` doesn't count suspend, `CLOCK_BOOTTIME`
does. If the sensor stamps the event from one clock family and the kill
guard reads the live process from another, your comparison drifts by
whatever the difference happens to be that day, and your guard starts
refusing legitimate kills after an NTP correction. The sensor here reads
`task->start_boottime` and applies the REALTIME−BOOTTIME offset precisely so
both sides of the comparison end up in the same family. Two numbers being
"a timestamp" is not enough for them to be comparable.

## A path is a question, not an answer

Files have the same disease in a more virulent form.

`/tmp/payload.bin` is not a file. It's a *query* — instructions for
traversing directories to find an inode — and it's re-evaluated every single
time you use it. Between your `stat()` and your `open()`, anything with
write access to any directory along that path can change the answer. That's
the TOCTOU (time-of-check to time-of-use) family, and for a security tool
it's not a theoretical concern: quarantining a file is precisely the moment
an attacker most wants to redirect you.

Imagine quarantine done naively. Hash the path to confirm it's the malicious
file. Then move the path into the quarantine store. In between, the attacker
replaces the path with a symlink to `/etc/shadow`. You have just used your
elevated privileges to hash a known-bad file and quarantine a critical
system file. Your logs will say the operation succeeded.

The fix is to stop using the name after the first lookup. From
`shipper/src/quarantine.rs`:

```rust
//!   * `FileControl` — the OS primitives (pin a file to one inode/object,
```

and, concretely:

```rust
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
```

`O_NOFOLLOW` refuses to traverse a final symlink — so the swap-a-symlink
attack fails at the door rather than succeeding silently. And once that
`open` returns, the file descriptor *is* the identity. It refers to one
inode. Renaming the path doesn't move it, deleting the path doesn't
invalidate it, and no amount of directory manipulation can make it point
somewhere else. Every subsequent operation goes through the descriptor:

```rust
            // fchmod on the pinned inode: a path swap cannot redirect it.
```

`fchmod` rather than `chmod`. `fstat` rather than `stat`. The pattern is
consistent, and once you see it you'll see it everywhere in well-written
systems code: **resolve the name exactly once, then work with the handle.**
The handle is the identity; the path was only ever a way to find it.

The same code then does something I want to highlight because it's a habit
worth stealing:

```rust
                // instant; prove the blob IS our pinned inode.
```

Having moved the file into the store, it *verifies* that the object now in
the store is the same object it pinned — and rolls back if not. It doesn't
assume the operation it just performed did what it intended. In a system
where an adversary is actively trying to make your operations mean something
other than what you meant, that distinction between "I issued the correct
call" and "the correct thing happened" is the whole game.

## Identity by content

Sometimes you don't want to identify a *file* at all — you want to identify
a *payload*, wherever it happens to live. The same malware dropped at ten
paths on ten machines is one thing worth tracking, not ten.

That's what a cryptographic hash gives you: an identity derived from
content rather than location. Two files with the same SHA-256 are the same
payload, no matter what they're named or which host they're on.

The schema in `backend/schema/001_events.sql`
makes a small decision here that reveals something about designing for
consumers rather than for storage:

```sql
    -- agent-computed sha256 of the executable image, lowercase hex;
    -- '' = not hashed (EXIT events, vanished file, over the size cap,
    -- or a sensor without enrichment). Hex, not raw: IOC lists join
    -- directly in SQL.
```

Raw bytes would be half the size. Hex is stored anyway, because every threat
intelligence feed on earth distributes hashes as lowercase hex, and an
analyst with a list of indicators should be able to write a join and get an
answer — not first write a conversion. Sixteen extra bytes per row buys
frictionless use of the column for its actual purpose. Storage efficiency
that makes data harder to use is a false economy.

Note also that `''` means "no hash," and the comment enumerates the reasons
why. Which brings us to the theme that turns out to matter most of all.

## Absence is not zero

If a value can be missing, its absence must be *representable* and must not
be confusable with any real value. This sounds obvious. It is violated
constantly, usually by accident, usually via a language's default value.

The uid column is the sharpest example:

```sql
    -- acting process's real/effective uid; 4294967295 = not captured
    -- (pre-uid WAL replay or platform without parity). uid 0 IS root,
    -- so absence must never look like it — rules must exclude the
    -- sentinel explicitly.
```

The obvious default for a missing integer is 0. For a uid, 0 is **root**.
Default an unknown user to 0 and every event from a sensor that couldn't
determine the user now claims to be a root action. Your detection rules —
which quite reasonably treat root activity as more interesting — light up
on a field that means "we don't know." You'd have manufactured a false
positive generator out of a language default.

The same reasoning appears for timestamps, and the choice of sentinel is
neatly argued:

```sql
    -- identity (pids recycle, the pair doesn't). 1970-01-01 00:00:00 =
    -- not captured (pre-field agent) — no real process starts at the
    -- epoch, so the zero default is unambiguous, unlike uid.
```

Epoch-0 is safe as a sentinel *because no real process starts then*. Zero is
unsafe for uid *because uid 0 is real and important*. Identical mechanism,
opposite verdicts — and the difference is entirely about the semantics of
the domain, not about the type. There is no general rule like "use 0 for
missing" or "use -1 for missing." You have to look at what the values mean
and pick something outside the real range.

## In-kernel or not at all

Container attribution is where identity gets genuinely hard, and where the
solution is instructive.

The naive approach: an event arrives with a PID; read
`/proc/<pid>/cgroup`; parse out the container. It works when you test it.
It fails in production for a reason you've already seen twice in this essay
— by the time you read `/proc`, the process may be gone, and the PID may
belong to something else. Your container attribution is now not just missing
but *wrong*, and short-lived processes are exactly the ones an attacker
uses.

`shipper/src/cgroup.rs` refuses that whole
approach:

```rust
//! module turns that number into the runtime's container id.
//!
//! Why the inode: on cgroup v2 the id the kernel returns equals the cgroup
//! directory's inode (its kernfs node id — a full 64-bit ino since 5.5;
//! the agent's BTF-enabled floor sits there). So the mapping is a scan of
//! /sys/fs/cgroup for the directory whose inode matches — keyed on the
//! stable id, never on a pid that may already be gone (the whole reason
//! the id is stamped in-kernel rather than re-read from /proc).
```

The eBPF probe calls `bpf_get_current_cgroup_id()` *at event time, in
kernel context, while the process is definitionally alive*. That number
rides along in the event. Resolution to a human-meaningful container id
happens later, in user space, at leisure — because unlike the PID, the
cgroup id is stable and doesn't recycle out from under you.

This is the general principle, and it's the most portable lesson in the
essay: **capture identity at the moment of the event, in the context where
it's unambiguous. Resolve it to something readable whenever you like.**
Deferring *capture* is a correctness bug. Deferring *resolution* is just
scheduling.

There's also a small piece of Linux trivia in there that I enjoy far more
than I should. The cgroup id *equals the directory's inode number*, because
cgroups are backed by kernfs and the "id" is just the kernfs node id. That's
not a documented mapping so much as a consequence of how the thing is built
— which means the resolver can find the cgroup by scanning for a matching
inode, with no parsing and no API. Understanding the implementation gave a
cleaner solution than the interface advertised.

## Making identity durable

The final move is to take these carefully-constructed identities and turn
them into something you can query, which is where
`backend/schema/006_process_index.sql`
comes in:

```sql
-- Backend-materialized process index: one row per process identity
-- (agent_id, pid, start_time) — pids recycle, the pair doesn't.
```

Two events describe a process — its creation and its exit — and they may
arrive out of order, or twice, or hours apart if a WAL replayed. The index
has to fold them into one row regardless:

```sql
-- Replay contract: an insert deduplicated by token skips the view too. A
-- replay that outlives the token window re-feeds the view, so every
-- column is an idempotent fold (min/max) — replaying a byte-identical
-- row cannot change the folded state. Out-of-order arrival (exit before
-- create, WAL replay) folds the same way: merges are order-blind.
```

Every column folds with `min` or `max`. Those operations are commutative,
associative, and idempotent — which is the algebraic way of saying that
order doesn't matter, grouping doesn't matter, and repetition doesn't
matter. Given those three properties, "exit arrived before create" and "this
batch replayed four times" stop being cases you handle and become cases that
cannot arise.

And the sentinel discipline from earlier shows up again, now doing real
work:

```sql
-- uid/euid fold with min so the 4294967295 absence sentinel loses to
-- any captured value — and 0 still IS root, never absence.
```

Because absence is `4294967295` — the *largest* possible u32 — folding with
`min` means any real value beats it automatically. The choice of sentinel
and the choice of fold operator were made together, and the result is that
"prefer a real value over a missing one" needs no conditional logic at all.
It's a consequence of arithmetic.

That's the thing I'd point at if someone asked what good data modeling looks
like. Not the absence of special cases, but special cases that dissolve into
the structure so completely that there's nothing left to get wrong.

## The tax and the return

Look at what all this cost. Every process reference carries a timestamp.
Every file operation carries a descriptor. Every event carries a cgroup id
stamped in kernel context. Every nullable column carries an explicitly
chosen sentinel and a comment defending it. It's more fields, more plumbing,
more to explain.

What it buys is that a whole category of bug becomes impossible rather than
unlikely. Not "we tested it and didn't see the race" — actually impossible,
because a recycled PID cannot match a start time, a descriptor cannot be
redirected by a rename, and a `min`-fold cannot be disturbed by a replay.

Which matters especially here, because the next thing this system does with
these identities is act on them: terminate the process, quarantine the file,
cut the machine off the network. Once you're taking destructive action on a
remote host, "we're pretty sure this is the right process" isn't a standard
anyone can live with.

And that raises a question this essay has been carefully avoiding: who gets
to decide that the action happens at all? That is the authority problem in
the next essay.
