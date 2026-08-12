+++
title = "The Shape of a Pipeline"
date = "2026-08-1w"
description = "Why endpoint telemetry pipelines converge on bounded queues, durable logs, replay, and idempotent consumers."

[extra]
toc = true
keywords = "EDR pipeline, telemetry queue, write-ahead log, backpressure, event delivery"

[taxonomies]
tags = ["EDR", "Architecture", "Telemetry", "Data Engineering"]
+++

*Building an EDR from scratch, essay 2 of 13.*

Once the three sensors from the last essay are producing events, a
suspiciously boring problem appears: get the events to a server.

I say suspiciously because everyone underestimates it, including me. It
sounds like plumbing. It reads like a weekend of work. And then you sit
down to write it and discover that you are re-deriving, from scratch, the
same structure that sits inside Kafka, inside PostgreSQL's WAL, inside
`journald`, inside every message queue you've ever used, and — if you go
back far enough — inside TCP.

That convergence is the interesting thing. This essay is about why the
shape is nearly forced, which decisions inside it are actually free, and
the one place where I think the conventional answer is a lie people tell
in marketing copy.

## Three things you can do when you can't keep up

Start with the only situation that matters. Data is arriving faster than
you can move it along. You have exactly three options, and there is no
fourth:

1. **Drop it.** Throw away data. Fast, bounded, and lossy.
2. **Buffer it.** Hold it somewhere. Preserves data, and converts a
   throughput problem into a memory problem, which is a worse problem
   because it kills the whole process instead of one event.
3. **Push back.** Refuse to accept more until you've caught up, so the
   pressure propagates upstream to whoever is producing.

Every stage of every pipeline picks one. A system's character is entirely
determined by which stage picks which, and the failure you get in
production is always the failure of whichever stage picked *drop*.

Here is the thing that took me longest to internalize: **backpressure is
not a way to avoid dropping data. It's a way to choose where the dropping
happens.** If the producer is a kernel probe watching a machine that is
compiling a large C++ project, the events exist whether or not anyone is
ready. Pressure has to terminate somewhere. Pushing back moves the
overflow up the chain; it doesn't delete it.

So the real design question isn't "how do we never lose events." It's
**where do we want the loss, and can that place be honest about it?**

## Putting the loss where it can be counted

The answer this agent settles on is stated as an invariant, and it's the
single most load-bearing sentence in the codebase: the kernel-adjacent ring
is the only place allowed to drop events — and it counts what it drops.

Both halves matter, and the second half is the one people forget.

The kernel ring is the right place to lose data for unglamorous reasons.
It is a fixed-size allocation that exists whether you like it or not. It
sits at the boundary where the producer genuinely cannot be slowed down —
you are not going to make a process-creation event wait while your
userspace agent catches up, because that would mean the security tool is
now a performance bottleneck in `fork()`, which is how you get uninstalled.
And critically, the kernel gives you a drop counter for free, because it
knows exactly how many times it failed to write.

That last property is what turns a data loss into a *known* data loss, and
the difference between those two is the whole ballgame. A pipeline that
loses 4% of events and reports "everything is fine" is worse than useless
— it's actively misleading, because an analyst will interpret the absence
of an event as evidence that nothing happened. A pipeline that loses 4% and
says so lets you make a decision: add capacity, tune the filters, or accept
the gap knowingly.

Everything downstream of the ring, therefore, is forbidden from dropping.
It must push back instead. You can watch the invariant being enforced in
one line in
`shipper/src/linux_sensor.rs`:

```rust
//! events into the shipper's bounded channel. blocking_send provides the
//! backpressure link: a stalled shipper stops this loop and overflow is
```

`blocking_send`, not `try_send`. The distinction is four characters wide
and it's the entire policy. `try_send` would return an error when the
channel is full, and the natural thing to write next is a `continue` — at
which point you have quietly created a second drop site, uncounted,
invisible, in user space. `blocking_send` instead parks the reader thread,
which stops draining the kernel ring, which pushes the overflow back to the
one place designed to absorb it.

A bounded channel with a blocking send *is* the backpressure. There's no
framework involved. The design lives in a function name.

## Why "exactly once" is a marketing term

Now the events need to cross a network to a backend, and here we meet the
most persistently misunderstood problem in distributed systems.

You send a batch. You don't get a response. What happened?

Maybe the batch never arrived. Maybe it arrived, was written to the
database, and the acknowledgement was lost on the way back. From where you
sit those two situations are *indistinguishable* — the evidence available
to you is identical — and yet they demand opposite actions. Resending is
correct in the first case and creates a duplicate in the second.

There is no protocol that fixes this. You cannot add a handshake, because
the acknowledgement of the handshake can also be lost, forever, turtles all
the way down. This is the Two Generals problem and it is not an engineering
gap, it's a proof.

So "exactly once delivery" does not exist. What exists — and what every
mature system actually does, whatever the brochure says — is **at-least-once
delivery plus idempotent processing**. Send until acknowledged, accept
duplicates as normal, and make the receiver's handling of a duplicate a
no-op. The system's *observable behavior* is exactly-once. The delivery
never was.

The receiving half is a single line in
`backend/src/lib.rs`:

```rust
                .with_option("insert_deduplication_token", &token);
```

The token is `<agent_id>:<sequence>`. ClickHouse remembers recently-seen
tokens and silently discards an insert that repeats one. The agent is free
to be dumb and persistent; the backend makes repetition harmless.

## The constraint nobody warns you about

Here's where it stops being textbook, and it's my favorite thing in the
whole pipeline.

Once you've decided that identity is `(agent_id, sequence)` attached to a
*batch*, you have — without necessarily noticing — signed a contract that
constrains you forever after. From
`shipper/src/queue.rs`:

```rust
//! Because the backend dedupes on (agent_id, sequence), recovery must resend
//! the exact batches as originally constructed — re-batching the same events
//! under an old sequence would get them silently deduped away. So the WAL
//! stores whole batches, and replay bypasses the batching logic entirely.
```

Read that failure mode carefully, because it's beautifully nasty. Suppose
after a crash you replay your unsent events and, being tidy, you repack
them into fuller batches. Batch 100 originally held events A and B; now
batch 100 holds A, B, C, and D. You send it. The backend sees token
`agent:100`, recognizes it, and drops the insert as a duplicate.

Events C and D are gone. Not delayed — *gone*, permanently, and with a
successful acknowledgement returned to the agent. No error is logged
anywhere. Your metrics are green. The data is missing.

The lesson generalizes well beyond this codebase: **when you make an
identifier the basis of deduplication, you freeze the boundaries of whatever
that identifier names.** The batch stopped being a transient performance
optimization the moment it became an identity. It's now a durable structure
you are not allowed to reorganize.

Which is exactly why the write-ahead log stores whole encoded batches, and
why replay is a separate code path that walks the disk rather than
re-entering the batcher. The pipeline has a "no re-batching" rule the way a
database has a "no rewriting history" rule, and for the same underlying
reason.

## What durability actually costs

The write-ahead log itself is the oldest trick in the book: write the data
to disk and force it to physical media *before* you tell anyone you have
it, and reclaim the space only after someone else has taken responsibility.

The header spells the ordering out:

```rust
//! Durable on-disk queue: a write-ahead log of EventBatch records so events
//! survive a shipper restart. A batch is appended and fsync'd *before* the
//! first send attempt and reclaimed only after the backend acks it.
```

`fsync` before the first attempt, reclaim after the ack. Those two
bookends define a window in which the data exists in two places at once,
and that redundancy is the entire point. Every durable system in existence
is some variation on this trick.

The part that separates a real WAL from a toy one is what happens when you
find damage on startup:

```rust
//! missing cursor is safe: everything replays and the backend dedupes. A
//! torn record at the tail of the *last* segment is a normal crash artifact
//! and is truncated away; corruption anywhere else is a hard error.
```

This is a small masterclass in thinking about failure, so let me unpack the
three cases separately.

A **torn record at the tail of the last segment** is what a crash *looks
like*. You were in the middle of appending; the machine lost power; the
final record is half-written. That isn't corruption, it's the expected
physical signature of an interruption. Truncate it and move on — the events
in it were never acknowledged to anyone, so nothing is lost that anyone
believes exists.

A **damaged record in the middle** is a different animal entirely. Nothing
in normal operation writes there. Its presence means a bad disk, a filesystem
bug, or something modifying your files. Recovering from that by skipping the
bad record would be the worst possible choice: you'd silently drop unknown
data and continue as if healthy. So it's a hard error, loudly.

A **missing ack cursor** is safe to lose because losing it can only cause
*over*-delivery — you replay batches the backend already has, and the
deduplication makes that free. The cursor is an optimization, and it's
designed so that its failure mode lands on the harmless side.

That's the design principle underneath all three: for every piece of state,
ask which direction its corruption pushes you, and arrange for the cheap
direction to be the one that happens. Redundant work: fine. Silent data
loss: never.

## Decoupling, and the luxury of a slow consumer

The last structural idea is visible in the module header of
`shipper/src/ship.rs`:

```rust
//! Batching gRPC publisher, decoupled into a batcher and a sender that
//! meet at the durable queue: the batcher drains the channel and appends
//! every batch to the WAL; the sender reads batches back off disk and
//! delivers them at-least-once (same sequence until acked). A dead
//! backend therefore parks only the sender — telemetry keeps flowing to
//! disk up to Config::max_queue_bytes, past which the batcher stops
//! consuming and backpressure walks channel -> reader thread -> kernel
//! ring (still the only place designed to drop).
```

Two independent components that never speak to each other; they share only
a file. The batcher's job is to get events onto disk. The sender's job is to
get things off disk and onto the network. Neither knows the other exists.

The consequence is that a backend outage — which is the common case, not
the exotic one; deploys happen, networks partition — degrades gracefully
along a predictable path. The sender parks. The batcher keeps writing.
Telemetry accumulates on disk, which is cheap and enormous. Only when the
disk cap is reached does pressure resume its walk up the chain toward the
kernel ring.

There's a nice systems-thinking observation buried in there. Introducing an
intermediate storage layer didn't just add buffering — it **changed the
failure mode from correlated to independent**. Without the WAL, a network
problem immediately becomes a kernel-ring problem, because the whole chain
is rigidly coupled and pressure transmits instantly. With it, the two
failures are separated by hours of disk capacity. Same components, one
extra layer, and an outage that would have cost you telemetry now costs you
nothing but disk space.

## Boring on purpose

Look at what the finished pipeline actually is. A bounded channel. A
blocking send. A size-and-time batcher. An append-only log with CRCs. A
retry loop. A dedupe token.

Not one of those is clever. There is no novel algorithm anywhere, nothing
you couldn't explain to a competent engineer in a minute each. And that's
the achievement rather than an apology for it — because this layer sits
between kernel code that can crash a machine and a detection engine whose
correctness depends utterly on its input being complete. It is the part of
the system that *must* be reasoned about without effort, at 3am, by someone
who didn't write it.

The interesting decisions were all about placement and honesty. Put the
lossy stage where loss is unavoidable and countable. Put durability before
the first send, not after. Keep failures independent by inserting a layer
between them. Make every piece of state fail toward redundant work rather
than toward silence.

Do that, and what's left is boring. Which means the thinking worked.

The next problem doesn't yield to boring, though. Once you have a complete,
durable stream of events, you have to say *what each one happened to* — and
on a running machine, the things you're naming keep disappearing and the
names keep getting reused. That identity problem is where the next essay
begins.
