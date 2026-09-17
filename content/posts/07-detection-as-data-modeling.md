+++
title = "Detection Is a Data-Modeling Problem"
date = "2026-09-17"
draft = false
description = "Detection quality depends on event semantics, schema evolution, idempotency, and honest health signals before it depends on clever rules."

[extra]
toc = true
keywords = "detection engineering, EDR schema, event semantics, detection rules, telemetry health"

[taxonomies]
tags = ["EDR", "Detection Engineering", "Data Modeling", "Telemetry"]
+++

*Building an EDR from scratch, essay 7 of 13.*

Detection engineering has a glamorous reputation. It's the part with the
attacker in it — behavioral analytics, threat hunting, the rule that catches
the thing nobody else caught.

Having now built a small one, my honest assessment is that the clever rules
are the easy part, and they're not where the failures live. The failures
live in the data model underneath: whether a rule *can* express what you
mean, whether it means the same thing tomorrow, and — the one that nearly
got me — whether the system tells you when it has quietly stopped working.

This essay is about that substrate.

## One vocabulary, two purposes

The first decision sounds like an implementation detail and turns out to
shape everything. From `backend/src/detect.rs`:

```rust
//! Rules match the *normalized* EventRow (post-flatten), not raw proto:
//! field names in a rule are the ClickHouse column names, so a rule that
//! works in SQL works here and vice versa.
```

Rules could have matched against the protobuf message — it's what arrives on
the wire, and it's the natural object in the code. Instead they match the
flattened database row, using database column names.

The reason is a workflow, not a technical constraint. Real detection
engineering goes like this: an analyst is hunting, writing SQL against
historical events, and finds something. A query returns rows that shouldn't
exist. Now they want that query to run continuously against new data.

If rules speak a different language than queries, that transition is a
translation step — and translation is where meaning quietly drifts. The
analyst's `WHERE reg_key LIKE '%\CurrentVersion\Run%'` becomes some
`registry.key_path` field in a rule DSL, and the two are *almost* the same,
and the difference surfaces six months later as an alert that never fired.

When both speak the same names, promoting a hunt to a rule is copying a
condition. And it works in reverse, which is just as valuable: given an
alert, you can paste its condition into SQL and ask "how often did this
happen last month?" The investigation and the detection are the same
sentence in the same language.

**Make the exploratory tool and the production tool speak the same
vocabulary.** The friction you remove is conceptual, not typing.

## Correctness and volume are different problems

The second idea is a separation that I think a lot of systems get wrong by
conflating.

Two things sound similar: *don't record the same alert twice* and *don't
spam the analyst*. They are unrelated problems, and this engine solves them
with unrelated mechanisms — deliberately.

```rust
//! works in SQL works here and vice versa. Evaluation is pure — the same
//! rows always yield the same alerts — which is what makes replay safe:
//! an alert's identity is (agent_id, sequence, event_index, rule_id), so
//! a replayed WAL batch re-derives byte-identical alert keys
```

Alert identity is derived entirely from its inputs: which agent, which
event, which rule. No timestamps of evaluation, no counters, no randomness.
So when a WAL batch replays — which, per [essay 2](@/posts/02-the-shape-of-a-pipeline.md),
is routine — the same alerts are re-derived with the same keys and collapse
in the database exactly like the events do.

This is the dedupe token idea from the pipeline, applied one plane up, and it
works for the same reason: identity computed from content is stable under
repetition. Purity isn't an aesthetic preference here. It's the property that
makes replay safe, and any impurity — an evaluation timestamp in the key, say
— would silently break it.

Noise suppression is the other problem, and note how differently it's
treated:

```rust
//! Noise suppression is separate from replay dedupe and deliberately
//! best-effort: an in-memory window per (rule_id, agent_id) that survives
//! neither restarts nor multi-instance deployments — the deterministic
//! alert key is what guarantees correctness, suppression only reduces
//! volume.
```

Suppression is explicitly allowed to be wrong. It lives in memory, dies on
restart, and doesn't coordinate across instances. If a backend restarts, you
might see a duplicate alert you'd have preferred to suppress. Nobody's
correctness is violated; someone is mildly annoyed.

That's a completely legitimate place to be sloppy — *provided* you're clear
about which mechanism carries the guarantee. The failure I've seen in real
systems is using the suppression cache as the deduplication mechanism, at
which point a restart doesn't produce a duplicate alert, it produces a
**missing** one, and nobody notices because the alert that didn't fire is
invisible.

Which leads directly to the subtlest line in the module:

```rust
//! volume. The check/commit split is load-bearing: evaluate() only READS
//! the window and commit() is called strictly after the alert insert
//! succeeded, so an alert whose insert failed is never remembered as
//! "already fired" and lost on the retry.
```

Evaluation reads the suppression window. It does not update it. The update
happens only after the alert has actually been written.

Get that ordering backwards — mark it suppressed at evaluation time, then
insert — and here's your incident: the database write fails, the retry
arrives, the suppression window says "already fired," and the alert is
dropped. It was never stored anywhere. The only trace is a metric counter
that doesn't match.

The general rule is worth stating carefully because it's violated everywhere:
**a record that says "I did X" must be written after X, never before.** The
window between attempt and confirmation is exactly where crashes and errors
live, and a system that has already recorded success on entering that window
cannot tell the difference between done and never-happened.

## Knowing what your data means

Now my favorite rule-writing detail, because it isn't about rules at all.
From `backend/rules/README.md`:

```
Every string condition here uses the ASCII-case-insensitive form
(`contains_i`, `eq_i`). The registry is a case-insensitive namespace, so
the case recorded in the event is the *writer's* choice, not a fact about
the key: a value that does not already exist is stored with whatever case
created it. A case-sensitive `reg_value_name eq "Debugger"` would miss
`debugger` for free, which is not a detection worth shipping.
```

Sit with "the case recorded in the event is the writer's choice, not a fact
about the key."

The Windows registry is case-insensitive but case-*preserving*. Create a
value named `debugger` and the registry stores it as `debugger` while
treating it as identical to `Debugger` for every lookup. Windows will happily
use it. Your telemetry faithfully records the lowercase form. And a rule
matching `Debugger` exactly sees nothing.

That's not a bug in the sensor — the sensor reported precisely what
happened. It's a rule that mistook an *incidental encoding* for *semantic
content*. And the bypass costs an attacker exactly one keystroke, with no
tooling and no cleverness.

You cannot find this class of bug by testing your rule, because your test
will use the canonical casing, and it will pass. You find it by asking a
question about the data itself: **for this field, which parts of the value
are meaningful and which are the writer's arbitrary choice?**

The same question, asked elsewhere, produces: paths on case-insensitive
filesystems, domain names, HTTP headers, Unicode normalization forms,
trailing dots on FQDNs, `/tmp` versus `/private/tmp` on macOS. Every one is a
place where two representations mean the same thing, and where a comparison
that doesn't know it becomes a free bypass.

The packaged rule shows what this looks like in practice — note that *both*
conditions use the `_i` form:

```json
  "where": [
    {"field": "reg_key", "op": "contains_i", "value": "\\CurrentVersion\\Run"},
    {"field": "reg_data", "op": "contains_i", "value": "\\AppData\\"}
  ],
```

The key path is case-insensitive because the registry is. But `reg_data` is
a *filesystem path the attacker chose*, and `C:\Users\bob\appdata\roaming\x.exe`
works perfectly well on Windows. Any field an adversary controls the encoding
of needs the same treatment, for the same reason.

## When healthy is a lie

Now the story that reorganized how I think about validation, and it's the
reason this essay exists.

The alerts table has an `event_type` column, an enum listing every event
type an alert can be about. It was created with 11 types. Meanwhile the
events table grew — module loads, process access, TCC, exec-maps, registry —
to 23. The alerts enum never followed.

So a rule matching on, say, `registry_value_set` produced an alert whose
`event_type` byte had no corresponding enum member. Here's what happened
next, from `backend/schema/015_alerts_registry.sql`:

```sql
--      an alert whose stored byte had no enum member. That does NOT fail
--      the INSERT — RowBinary writes the byte unvalidated — it fails on
--      READ, when the column is formatted (UNKNOWN_ELEMENT_OF_ENUM),
--      breaking SELECT * on the table with nothing logged at ingest.
```

Trace the observable state of the system. Batches are acknowledged. The
alert counter climbs. No error is logged, anywhere, by anyone. The metrics
dashboard is green. Every health check passes.

And `SELECT * FROM edr.alerts` throws.

The detection pipeline was "working" by every signal it emitted, and the
alerts were unreadable. The gap between the operation failing and anyone
finding out was bounded only by how long until someone looked at the table.
In this case, seven schema versions.

Two things are worth extracting.

The first is about **where validation lives**. RowBinary is a schema-less
binary format: values are written positionally with no names and no types on
the wire. That's what makes it fast, and the speed is real. But "no schema
on the wire" means the receiver cannot check anything — it writes the bytes
you gave it. The validation you *thought* the database was doing was never
happening; you had simply never sent it anything invalid before.

Fast serialization formats buy their speed by trusting the sender. The trust
doesn't remove the need for validation, it *relocates* it — and if you don't
consciously relocate it, it lands nowhere. Which is why the fix isn't only
the migration:

Two unit tests now pin the alerts enum's membership and the struct's column
order against the DDL file itself. The check moved into the build, because
that's the last place both sides of the contract are visible at once.

The second extraction is subtler and rather beautiful:

```sql
--      Extending the enum also HEALS rows already written that way: the
--      stored byte becomes a legal member again and reads back correctly,
--      so no repair pass is needed after this runs.
```

The old rows repair themselves. Because the byte was stored *faithfully* —
ClickHouse wrote exactly what it was given — the data was never corrupt. It
was **uninterpretable**, which is a different condition entirely. The value
was right; the dictionary needed to read it was incomplete. Extend the
dictionary and every historical row becomes readable.

That distinction — *lossless but unreadable* versus *lossy* — is worth
carrying around. Systems that store faithfully and interpret separately can
recover from interpretation bugs. Systems that normalize on the way in
cannot: they've thrown away the thing they'd need to fix it later. It's the
same instinct as [essay 3](@/posts/03-naming-things-that-move.md)'s insistence that
absence be representable. Preserve what you were given; decide what it means
as late as you can.

There's a companion hazard right next to it, mentioned in the same file:
RowBinary is *positional*, so the Rust struct's field order and the DDL's
column order are a single contract split across two files in two languages.
Get them out of step and every value shifts one column over — `severity`
lands in `state`, `agent_id` lands in `sequence` — and again, nothing errors.
Hence the comment on the struct:

```rust
/// One edr.alerts row; field order matches the DDL exactly (RowBinary).
```

A comment is not enforcement, which is why there's a test. But the pattern to
notice is that **implicit contracts need explicit tests**, and the most
dangerous contracts are the ones expressed as an agreement about *order*,
because they fail silently and totally.

## Retention makes you denormalize

One more modeling decision, driven by an unglamorous force:

```sql
    -- Context copied from the matched event at detection time, so triage
    -- answers "what ran / what was touched / where did it connect"
    -- without a join and unaffected by the events TTL.
```

An alert copies its context from the event that fired it. Normalization says
don't — store the reference, join when needed. The reason to break that rule
is stated plainly in the migration: events live 30 days, alerts live 90, and
an investigation routinely outlives its evidence.

An alert that says "rule X fired on event `(agent, 4821, 3)`" is, on day 45,
a pointer into a void. The join returns nothing. The alert is technically
still there and practically worthless.

Normalization implicitly assumes both sides of a relationship live the same
length of time. When they don't, a foreign key is a promise that expires.
**Different retention periods force denormalization**, and the copy isn't
redundancy — it's the only way the alert stays meaningful for its own
lifetime.

## Where the difficulty actually is

None of the hard parts in this essay were about detection logic. The rules
themselves are almost trivial — a few string comparisons ANDed together,
matching persistence keys that have been documented for twenty years.

The hard parts were: whether a rule can be expressed in the same language as
a query; whether alert identity survives replay; which mechanism carries the
guarantee and which is allowed to be sloppy; whether a comparison respects
the semantics of the namespace it's comparing in; whether a serialization
format validates or merely stores; whether a foreign key outlives what it
points to.

Every one of those is data modeling. And every one of them can break a
detection *without breaking anything visible* — which is the recurring theme
of this whole series and the specific reason detection is unforgiving. A
crashed system announces itself. A detection that stopped firing looks
exactly like a quiet week.

Which raises the next question. If silent failure is the enemy, and the code
runs inside kernels on machines you'll never touch, how do you ever know it
works? The next essay tackles that problem.
