+++
title = "Cutting the Network from Inside"
date = "2026-09-02"
draft = false
description = "Network isolation is a distributed-systems problem: preserve control, apply policy atomically, and design a safe path back."

[extra]
toc = true
keywords = "EDR network isolation, host containment, firewall policy, endpoint response"

[taxonomies]
tags = ["EDR", "Architecture", "Networking", "Response"]
+++

*Building an EDR from scratch, essay 5 of 13.*

Network isolation is the response action that looks easiest and is hardest.

The pitch is simple enough that a manager can specify it in one sentence: a
machine is compromised, cut it off the network, contain the damage. Every
commercial EDR has the button. It usually has a reassuring icon.

And the implementation is a paradox with a very short fuse. You are going to
tell a machine to stop talking to the network — using the network. The
instruction to sever connectivity arrives over the connectivity it severs.
If you do the obvious thing, the machine goes silent mid-sentence and stays
silent forever, because the only channel you had for saying "actually, let
it back on" was the one you just cut.

That's not a race condition you'll catch in code review. It's a machine that
needs someone to physically walk to it. Multiply by the number of hosts an
analyst can click through in a panic, and a containment feature becomes an
outage.

Everything interesting about this action follows from that one problem.

## Isolation isn't "block everything"

The naive version — drop all traffic — is unusable, and the exemption list
tells you a lot about how networks actually work. From
`shipper/src/isolate.rs`:

```rust
//! Self-harm is the whole problem (see proto IsolateHostAction): a
//! ruleset that fails to exempt the agent's own backend endpoint bricks
//! the host — isolated, unreachable, and un-un-isolatable. So the
//! executor refuses to apply ANYTHING unless it can parse and resolve
//! the backend endpoint, and validates every operator CIDR before the
//! kernel is touched (all-or-nothing).
```

Start with the refusal, because it's the most important line. If the agent
cannot determine its own backend endpoint, it applies *nothing at all*. Not
a best-effort ruleset, not a partial block. The action fails and reports
failure.

This runs against a reflex most of us have — partial progress feels
responsible, and "we contained most of it" sounds better than "we did
nothing." Here it's precisely backwards. A partially-applied isolation is a
bricked host, which is strictly worse than an uncontained one: you've lost
the machine *and* your visibility into it, and now the incident includes a
site visit. When a failure mode is unrecoverable, refusing to start is the
safe branch.

The rest of the exemption list is a tour of the protocols people forget:

```rust
//! kernel is touched (all-or-nothing). The exemption set is deliberately
//! minimal: backend endpoint, loopback, DHCP (v4 + v6, or lease expiry
//! takes the host off the network underneath the containment), and IPv6
//! neighbor discovery (ARP lives below IP, but NDP rides ICMPv6 — block
//! it and v6 connectivity dies, including to the backend).
```

**Loopback** — block it and half the software on the machine breaks, because
local services talk to each other over `127.0.0.1` constantly. You'd contain
the host by breaking it.

**DHCP** is the one that gets people, and it's a lovely example of a
time-delayed failure. Block DHCP and everything works fine. For hours. Then
the lease expires, the renewal is blocked, the interface loses its address,
and the host drops off the network entirely — including the exempted backend
path, which was exempted by IP on an interface that no longer has one. Your
isolation silently upgrades itself to a brick, long after anyone is watching.

**IPv6 neighbor discovery** is the same trap with a protocol-layering twist.
On IPv4, address resolution is ARP, which sits *below* IP and isn't touched
by IP-layer filtering — you can block everything and ARP still works. IPv6
folded that function into NDP, which rides on ICMPv6, which *is* IP traffic.
Apply the IPv4 mental model to an IPv6 host and you block neighbor discovery,
and v6 connectivity dies — including to your backend, if it's reached over
v6. Two protocols doing the same job at different layers, and the difference
is only visible if you know the history.

## What you refuse to exempt

The omissions are more interesting than the inclusions, because each one is
a deliberate acceptance of pain:

```rust
//! it and v6 connectivity dies, including to the backend). Deliberately
//! NOT exempted: established flows (an active C2 session must die) and
//! DNS (re-resolution would open a tunnel; backend IPs are pinned at
//! apply time — a backend failover during isolation needs an operator
//! allow_cidrs entry planned ahead).
```

**Established flows must die.** Almost every firewall ruleset on earth
begins with "allow established and related" — it's the first line of every
tutorial, because without it stateful protocols break. But an active C2
session *is* an established connection. Exempt established flows and you have
built a containment that specifically permits the thing you're containing.
The attacker's live shell survives; only their ability to open *new*
connections is blocked. This is, I'd bet, a real bug in real products.

**DNS must die**, which hurts more than it sounds. Blocking name resolution
breaks a lot of software in confusing ways. But DNS is a general-purpose
bidirectional channel that every network permits by default — DNS tunneling
is a mature, tooled technique, not a curiosity. Leaving a hole for it
because "it's just name resolution" defeats the exercise.

The cost is stated plainly rather than hidden: backend IPs are pinned as
addresses at the moment of application, so if the backend fails over to a
different address while a host is isolated, that host can't follow, and
recovering it needs a CIDR that an operator planned in advance. That's a
genuine operational constraint. Writing it down in the module header, next to
the decision that causes it, is what separates an accepted trade-off from a
future incident report.

## Half-applied is worse than not applied

Since a partially-applied ruleset is the disaster case, atomicity isn't a
nice-to-have. There must never be an instant where the block-everything rule
exists and the exemption doesn't.

What I find genuinely satisfying is that all three platforms provide a way to
do this, and all three arrived at it independently.

**Linux** uses an `nft -f` file load, which applies as a single transaction.

**macOS** uses PF anchors, and the sequencing is spelled out step by step:

```rust
/// sequenced so the policy only ever becomes visible complete:
/// (1) `pfctl -E` enables PF with a reference token — rules without
/// enforcement would be silent theater, PF ships disabled on macOS;
/// (2) the whole ruleset lands in the anchor via one
/// `pfctl -a edr_isolate -f -` load (an anchor load is a single commit,
/// the `nft -f` analog); (3) the main ruleset gets the anchor
/// attachment only if missing — attaching AFTER the load means the
/// first evaluation already sees the full policy;
```

Step 3 is the one to admire. The anchor is *populated first*, then attached
to the main ruleset. Attach first and there's a window — however brief —
where an empty or half-loaded anchor is live. Ordering the operations so the
dangerous window never opens is cheaper and more reliable than trying to make
the window small.

**Windows** uses the Windows Filtering Platform:

```rust
/// mutations run inside one FwpmTransaction — commit or nothing, the
/// `nft -f` atomicity.
```

Three operating systems, three unrelated APIs, one requirement. When a
constraint shows up identically across independent designs, it's usually
telling you something true about the problem rather than about the tools.

## Rules don't apply to conversations already happening

Here's the concept I'd most want a reader to take away, because it
generalizes far beyond firewalls and it's counterintuitive until it isn't.

A stateful firewall doesn't evaluate rules for every packet. That would be
expensive. Instead, the first packet of a flow is evaluated against the rules,
and the verdict is cached in a **state table**. Subsequent packets of that
flow match the state and skip rule evaluation entirely.

Which means: **changing the rules does not affect conversations already in
progress.** You install a perfect block-everything ruleset, and the attacker's
existing session sails straight through it, because that session's packets
never reach the rules at all.

```rust
/// first evaluation already sees the full policy; (4) `-F states`
/// flushes the state table, because PF consults states BEFORE rules —
/// a pre-isolation flow's state would ferry C2 packets straight past
/// the block.
```

You have to flush the state table. The ruleset is only half the enforcement;
the cached verdicts are the other half, and they're older than your policy.

Windows has the same problem and solves it as a side effect, which is a
pleasant piece of luck:

```rust
/// table and macOS anchor exactly. Adding/deleting ALE filters makes
/// BFE reauthorize established connections, so live C2 dies at apply
/// with no extra work.
```

WFP's ALE (Application Layer Enforcement) layers reauthorize existing
connections when filters change. The state invalidation is automatic.

The general shape — *a policy change must invalidate the caches that were
built under the old policy* — is everywhere once you look. Session tokens
issued before a permission was revoked. Connection pools holding
credentials rotated an hour ago. CDN caches serving content you've since
made private. In every case the new rule is correct and completely bypassed,
because something old is short-circuiting the check. Ask, always: what
already decided this, before I changed the rules?

## Living in someone else's house

An enterprise machine's firewall is not yours. It has corporate policy,
maybe a VPN client, maybe `firewalld`, maybe Docker rewriting rules whenever
a container starts. You are a guest.

The pattern that makes this survivable is an owned namespace:

```rust
/// The agent-owned nftables table (Linux). Created, flushed, and deleted
/// by name only — other tables (firewalld, docker) are never touched.
pub const TABLE_NAME: &str = "edr_isolate";
```

```rust
/// The agent-owned PF anchor (macOS) — the same owned-namespace idea as
/// the Linux table: loaded, listed, and flushed by name only. The main
/// ruleset is touched exactly once, to attach the anchor reference
/// (see render_pf_main_ruleset), never to edit other rules.
```

Windows gets the same treatment with a fixed provider and sublayer GUID. In
all three cases the rule is: everything the agent creates lives under one
name it owns, it only ever manipulates things under that name, and cleanup is
"delete my container" rather than "remove the rules I think I added."

"Touched exactly once" is the discipline that makes it work. There's one
unavoidable interaction with shared state — the anchor has to be *referenced*
from the main ruleset or it's never consulted — and that single touch is
called out explicitly, so the exception stays an exception.

This is just namespacing, the same instinct that gives you Java packages and
Kubernetes namespaces. It's worth naming as a general technique for
modifying systems you don't own: **claim a namespace, confine yourself to
it, and make removal a single operation.**

## Deciding what a reboot means

One more decision, easy to skip past, that is actually a policy question
disguised as an API flag:

```rust
/// `nft -f` atomicity. The engine session is the default non-dynamic
/// one and no filter carries FWPM_FILTER_FLAG_PERSISTENT: containment
/// outlives the agent process but not a reboot, matching the Linux
/// table and macOS anchor exactly.
```

Should isolation survive a reboot?

**Yes** is defensible: the machine was compromised, containment should be
durable, and an attacker who can reboot shouldn't be able to escape it.

**No** is what's implemented, and the reasoning is about recoverability.
Isolation that persists across reboots means a mistake — a bad rule, a
resolution failure, a mis-clicked host — needs manual intervention on the
console. Isolation that dies at reboot means the worst case has a recovery
path any user can perform, and the agent can simply re-apply it on startup if
the host is genuinely still contained.

I don't think there's a universal right answer; it depends on whether you
fear attackers with reboot access more than you fear your own mistakes at 2am.
What matters is that the question got asked and answered *the same way on all
three platforms*. WFP filters can be persistent. The agent deliberately
doesn't make them so, specifically to match the Linux and macOS behavior.

That's the discipline that keeps cross-platform systems sane. Every platform
offers slightly different capabilities, and the temptation is to use whatever
each one provides. Do that and you get three subtly different products
wearing one name, and an operator who learned the behavior on Linux is
surprised by Windows during an incident. Choosing the *same* semantics
everywhere — even when it means declining a feature — is what makes fleet
behavior predictable.

## Testing the thing you can't test

Last piece, and it's the one that made this action tractable at all:

```rust
//! Policy is separated from mechanism so the dangerous decision logic is
//! exhaustively unit-tested without ever touching a firewall:
//!   * `IsolateControl` — the OS primitive (atomically replace / remove
//!     the containment ruleset), one thin impl per platform.
//!   * `IsolateExecutor` — the pure guard/rendering logic over any
//!     `IsolateControl`, driven by a mock in tests.
```

The dangerous part of this feature isn't the firewall call. It's the
*decisions*: which exemptions to include, whether the backend resolved, what
to do about a malformed CIDR, what the ruleset text should say. All of that
is pure computation — inputs to strings — and pure computation can be tested
exhaustively, on any machine, in milliseconds, with no root and no risk.

So the rendering functions produce ruleset text that gets compared against
golden files, and the guard logic runs against a mock. The part that actually
touches the kernel shrinks to a thin layer whose only job is to hand a
prepared string to `nft`, `pfctl`, or BFE.

Which means most of this feature's correctness was established on a Linux
laptop, including the Windows and macOS behavior. Not all of it — you still
need real drills to learn things like PF's state-table ordering — but the
decision logic, which is where the bricking bugs live, is verified without a
firewall in sight.

That inversion, and how far you can push it when your target is a kernel you
cannot attach a debugger to, returns later in the series.

But first, the uncomfortable inverse of everything this series has covered so
far: not what the sensors see, but what they structurally cannot. That is
the subject of the next essay.
