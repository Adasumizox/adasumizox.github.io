+++
title = "The Authority Problem"
date = "2026-08-26"
draft = false
description = "Adding response turns an endpoint sensor into a remote authority. This is how commands can be authenticated, scoped, and revoked."

[extra]
toc = true
keywords = "EDR response, command authorization, key rotation, replay protection, endpoint security"

[taxonomies]
tags = ["EDR", "Architecture", "Cryptography", "Response"]
+++

*Building an EDR from scratch, essay 4 of 13.*

Up to this point, everything in this series has been read-only. Sensors
observe, the pipeline delivers, the backend stores. If the whole system were
compromised tomorrow, the damage would be a serious data breach: an attacker
learns what runs on your machines.

Now we add the letter R. Response. Kill this process, quarantine that file,
cut this host off the network.

And the moment you do that, you have built something categorically
different. You have deployed, to every endpoint in the organization, a
privileged agent that accepts instructions from the network and carries them
out. That is a description of a botnet. The only thing separating your
security tool from the worst-case incident in your company's history is the
answer to one question: **how does an endpoint know that an instruction is
legitimate?**

Get that answer wrong and your EDR becomes the most efficient lateral
movement infrastructure an attacker could ask for — pre-installed
everywhere, running as root, already trusted, already exempt from your own
monitoring.

This essay is about the answer.

## Two questions that look like one

The most common way to get this wrong is a confusion so natural that people
make it without noticing.

The agent connects to the backend over mutual TLS. Both sides present
certificates, both verify, the channel is encrypted and authenticated.
Excellent. Now a command arrives over that channel. Should the agent execute
it?

The tempting reasoning: the channel is authenticated, so the message came
from the backend, so the message is legitimate. Each step is true. The
conclusion does not follow — because "this message came from the backend" and
"a human being with authority decided this should happen" are *different
propositions*, and TLS only establishes the first.

Say it more carefully:

- **Transport security** answers: *who am I talking to right now?*
- **Authorization** answers: *who decided this should happen, and were they
  allowed to?*

A compromised backend passes the first test perfectly. It holds the
legitimate server key. Every TLS check succeeds. If the agent's only gate is
"did this arrive over the authenticated channel," then whoever owns the
backend owns every endpoint, instantly and totally.

And backends get compromised. They're internet-adjacent, they run a stack of
dependencies, they're administered by humans. Designing as though the
central server can never be breached is not a security posture, it's a hope.

## Designing for your own compromise

So the real design exercise is to assume the backend *is* compromised and
ask what an attacker can then do.

The answer this system gives is stated in the first paragraph of
`backend/src/tasking.rs`:

```rust
//! The backend is a RELAY, never an authority (see proto AgentTasking): it
//! decodes each SignedTask payload ONLY to read agent_id (routing) and
//! task_id (dedupe/ack) — it never inspects the signature, so it holds no
//! signing key and cannot mint a task an agent will run. All verification
//! is the agent's (crate::task on the shipper side).
```

Tasks are signed by an operator with an Ed25519 key. The backend never has
that key. It cannot create a valid task, cannot modify one without breaking
the signature, and — this is the elegant part — *cannot even verify one*,
because it has no reason to.

Note the deliberate refusal in "it never inspects the signature." A backend
that verified signatures would be no less secure, but it would blur the
architecture: someone would eventually add a "trusted internal task" path
for convenience, and the property would quietly die. Making the backend
structurally incapable of the check keeps the boundary honest.

So what *can* a compromised backend do? Exactly three things: withhold
tasks, delay tasks, and replay tasks it has already seen. That is a real
attack surface — a backend that silently drops every quarantine command is a
serious problem — but it is a **denial** surface, not an **execution**
surface. The attacker can prevent responses. They cannot cause them.

That distinction is the entire point of the design, and it generalizes: when
you're deciding where to put a security check, ask what each component can do
if it's fully owned. Components that *can't* do damage need less protection
than components that can. Here, the backend was demoted from a trusted
authority to an untrusted courier, and the amount of trust the system needs
to place in its most exposed component dropped to nearly zero.

## Claims versus proof

The second structural idea concerns identity, and it has the same flavor:
never accept an assertion when you can require a proof.

Every message on the wire contains an `agent_id` field. An agent connecting
to the task stream says "I am `web-07`, give me my tasks." The obvious
implementation reads the field and routes accordingly, and it is trivially
exploitable — any enrolled agent can claim to be any other agent and receive
its commands.

The fix is to treat the field as a *claim* that must match a *proof*, and
the proof is the client certificate. From
`backend/src/authn.rs`:

```rust
//!   edr-agent://<agent_id>    an agent; may publish telemetry and open a
//!                             task stream only as <agent_id>
//!   edr-operator://<name>     an operator; may submit tasks (<name> is
//!                             for audit logging)
```

The certificate carries a URI in its Subject Alternative Name, and the URI
scheme *is* the role. An `edr-agent://` certificate may open a task stream —
but only for the exact `agent_id` written into its own SAN. An
`edr-operator://` certificate may submit tasks and nothing else. An enrolled
agent, even a fully compromised one, cannot submit tasks to other agents,
because it doesn't hold a certificate with the operator scheme.

Two details in that module are worth dwelling on because they're the kind of
choice that separates a design from an implementation.

The first is *why the SAN rather than the Common Name*, which is where most
people's instinct goes:

```rust
//! Identity is a URI Subject Alternative Name, never the Subject CN: a DN
//! may carry several CNs in several string encodings (RFC 6125 deprecates
//! CN for name binding), while a scheme-scoped URI SAN is unambiguous and
//! cannot collide with the DNS SANs of a server or web-PKI cert.
```

A Distinguished Name can contain multiple CN components, in several string
encodings, and different libraries will hand you different ones. An
identifier that different parsers read differently is not an identifier —
it's a vulnerability with a waiting period. The web PKI learned this
expensively enough that RFC 6125 deprecated the practice. A scheme-scoped
URI has exactly one reading.

The second is what happens when a certificate is *ambiguous*:

```rust
//! The leaf must carry EXACTLY one EDR-scheme SAN: zero means the cert
//! was not enrolled as an EDR identity, two or more is a misissued cert
//! that could act as either — both are refused rather than guessed at.
```

A certificate holding both an agent SAN and an operator SAN is refused
outright. Not "prefer the more specific one," not "take the first" — refused.
Because a cert like that can only exist through an enrollment bug or an
attack, and in either case the correct response to "I cannot tell what this
is" is to stop. Every "pick a sensible default when the input is ambiguous"
in a security path is a place where an attacker gets to choose which
interpretation you take.

## Burning a key, not banning a name

Certificates get stolen. So there has to be a way to say "that credential is
no longer valid," and the choice of *what* you revoke turns out to encode a
philosophy.

```rust
//! The list is keyed on the certificate SERIAL (the standard CRL key),
//! not the identity: "this key is burned", so recovery is revoke the old
//! serial and mint a fresh cert for the same agent_id.
```

Revoking the *serial* says "this particular key is compromised." Revoking
the *identity* would say "this host is banned." They diverge exactly when it
matters: a laptop is stolen, you revoke, IT reimages the machine and
reissues it. Under serial-keyed revocation, the new certificate for the same
`agent_id` just works, because it's a different key. Under identity-keyed
revocation, you've permanently poisoned a hostname and now you're renaming
machines to work around your own security tool.

The general form: **revoke the credential, not the principal.** Compromise
is a property of a secret, not of the person or machine that held it.

There's also a nicely pragmatic touch — serials are compared in canonical
form, lowercase hex with leading zeros stripped, "so `openssl x509 -serial
-noout` output pastes straight into the file." Revocation is an emergency
procedure performed by a stressed human at an unpleasant hour. A format
mismatch that silently fails to revoke is a security control defeated by
usability. Meeting the operator where they already are is a security
property.

## A valid signature is not a fresh authorization

Now the deepest problem in the essay, and the one I found genuinely
surprising.

Signatures don't expire. A message signed today verifies identically in five
years — that's what makes them useful. But it means an attacker who captures
a signed message holds something permanently valid. Replay is therefore not
an edge case; it's the natural consequence of how signatures work.

Worse, in this system, replay is also *completely normal traffic*. Delivery
is at-least-once, so honest duplicates arrive routinely. The agent cannot
treat repetition as an attack, because repetition is the protocol working
correctly.

`shipper/src/task.rs` answers with a sequence of
checks, each catching what the previous one can't:

```rust
//! Every SignedTask must pass, in order: Ed25519 signature over the raw
//! payload bytes against the pinned operator key (the backend only
//! relays — it can drop or delay tasks, never mint them), payload decode,
//! agent binding (a task signed for another host is a cross-host replay),
//! freshness of issued_at (temporal replay; the window is symmetric
//! because agent clocks skew both ways), and task_id dedupe (at-least-once
//! delivery makes benign re-sends normal; the same set stops malicious
//! same-window replays).
```

Signature: was this authored by the key holder. Agent binding: was it
authored *for this host* — otherwise a task captured from one machine
replays against another. Freshness: was it authored recently, bounding how
long a captured task stays dangerous. Dedupe: have I already done this one.

Four checks, four distinct attacks, none redundant. And the freshness window
is symmetric because agent clocks drift in both directions — a detail that
sounds pedantic until a host with a fast clock rejects every legitimate task
it receives.

Then comes the case that breaks the whole scheme, and it took me a while to
even see it. From `shipper/src/config.rs`:

```rust
//! The policy lives INSIDE the signed payload, so the backend can withhold
//! or delay policy but never mint it. The central hazard is stale-policy
//! replay: a captured OLDER policy under a fresh task_id/issued_at is
//! still validly signed, so the task-level replay defenses (dedupe,
//! freshness) do not cover it.
```

Read that twice. Configuration policy is signed. An attacker captures a
policy document from six months ago — one that, say, monitored fewer
registry keys, or set a heartbeat interval so long the agent looks alive
while blind. They can't modify it; the signature would break. But they don't
need to. They wrap that genuinely-signed old policy in a *fresh envelope*
with a new task ID and a current timestamp.

Every defense passes. The signature is real. The agent binding is right. The
timestamp is current. The task ID has never been seen. The agent applies a
six-month-old policy, and the attacker has rolled back its configuration
using nothing but valid, correctly-signed messages.

The envelope was fresh. The *content* was ancient. Freshness of transmission
tells you nothing about currency of intent.

The fix has to live in the content's own semantics:

```rust
//! freshness) do not cover it. `AgentPolicy.version` monotonicity is the
//! identity guard: only version > current applies; version == current with
//! identical content is success (goal state met — idempotence under
//! at-least-once, surviving even a restart that emptied the result cache);
//! equal version with different content, or any lower version, refuses.
```

The policy carries a version, and the agent only ever moves forward. An old
policy is refused on the strength of its own contents, no matter how fresh
its wrapper.

The general lesson is one I now apply everywhere: **a signature proves
authorship, not currency.** If a document's *age* matters to its safety, the
document itself must say how old it is, in terms the recipient can order.
You cannot bolt freshness onto the transport and expect it to protect the
payload.

Notice too the treatment of the equal-version case. Same version, identical
content: success. Because under at-least-once delivery the agent will
genuinely receive the same policy twice, and the honest question isn't "did I
process this message" but "is the world in the state this message asks for."
Idempotence expressed as goal-state rather than as message-history — which
means it survives a restart that wiped every cache.

## Trusting your own disk, carefully

One last move, because it inverts a rule the rest of the system follows
strictly.

Policy has to survive restarts, so it's written to disk. Disk is not a trust
boundary — an attacker on the host can edit files. What should the agent do
at startup if the stored policy fails verification?

```rust
//! validity. Disk is untrusted storage: tamper means the load refuses and
//! the agent runs baked defaults at version 0 — never a startup failure,
//! because bricking the sensor over a corrupt config file trades
//! availability for nothing (an attacker with store write access already
//! owns the host).
```

Everywhere else in this system, bad security configuration means *fail to
start*. Here it means fall back to defaults and keep running. The reasoning
is a threat-model argument rather than a taste argument: the attacker who
can corrupt that file already has host write access. Refusing to start
doesn't deny them anything — it just kills your telemetry, which is a gift.
Running on safe defaults keeps the sensor reporting, from a host you now have
reason to look at closely.

The same header notes that load deliberately skips the freshness check,
"because freshness gates admission over the NETWORK; a policy this agent
itself admitted and persisted is durable state, not a new admission." Which
is exactly the transport-versus-content distinction again, seen from the
other side: freshness was always a property of *accepting a message*, never
of *holding a fact*.

## What authority actually requires

Strip it down and the same principle produces every decision here.

Authority must be **provable at the point of action**. Not asserted at the
point of transmission, not implied by the channel, not inherited from a
component's position in the architecture. The agent — the thing that will
actually terminate the process — has to be able to verify, from the message
in front of it and a key it already holds, that someone with the right to
order this ordered it, for this host, recently, and that it hasn't already
been done.

Everything else follows. The backend is a relay because a courier needs no
authority. Identity comes from certificates because claims need proofs.
Revocation targets serials because compromise is a property of secrets.
Policy carries a version because signatures don't age.

And the payoff is that you can say something concrete about the worst case.
If the backend falls, the attacker gets to see telemetry and to withhold
responses. They do not get to run commands on ten thousand machines. For a
system with this much power distributed this widely, being able to state that
bound — and point at the code that enforces it — is the difference between a
security tool and a liability.

Next comes the action with the largest blast radius of all: cutting a
machine off the network, over the network, without cutting the connection
you would need to undo it.
