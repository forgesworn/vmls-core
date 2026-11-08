# Codex review: Box `b7f73ed`

Read-only source review of the relay-test change in `2dbdf48..b7f73ed`, with the
allocation regression in `5970bc8..2dbdf48` also inspected. Codex did not edit,
build, run tests, or perform network/deployment actions. The host ran the checks
recorded in `AUDIT-INTEROP.md` §17.

No blocking findings.

- **First-batch sizes:** if the held first batch contains `b` events, where
  `1 <= b <= 64`, the gate condition leaves exactly `64-b` queued. For `b <= 8`,
  the next drain has at least 56 events; for `b >= 9`, the first batch already
  satisfies `largest_batch > 8`. This removes dependence on aggregate scheduling
  efficiency.
- **Timeouts, drop order and deadlock:** `ReleaseOnDrop` exists before the first
  EVENT send and drops before the socket, routes, relay and store. Either
  five-second wait can panic without leaving the writer held during teardown.
  The condition-variable predicate prevents lost wakeups, and the queue/order
  checks introduce no lock cycle.
- **Kernel buffers:** sending exactly 64 events before release avoids requiring
  the server to read beyond its cap while commits are blocked. The later
  send-all/read-all pattern retains its existing reliance on socket buffering
  for small `OK` replies and has no explicit send timeout; this is a residual
  portability limitation, not a newly introduced gate deadlock.
- **Group-commit evidence:** the test still exercises real loopback
  TCP/WebSocket transport, authentication, preparation, writer queueing and
  SQLite batch commits. It proves batching under an accumulated backlog and
  deliberately stops asserting average batching efficiency. It does not
  independently measure fsync count.
- **Ordering and backpressure:** production code is unchanged. Queue admission
  remains in frame order and socket reads remain capped; separate ordering and
  cap tests remain intact.
- **Allocation regression:** the private forwarding extraction preserves
  admission, signature verification, token consumption and guard ownership
  through blocking store work. The regression commits once before injecting I/O
  failure, checks the empty `503` and spent-token rejection, then verifies a
  fresh signed retry returns sequence 1 without another advance. The relay-test
  revision does not affect it.

Low-severity limit: fixed deadlines can still fail under extreme starvation or
storage delay. The gate removes the identified scheduler-dependent batch-count
failure, not every timing dependency.

OPEN PR
