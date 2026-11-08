# Claude review: Box `b7f73ed`

Read-only source review of the relay-test change in `2dbdf48..b7f73ed`, with the
allocation regression in `5970bc8..2dbdf48` also inspected. Claude did not edit,
build, run tests, or perform network/deployment actions. The host ran the checks
recorded in `AUDIT-INTEROP.md` §17.

An initial review of the first deterministic-test draft returned **CHANGES
REQUIRED**: waiting for more than eight queued writes could be impossible if the
held first batch contained at least 56 events, and a timeout could leave the
store gate closed during writer teardown. The final candidate was revised before
this follow-up review.

No blocking findings in the final candidate.

**Previous findings resolved.** The test sends exactly `MAX_INFLIGHT_WRITES`
(64) events. The writer takes a first batch of `k` events and the held store
records them before blocking, so `writer_queued().0 + store.order.len()` reaches
64 regardless of `k`. `ReleaseOnDrop` is declared after the relay, routes,
socket and events and before the first send, so it opens the gate before those
objects are dropped if either wait panics. Calling `release` again is safe and
permanent.

**Group commit is deterministic.** After release, the next batch contains
`64-k` events. The largest of the first two batches is therefore at least
`max(k, 64-k)`, whose minimum is 32, so the retained `largest_batch > 8`
assertion holds for every first-batch size. A connection that waited for each
`OK` before reading ahead would time out, and a writer committing one event at a
time would fail the assertion.

**No new deadlock, race or kernel-buffer issue found.** The first 64 frames are
sent while the server is still reading. The remaining traffic resumes only
after release. The queue/order locks are held briefly, and the held writer is a
standard thread rather than a runtime worker.

**Allocation regression unaffected.** The new change is confined to test code in
`event_relay.rs`; it does not alter `allocation_witness.rs` or its verified
forwarding, token-consumption, guard-lifetime or reconciliation behaviour.

The scheduler-dependent aggregate batch-count assertion remains removed. The
500 distinct successful replies, exact event-ID set, writer event count and
in-flight-cap assertions are retained.

OPEN PR
