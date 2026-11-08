# Claude review: Box `2dbdf48`

Read-only source review of `5970bc8..2dbdf48`; Claude did not build or run tests.
The host ran the scoped tests recorded in `AUDIT-INTEROP.md` §17.

I found no blocking issues. This was a static review: I read the diff and the current source but didn't build or run anything, so CI still has to confirm it compiles and the test passes.

**Production forwarding is unchanged.** `forward` (`crates/bothy-link/src/allocation_witness.rs:222`) now passes the old `Read`/`Advance` match to `forward_with` as a closure. The code is the same as before: same writer, the same `run` calls and the same store arguments. The pre-checks in `forward_with` (`:264`) are unchanged and still run in the same order: content type, then `try_enter` (`:279`), then `ForwardedRequest::verified`, then `consume_with` (`:291`).

**The token is still spent before any store work.** `work(routes, verified, guard)` runs only at `:295`, after `consume_with` has succeeded. Even the injected test closure can't skip the token check, because it happens inside `forward_with`. This matches the pinned vmls-core rule that services must consume `courier_token()` before acting on `request()`.

**The admission guard still lasts as long as the store work.** The `WorkGuard` is moved into the closure and then into the blocking closure (`let _guard = guard` at `:240`, `:247`, and `:693` in the test). Dropping the HTTP future while store work is queued or running therefore still keeps the capacity held, as before.

**The test models commit-then-unknown-result and fresh signed reconciliation.** In `uncertain_store_result_spends_token_and_fresh_retry_reconciles_once` (`:676`):
- **Commit then unknown result:** the closure really calls `store.advance` and then returns `WitnessError::Io` (`:702`). `run` turns that into a 503 with an empty body, which is what a writer sees when it can't tell whether the write landed.
- **Token spent:** replaying the same envelope gets a 403 with no refusal header. That can only come from `consume_with`, so the token was spent, and the store reads `seq == 1`, so the commit happened.
- **Fresh reconciliation, once:** a new token with a newly signed envelope (challenge 16) returns a receipt checked against `[16; 32]` showing `(1, NEXT)` (`:747`). The store still reads `seq == 1` afterwards, so there was no second revision.

**No new dependency or authority.** Only this one file changed, and no manifests or `Cargo.lock`. `forward_with` is private to the module. `SignatureVerifiedRequest` is already public in the pinned vmls-core rev `d9a8d24`; the code used its `writer`, `request` and `courier_token` methods before and now names the type.

**Optional extra assertions:**
1. The test doesn't check that the 503 leaves the admission counters clean. `MAX_PEER_WORK` is 2, so one leaked guard would slip past the two router calls that follow. Asserting `f.routes.allocation.inner.lock().unwrap().active == 0` after the 503 would prove from the test what I've only shown by reading the source.
2. The test checks the 503's status and empty body but doesn't confirm that the writer side would treat it as "unavailable". Running the 503 through `super::super::failure(status, &headers)` (`witness.rs:290`) and checking the result, as the neighbouring tests do, would cover that. Capture the headers before `into_body()`, and also assert there is no `REFUSAL_HEADER` on that response.

OPEN PR
