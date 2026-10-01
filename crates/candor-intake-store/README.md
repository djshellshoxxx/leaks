<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# candor-intake-store

This crate is the Candor Intake Store (component C-08), licensed AGPL-3.0-or-later. It owns the `IntakeStore` trait, which is the persistence interface of the intake zone, and ships two implementations:

- **`PgIntakeStore`** is for production. It uses PostgreSQL 16 over a Unix socket through sqlx 0.9, with static SQL only, row-level security (RLS) and DB-enforced invariants.
- **`MemoryStore`** is for tests of other crates. It follows the same rules and passes the same conformance suite.

Specs: `specs/09-DATABASE.md` §5.1/§8/§10/§11, `specs/07-BACKEND.md` §5.3/§5.4/§6.3, `specs/08-API.md` RL-01..RL-12 and SA-19/SA-20. Decisions and residual risks are in [SPEC-NOTES.md](SPEC-NOTES.md).

## Guarantees

- The store never reads a wall clock. It stores only UTC day numbers (`Day`) supplied by the caller's `SourceClock`.
- No timestamp, time, interval or network-typed column exists anywhere in the intake DB. A static lint and a live lint enforce this.
- Envelopes are fixed-shape groups (main, bundle, identity) with no account reference; accounts are created and updated by their own operations, which chaff uses too (ADR-052(1)/(2)).
- Source actions never update an account row. Every source-linkable row is rewritten at each fixed import slot (`uniform_rewrite`), so row `xmin` reveals only the slot (ADR-052(14)). Quota lives in process RAM only.
- Expected outcomes (duplicates, existing accounts) never raise a server-side error, so PostgreSQL logs nothing about source actions.
- Real and chaff envelopes are stored identically.
- No kind, tier or arrival date leaves through RL-02.
- Source deletions append a K31-signed, hash-chained deletion-list entry in the same transaction. The list is append-only for the application role; only the maintenance role prunes, never the head. Inserts must extend the chain (DB trigger). Acknowledgements (RL-11) and pushed lists (RL-12) are accepted only against a Z-CORE-signed head; the maintenance process re-verifies that signature before it prunes anything. A restored store, and the PostgreSQL store at every process start, refuses service until a verified, contiguous, untruncated Z-CORE list that chains to the last verified head (carried in backups) is applied.
- The Key Directory snapshot high-water mark never decreases. The store checks this, and a DB trigger enforces it as well.
- The fetch-all reply set is served as fixed 64 × 70,000-byte pages. The page count is a power of two fixed by the configuration, every requester gets byte-identical pages, and each import slot adds exactly K persistent entries (real replies topped up with dummies), so diffs between rebuilds reveal nothing about reply volume. Dummy sizes are drawn from a configured public bucket distribution, never copied from real replies, and every stored reply (real or dummy) has the canonical length of its bucket.
- Errors and `Debug` output are content-free.
- Sealed attachment bundles arrive from the sealer as sealed memfds over `istore.sock` (`staged::StagedReceiver`, hand-over protocol 2, AUD-RM2-STO-29). The store answers with 33-byte acknowledgements `u8 code ‖ sha256(bundle)`:
  - `0x02 ‖ h` once its copy is durable in the blob root;
  - then `0x01 ‖ h` after the envelope naming the blob is committed, or `0x00 ‖ 0³²` on refusal.

  The sealer accepts nothing else. Both sides cap a bundle at 4 GiB (`STAGED_MAX_BUNDLE_LEN`). Details are in SPEC-NOTES decisions 31–33.

## API sketch

```rust
use candor_intake_store::*;

// Production: migrate with `candorctl migrate` (OS user candor-migrate), then:
let cfg = DeadDropConfig { slots_per_day: 4, per_slot: 16, max_pending: 5_000,
                          dummy_bucket_weights: DEFAULT_DUMMY_BUCKET_WEIGHTS };
let store = PgIntakeStore::open(opts.username("candor_istore").database(db), tenant, 8,
                                cfg, Box::new(real_format_dummies)).await?;  // starts restore-pending
store.init(tenant, kdf_salt).await?;
store.apply_pushed_deletion_list(&core_copy, &signed_core_head, &core_pk, &k31_pk, &CoreReplyHasher, today).await?;
let acct = store.create_account(new_account, today).await?;     // separate from envelopes
let r = store.commit_envelope(CommitEnvelope { objects: [main, bundle, identity], /* … */ }).await?;
// At each fixed import slot:
let batch = store.claim_batch(today, ClaimLimits { max_objects: 500, max_bytes: MAX_CLAIM_BYTES }).await?;
let ack = store.ack_batch(batch.batch_no, &digests).await?;     // then delete ack.blobs_to_delete
store.apply_replies(today, replies).await?;
store.rebuild_published_set(slot).await?;                       // K new entries
store.acknowledge_deletion_head(&signed_core_head, &core_pk).await?;     // RL-11
store.uniform_rewrite(slot, &counter_deltas, &active_accounts).await?;   // last
vacuum_after_rewrite(&maint_opts).await?;   // as candor_intake_maint (database owner, no table), right after
// Daily job, separate process as candor_intake_maint:
PgIntakeMaintenance::open(maint_opts.clone(), tenant, core_pk).await?.prune_deletion_list(today).await?;
// Daily, fixed maintenance window (intake serving paused), as candor_intake_maint:
vacuum_full_daily(&maint_opts).await?;

// Tests of other crates:
let mem = MemoryStore::new()?;
```

## Tests

```sh
cargo test -p candor-intake-store                                          # PG tests return early (CANDOR_TEST_PG unset)
crates/candor-intake-store/scripts/pg-test.sh                              # throwaway PG 16 cluster + full suite
crates/candor-intake-store/scripts/pg-test.sh cargo test -p candor-intake-store --test pg
```

`scripts/pg-test.sh` works as follows:

1. It creates the unprivileged OS user `pgtest` if needed and runs `initdb` as that user in a private 0700 directory.
2. The cluster listens only on a Unix socket, with peer authentication through an ident map.
3. It applies the intake settings: `wal_level=minimal`, `max_wal_senders=0`, `archive_mode=off`, `track_commit_timestamp=off`, `log_min_messages=panic`, no SQL text or bind parameters in logs, and (default profile `CANDOR_TEST_PG_PROFILE=intake`) `track_counts=off` and `autovacuum=off`; `CANDOR_TEST_PG_PROFILE=stock` keeps both on.
4. It exports `CANDOR_TEST_PG=<socket dir>` and `CANDOR_TEST_PG_LOG=<0600 server log>` (only so a test can prove that no ERROR line is written), runs the given command, and always deletes the cluster, and the OS user if it created it, afterwards.
