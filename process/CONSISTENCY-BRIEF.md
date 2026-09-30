# Final Consistency Pass Brief (round 3)

Inputs: specs/DECISIONS.md (ADR-001..047; ADR-047 is new and binding: Source App encrypted vault, follow-up dates encrypted, CHAFF ENVELOPES adopted, freshness bounds, IDENTIFIED over onion allowed, per-locale wordlists, Desk case-key cache for vault recovery, PER-CASE METADATA ERASURE adopted, intake deletion list, MANAGED customer-held audit key, constants registry owned by 39/tools).
Cross-document requests: the "Cross-document requests" sections of process/DISP-G1.md … DISP-G8.md. Grep them for your document numbers.

Task: for YOUR assigned documents only, apply (1) every cross-document request addressed to them, (2) ADR-047, (3) fix any remaining contradictions with DECISIONS.md you notice (timers 20 min/2 h, 16 recipient slots, k=10 monthly, fixed import schedule, 10-word passphrase, Argon2id 64 MiB, port/interface names as defined in 16 and 06). Follow WRITER-BRIEF.md format rules; new requirements use next free IDs; never renumber; withdrawn rows prefixed "WITHDRAWN (ADR-0xx):". Where a request was rejected by an ADR, skip it and log it.
Output: append to process/DISP-FINAL-<agent>.md a table | Request (from DISP-Gx) | Target doc | Action (Applied/Skipped+reason) |.
Final message ≤150 words.
