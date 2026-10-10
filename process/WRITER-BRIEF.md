# Writer Brief (shared instructions for all specification authors)

You are writing part of the Candor specification set in `/home/user/leaks/specs/`.

## Mandatory reading before writing
1. `/home/user/leaks/specs/DECISIONS.md` — fully. It is BINDING: component IDs (C-nn), threat IDs (THR-nnn), requirement prefixes per document, requirement table format, ADRs. Do not contradict it. If you believe a decision is wrong, still conform, and add a section "Open Issues for ADR revision" at the end of your document explaining why.
2. The research notes relevant to your documents in `/home/user/leaks/research/` (R1 SecureDrop/OnionShare, R2 GlobaLeaks/CoverDrop/Hush Line/commercial, R3 historical incidents INC-nn + REQ-H-nn, R4 Tor/I2P/anonymity attacks, R5 crypto/integrity/sanitization/supply chain, R6 compliance/accessibility/licensing). Use grep to find relevant sections; you need not read every file in full. Cite bibliography IDs (B-SD-, B-OS-, B-GL-, B-INC-, B-AN-, B-CR-, B-CO-) and incident IDs (INC-nn) in the Evidence column. Do not invent bibliography IDs; if you rely on knowledge not in the notes, write "Knowledge (unverified)" and keep it minimal.

## Document structure (each file)
```
# NN — Title
Status: Draft v1.0 · Edition applicability: CE / EE / both · Owner: <team>
## 1. Purpose and scope
## 2. Context and dependencies (links to other spec files by filename)
## ... substantive sections (design detail, diagrams in Mermaid or ASCII, tables)
## N. Requirements   (table in exact format from DECISIONS.md §1)
## N+1. Residual risks and limitations (honest)
## N+2. Open issues
```
- Requirements tables MUST use exactly: `| ID | Requirement | Evidence | Threats | Component | Verification |`. IDs sequential within your prefixes, 3 digits. Every security/privacy requirement has non-empty Verification.
- Be precise and implementable: concrete values (sizes, timeouts, parameters, field names, state machines), not vague adjectives. Separate teams must be able to build from it without inventing major architectural decisions.
- Honest-language rules from DECISIONS.md §0 apply: never "unhackable/perfectly anonymous/untraceable/airtight/100% secure".
- Cross-reference other documents by filename (e.g., `see 04-CRYPTOGRAPHY.md §5`). You may reference requirement prefixes owned by other docs generically but do not invent specific IDs in other documents' namespaces.
- Diagrams: Mermaid (sequenceDiagram, flowchart) inside ```mermaid blocks.
- Token efficiency: dense, tables over prose, no filler, no repetition of DECISIONS.md content beyond what is needed — reference ADR IDs instead. But do not skip required content: completeness beats brevity.

## When finished
Your final message: ≤250 words: files written, requirement ID ranges, any conflicts with DECISIONS.md, open issues. Do not paste document content.
