# EscalationRelay - Consensus Agent-to-Human Handoff Receipts

EscalationRelay is a reusable GenLayer Intelligent Contract for AI agents that must pause before a consequential action. It records one canonical action, the named agent allowed to consume a clearance, the assigned human reviewer, a payload SHA-256 commitment, risk policy, independent evidence sources, and a bounded response deadline.

## Lifecycle

1. `open_escalation` binds the complete action and independently rendered evidence sources. Validators use a consensus-bound assessment to recommend `proceed`, `escalate`, or `inconclusive`.
2. A recommendation that needs a person becomes `handoff_pending`. Only the named reviewer can approve or reject before the deadline.
3. `consume_clearance` can only be called once by the named agent and re-derives the exact canonical action commitment.
4. Anyone can call `expire_handoff` after the deadline. Expiry always produces `expired_safe`; it never releases an action.

The contract records source identities and snapshot hashes, including validator-comparable evidence commitments. It treats rendered content as data, not instructions. It does not make a local model decision.

## Deployment

The submitted source is deployed to GenLayer Studio at
[`0xC55940bcB6116cb68Ff952E3682397fcb934F4eb`](https://explorer-studio.genlayer.com/address/0xC55940bcB6116cb68Ff952E3682397fcb934F4eb).
The deployment reached consensus and is accepted. The explorer exposes the complete read and write lifecycle:
`open_escalation`, `resolve_handoff`, `consume_clearance`, and `expire_handoff`.

## Checks

Run `node scripts/check-contract.mjs` to verify that the submitted source includes consensus assessment, SHA-256 commitments, reviewer/agent authorization, one-use consumption, and safe timeout recovery.
