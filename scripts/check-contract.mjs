import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const source = readFileSync(new URL("../contracts/escalation_relay.py", import.meta.url), "utf8");
for (const marker of [
  "class EscalationRelay(gl.Contract)", "open_escalation", "resolve_handoff", "consume_clearance",
  "expire_handoff", "gl.vm.run_nondet_unsafe", "gl.nondet.web.render", "hashlib.sha256",
  "canonical_action_commitment_mismatch", "only_assigned_reviewer_can_resolve",
  "only_named_agent_can_consume", "expired_safe", "evidence_sources_must_be_distinct_domains",
]) assert.ok(source.includes(marker), `Missing ${marker}`);
assert.ok(!source.includes("hash("), "Do not use a non-cryptographic hash for commitments.");
console.log("EscalationRelay lifecycle and commitment checks passed.");
