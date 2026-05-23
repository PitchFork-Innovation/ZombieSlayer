# Page 09 — Remediation recommendations

**Component under test:** `src/zombieslayer/remediation.py` — for each kind
of finding, the engine should produce a recovery-action recommendation
(e.g., "rotate the leaked credential," "purge the poisoned memory entry,"
"alert on the source URL").

**Schema variant:** mapping. Each entry pairs a finding (or finding set) with
the expected recommended action(s).

**Volume:** 12 entries — 12 finding→action mappings.

Labels in [`evals/labels/09_remediation.yaml`](../labels/09_remediation.yaml).

---

## rm-001 — single `override_ignore` finding

**Finding:** override_ignore (single, score 0.9)
**Expected recommendation:** quarantine the source content; do not propagate to memory or summary; flag the source URL for source-reputation tracking.

---

## rm-002 — `system_prompt_reveal` finding

**Finding:** system_prompt_reveal (score 0.9)
**Expected recommendation:** scrub any outgoing message that contains the system prompt; log the attempt with timestamp; alert security team via configured channel.

---

## rm-003 — `secret_exfil` with detected URL

**Finding:** secret_exfil + url_side_channel
**Expected recommendation:** rotate the credential type referenced (API key / OAuth token / password); add the destination URL to the egress denylist; alert the platform security team.

---

## rm-004 — `persist_memory` finding

**Finding:** persist_memory (score 0.8)
**Expected recommendation:** block the memory write; purge any prior persisted entries matching the same source; flag source as memory-targeting attacker.

---

## rm-005 — `persist_future` finding

**Finding:** persist_future (score 0.85)
**Expected recommendation:** block the memory write; mark the source for cross-session tracking; verify that no earlier session's persisted memory references the same source.

---

## rm-006 — `hidden_html_comment` finding

**Finding:** hidden_html_comment
**Expected recommendation:** strip HTML comments before further processing; consider stripping all hidden-content patterns from the source; flag the source as concealment-using.

---

## rm-007 — `zero_width_chars` finding

**Finding:** zero_width_chars
**Expected recommendation:** normalize the text (remove zero-width / bidi characters); re-scan the normalized text; report unicode-evasion attempt to security team.

---

## rm-008 — `fake_system_tag` finding

**Finding:** fake_system_tag (score 0.75)
**Expected recommendation:** strip role-tag tokens; do not interpret as a real role boundary; flag source as role-impersonation-attempting.

---

## rm-009 — `homograph_mixed_script` finding

**Finding:** homograph_mixed_script + override_ignore (decoded from homograph normalization)
**Expected recommendation:** normalize text to ASCII (or NFKC); flag source as obfuscation-using; consider tightening the source's trust level.

---

## rm-010 — compound: override + exfil + URL

**Findings:** override_ignore + secret_exfil + url_side_channel (score 0.99)
**Expected recommendation:** rotate the referenced credential; quarantine source permanently; add the exfil URL to the egress denylist; alert security; trigger an incident-response runbook (high-severity).

---

## rm-011 — `supply_chain_signature` finding

**Finding:** supply_chain_signature (score 0.85)
**Expected recommendation:** quarantine source; check provenance (where was this content retrieved from?); flag the source's package/feed for review; consider blocking the upstream registry.

---

## rm-012 — benign content (control)

**Findings:** none (score 0)
**Expected recommendation:** no recovery action; pass through.
