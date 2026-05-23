# Page 11 — Topology & audit (multi-agent + logging)

**Component under test:** `src/zombieslayer/topology.py` (multi-agent
handoff graph + tainted-lineage tracking) and `src/zombieslayer/audit.py`
(append-only JSONL audit log used for compliance export).

**Schema variant:** trace. Each scenario describes a handoff sequence
and asserts (a) the topology's taint-propagation state and (b) the
shape of audit-log entries written along the way.

**Volume:** 8 scenarios — 5 topology, 3 audit-log.

Labels in [`evals/labels/11_topology_audit.yaml`](../labels/11_topology_audit.yaml).

---

## tp-001 — straight handoff with clean input

**Trace:** Agent A receives benign user query → handoff to Agent B → Agent B completes task.

**Expectation:** No taint markers anywhere in the topology graph. Audit log records two events (intake-clean, handoff-clean).

---

## tp-002 — taint enters at intake, never propagates

**Trace:** Agent A intakes web content with override → quarantined → A continues with sanitized context → handoff to Agent B.

**Expectation:** Topology marks source as tainted but Agent B's incoming briefing is clean. Taint does not propagate.

---

## tp-003 — taint propagates via handoff briefing

**Trace:** Agent A intakes web content with override → quarantine → reviewer chooses INCLUDE (override the FP) → A includes content in handoff briefing → Agent B receives.

**Expectation:** Topology marks the lineage A→B as tainted. Audit log shows: intake-quarantine, review-include, handoff-tainted.

---

## tp-004 — multi-hop taint propagation

**Trace:** A intakes tainted content (INCLUDE-reviewed) → hands off to B → B's summary references A's content → B hands off to C.

**Expectation:** Topology shows two tainted edges (A→B, B→C). C inherits the taint marker for any actions derived from B's content.

---

## tp-005 — handoff with derived action requiring source approval

**Trace:** Agent A intakes content X (quarantined). A proposes action Y with `derived_from=[X]` for the downstream agent. Handoff happens.

**Expectation:** Action Y is queued as deferred on Agent B's side. Topology graph records the deferred-edge with `pending_review_of=[X]`.

---

## au-001 — audit log shape on benign intake

**Trace:** Intake one benign content item.

**Expected log entries (JSONL, append-only):**
```json
{"event":"intake","trust":"untrusted","content_id":"...","quarantined":false,"score":0.0,"findings":[]}
```

---

## au-002 — audit log shape on quarantine + review

**Trace:** Intake malicious item → reviewer REPROCESS_CLEAN.

**Expected log entries:**
```json
{"event":"intake","trust":"untrusted","content_id":"...","quarantined":true,"score":0.92,"findings":["override_ignore","system_prompt_reveal"]}
{"event":"review","content_id":"...","action":"reprocess_clean"}
```

Each line is a standalone JSON object. No update-in-place.

---

## au-003 — audit log shape on multi-agent handoff

**Trace:** Agent A → handoff → Agent B with tainted briefing.

**Expected log entries:**
```json
{"event":"handoff","from_agent":"A","to_agent":"B","briefing_id":"...","taint_sources":["..."]}
```

`taint_sources` lists the ids of upstream tainted content. If none, the field is `[]`.
