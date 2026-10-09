import { afterEach, describe, expect, it } from "vitest";
import { startRecordingTelemetry, type RecordingTelemetry } from "@azx-pbc/telemetry/testing";
import { GATEWAY_OUTCOMES } from "@azx-pbc/shared";
import {
  ADMISSION_DENIAL_REASONS,
  CUT_CHARGE_BASES,
  INSTR_GATEWAY_ADMISSION_DENIED,
  INSTR_GATEWAY_CALLS,
  INSTR_GATEWAY_CUT_CHARGES,
  INSTR_GATEWAY_DURATION,
} from "@azx-pbc/shared/telemetry";
import { meterAdmissionDenied, meterCutCharge, meterGatewayCall } from "./usage.js";

/**
 * `helix.gateway.calls` / `helix.gateway.duration` (ADR-0037 decision 8).
 *
 * The cardinality rules are the point. `userOid` is unbounded *and* personal
 * data — it belongs in the ledger, under the lawful basis ADR-0021 reasoned
 * about, and never on a metric label in a retained backend. `appId` is bounded
 * by the tenant and is the per-app breakdown the ADR wants, but only on the
 * counter.
 */

let recording: RecordingTelemetry | null = null;

afterEach(async () => {
  await recording?.restore();
  recording = null;
});

const CALL = { appId: "app-1", capability: "llm" as const };

describe("meterGatewayCall", () => {
  it("carries exactly capability, outcome and appId on the counter", async () => {
    recording = startRecordingTelemetry();
    meterGatewayCall({ ...CALL, outcome: "ok", durationMs: 12 });

    const point = (await recording.metrics()).find((p) => p.name === INSTR_GATEWAY_CALLS);
    expect(Object.keys(point?.attributes ?? {}).sort()).toEqual([
      "helix.app_id",
      "helix.capability",
      "helix.outcome",
    ]);
  });

  it("omits appId from the histogram, per the ADR's table", async () => {
    // A bucket set per app multiplies the series count by the tenant's app
    // count, for a question nobody asks of a latency distribution.
    recording = startRecordingTelemetry();
    meterGatewayCall({ ...CALL, outcome: "ok", durationMs: 12 });

    const point = (await recording.metrics()).find((p) => p.name === INSTR_GATEWAY_DURATION);
    expect(Object.keys(point?.attributes ?? {}).sort()).toEqual([
      "helix.capability",
      "helix.outcome",
    ]);
  });

  it("never records a duration for a call that measured nothing", async () => {
    // `quota_blocked` and `forbidden` are refused before anything is dialled,
    // and the app-data path does not time itself. A zero there would drag every
    // percentile toward zero and make the histogram report that the platform is
    // fast when what it did was refuse — the same failure decision 5 names
    // about a span ended at response headers.
    recording = startRecordingTelemetry();
    meterGatewayCall({ ...CALL, outcome: "quota_blocked" });
    meterGatewayCall({ appId: "app-1", capability: "fetch", outcome: "forbidden" });
    meterGatewayCall({ appId: "app-1", capability: "data", outcome: "ok" });

    const points = await recording.metrics();
    expect(points.filter((p) => p.name === INSTR_GATEWAY_CALLS)).toHaveLength(3);
    expect(points.filter((p) => p.name === INSTR_GATEWAY_DURATION)).toHaveLength(0);
  });

  it("puts no user identifier on any data point", async () => {
    recording = startRecordingTelemetry();
    for (const outcome of GATEWAY_OUTCOMES) {
      meterGatewayCall({ ...CALL, outcome, durationMs: 5 });
    }

    for (const point of await recording.metrics()) {
      const keys = Object.keys(point.attributes);
      for (const banned of [
        "userOid",
        "helix.user_oid",
        "userName",
        "userEmail",
        "path",
        "model",
      ]) {
        expect(keys, `${point.name} must not carry ${banned}`).not.toContain(banned);
      }
    }
  });

  it("carries exactly appId and usage basis on cut-charge counter", async () => {
    recording = startRecordingTelemetry();
    for (const basis of CUT_CHARGE_BASES) {
      meterCutCharge({ appId: "app-1", basis });
    }

    const points = (await recording.metrics()).filter((p) => p.name === INSTR_GATEWAY_CUT_CHARGES);
    expect(points).toHaveLength(CUT_CHARGE_BASES.length);
    for (const point of points) {
      expect(Object.keys(point.attributes).sort()).toEqual(["helix.app_id", "helix.usage.basis"]);
      expect(CUT_CHARGE_BASES).toContain(point.attributes["helix.usage.basis"]);
      expect(Object.keys(point.attributes)).not.toContain("helix.user_oid");
    }
  });

  it("carries exactly capability, reason and appId on admission-denied counter", async () => {
    recording = startRecordingTelemetry();
    for (const reason of ADMISSION_DENIAL_REASONS) {
      meterAdmissionDenied({ appId: "app-1", capability: "llm", reason });
    }

    const points = (await recording.metrics()).filter(
      (p) => p.name === INSTR_GATEWAY_ADMISSION_DENIED,
    );
    expect(points).toHaveLength(ADMISSION_DENIAL_REASONS.length);
    for (const point of points) {
      expect(Object.keys(point.attributes).sort()).toEqual([
        "helix.app_id",
        "helix.capability",
        "helix.reason",
      ]);
      expect(ADMISSION_DENIAL_REASONS).toContain(point.attributes["helix.reason"]);
      expect(Object.keys(point.attributes)).not.toContain("helix.user_oid");
    }
  });

  it("only ever emits outcomes from the ledger's own vocabulary", async () => {
    // Sharing `GATEWAY_OUTCOMES` with the ledger is what stops the counter and
    // the audit trail describing the same event differently. They are never
    // reconciled (decision 9) — but they should at least speak one language.
    recording = startRecordingTelemetry();
    for (const outcome of GATEWAY_OUTCOMES) {
      meterGatewayCall({ ...CALL, outcome, durationMs: 5 });
    }

    for (const point of await recording.metrics()) {
      expect(GATEWAY_OUTCOMES).toContain(point.attributes["helix.outcome"]);
    }
  });
});
