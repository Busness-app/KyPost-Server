import { beforeEach, describe, expect, it, vi } from "vitest";
import { deleteDeviceEnvelope, putDeviceEnvelope } from "./pgp";
import type { DeviceEnvelope } from "../lib/deviceEnrollment";

const putJSON = vi.fn();
const deleteJSON = vi.fn();

vi.mock("./client", () => ({
  getJSON: vi.fn(),
  postJSON: vi.fn(),
  putJSON: (path: string, body: unknown) => putJSON(path, body),
  deleteJSON: (path: string, body: unknown) => deleteJSON(path, body)
}));

// stepUp derives a credential the server can verify; the shape is auth.ts's
// business, so this pins only that the step-up IS attached.
vi.mock("./auth", () => ({
  deriveCredential: async () => ({ kind: "test" }),
  credentialFields: () => ({ password: "hunter2" })
}));

const ENVELOPE: DeviceEnvelope = {
  v: 1,
  alg: "ECDH-P256+HKDF-SHA256+A256GCM",
  epk: "EPK",
  iv: "IV",
  ct: "CT"
};

beforeEach(() => {
  putJSON.mockReset();
  deleteJSON.mockReset();
  putJSON.mockResolvedValue({ ok: true });
  deleteJSON.mockResolvedValue({ ok: true });
});

describe("putDeviceEnvelope", () => {
  it("writes the device slot with the id escaped and the prefix literal", async () => {
    await putDeviceEnvelope("dev:1", ENVELOPE, "hunter2");

    expect(putJSON).toHaveBeenCalledWith("/api/pgp/identity/envelope/device:dev%3A1", {
      envelope: JSON.stringify(ENVELOPE),
      password: "hunter2"
    });
  });
});

describe("deleteDeviceEnvelope", () => {
  // The route decodes the body unconditionally and 400s a bodyless request
  // rather than treating it as "no credential needed" — so the credential must
  // travel in the body, not as a query parameter.
  it("sends the step-up in the body", async () => {
    await deleteDeviceEnvelope("dev:1", "hunter2");

    expect(deleteJSON).toHaveBeenCalledWith("/api/pgp/identity/envelope/device:dev%3A1", {
      password: "hunter2"
    });
  });
});
