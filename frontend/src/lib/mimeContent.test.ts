import { describe, expect, it } from "vitest";
import { parseMimeContent } from "./mimeContent";

// This is what a client-protected account's mail actually goes through. Before
// it existed, decryptMessage handed the reader the whole MIME entity — headers,
// boundaries and all — and the render mode was then guessed by inspecting those
// bytes. Both of those are what these tests hold shut.

describe("parseMimeContent", () => {
  it("returns null for bare text so inline PGP is left alone", () => {
    // An inline-PGP message decrypts to plain text with no headers. Running it
    // through a MIME parser would find structure that was never there.
    expect(parseMimeContent("Just a plain message.\nNo headers here.")).toBeNull();
  });

  it("reads the mode off a simple text/html entity", () => {
    const raw = "Content-Type: text/html; charset=utf-8\r\n\r\n<p>Hello</p>";
    expect(parseMimeContent(raw)).toEqual({ body: "<p>Hello</p>", mode: "html" });
  });

  it("reads the mode off a simple text/plain entity", () => {
    const raw = "Content-Type: text/plain; charset=utf-8\r\n\r\nContact <admin@example.com> today";
    // The exact case the sniffing heuristics kept destroying: the Content-Type
    // says plain, so the address survives.
    expect(parseMimeContent(raw)).toEqual({
      body: "Contact <admin@example.com> today",
      mode: "plain"
    });
  });

  it("strips the MIME headers from the displayed body", () => {
    const raw = "Content-Type: text/plain\r\nMIME-Version: 1.0\r\n\r\nThe actual message.";
    const parsed = parseMimeContent(raw);
    expect(parsed?.body).toBe("The actual message.");
    expect(parsed?.body).not.toContain("Content-Type");
    expect(parsed?.body).not.toContain("MIME-Version");
  });

  it("picks the first usable part out of a multipart body", () => {
    const raw = [
      'Content-Type: multipart/mixed; boundary="abc"',
      "",
      "--abc",
      "Content-Type: text/html",
      "",
      "<p>the body</p>",
      "--abc",
      'Content-Type: application/pdf; name="invoice.pdf"',
      "",
      "%PDF-1.4",
      "--abc--",
      ""
    ].join("\r\n");
    const parsed = parseMimeContent(raw);
    expect(parsed?.mode).toBe("html");
    expect(parsed?.body.trim()).toBe("<p>the body</p>");
    expect(parsed?.body).not.toContain("%PDF");
  });

  it("skips the protected-headers legacy display part", () => {
    // This part repeats Subject/From for clients that cannot read protected
    // headers. Showing it as the body gives the reader a header dump.
    const raw = [
      'Content-Type: multipart/mixed; boundary="xyz"; protected-headers="v1"',
      "",
      "--xyz",
      'Content-Type: text/rfc822-headers; protected-headers="v1"',
      "",
      "Subject: Secret",
      "--xyz",
      "Content-Type: text/plain",
      "",
      "the real body",
      "--xyz--",
      ""
    ].join("\r\n");
    const parsed = parseMimeContent(raw);
    expect(parsed?.body.trim()).toBe("the real body");
    expect(parsed?.body).not.toContain("Subject: Secret");
  });

  it("skips named parts, which are attachments rather than the body", () => {
    const raw = [
      'Content-Type: multipart/mixed; boundary="b"',
      "",
      "--b",
      'Content-Type: text/plain; name="notes.txt"',
      "",
      "attachment text",
      "--b",
      "Content-Type: text/plain",
      "",
      "display text",
      "--b--",
      ""
    ].join("\r\n");
    expect(parseMimeContent(raw)?.body.trim()).toBe("display text");
  });

  it("recurses into a nested multipart/alternative", () => {
    const raw = [
      'Content-Type: multipart/mixed; boundary="outer"',
      "",
      "--outer",
      'Content-Type: multipart/alternative; boundary="inner"',
      "",
      "--inner",
      "Content-Type: text/plain",
      "",
      "plain version",
      "--inner--",
      "--outer--",
      ""
    ].join("\r\n");
    const parsed = parseMimeContent(raw);
    expect(parsed?.mode).toBe("plain");
    expect(parsed?.body.trim()).toBe("plain version");
  });

  it("decodes quoted-printable bodies", () => {
    const raw = "Content-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nCaf=C3=A9 =\r\nnext";
    expect(parseMimeContent(raw)?.body).toContain("next");
    expect(parseMimeContent(raw)?.body).not.toContain("=C3");
  });

  it("decodes base64 bodies as UTF-8", () => {
    const encoded = btoa(String.fromCharCode(...new TextEncoder().encode("Café ☕")));
    const raw = `Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n${encoded}`;
    expect(parseMimeContent(raw)?.body).toBe("Café ☕");
  });

  it("does not throw on malformed base64, and keeps the part", () => {
    const raw = "Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n!!!not base64!!!";
    expect(() => parseMimeContent(raw)).not.toThrow();
    expect(parseMimeContent(raw)?.body).toContain("not base64");
  });

  it("terminates on deeply nested multiparts", () => {
    // A decrypted payload is attacker-supplied by definition, so the walk has
    // to stop on its own rather than on the sender's good manners.
    let raw = "Content-Type: text/plain\r\n\r\ndeep body";
    for (let depth = 0; depth < 40; depth++) {
      const boundary = `b${depth}`;
      raw = [
        `Content-Type: multipart/mixed; boundary="${boundary}"`,
        "",
        `--${boundary}`,
        raw,
        `--${boundary}--`,
        ""
      ].join("\r\n");
    }
    expect(() => parseMimeContent(raw)).not.toThrow();
  });

  it("survives a multipart whose boundary never appears", () => {
    const raw = 'Content-Type: multipart/mixed; boundary="missing"\r\n\r\nno parts at all';
    expect(() => parseMimeContent(raw)).not.toThrow();
    expect(parseMimeContent(raw)).toEqual({ body: "", mode: "plain" });
  });

  it("tolerates bare LF line endings", () => {
    // Real mail uses CRLF, but the decrypted payload has been through a library
    // that may have normalized it.
    const raw = "Content-Type: text/html\n\n<p>lf only</p>";
    expect(parseMimeContent(raw)).toEqual({ body: "<p>lf only</p>", mode: "html" });
  });

  it("unfolds a wrapped Content-Type header", () => {
    const raw = 'Content-Type: multipart/mixed;\r\n boundary="w"\r\n\r\n--w\r\nContent-Type: text/html\r\n\r\n<b>x</b>\r\n--w--\r\n';
    const parsed = parseMimeContent(raw);
    expect(parsed?.mode).toBe("html");
    expect(parsed?.body.trim()).toBe("<b>x</b>");
  });
});
