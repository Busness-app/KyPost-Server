// Decrypts a one-time pickup message in the recipient's browser.
//
// Served as a standalone file rather than bundled: the page that loads it is
// rendered by the Go server for a recipient who has no account here, so it is
// outside the SPA entirely. It cannot import from src/lib/pickupCrypto.ts,
// which is why the base64 helpers below are repeated — about twenty lines,
// against pulling the whole app bundle onto a page that shows one message.
//
// The decryption key is in location.hash. Browsers never send a fragment to
// the server, so the key reaches this script without the server that built
// the link ever receiving it on the fetch.
(function () {
  "use strict";

  var script = document.currentScript;
  var id = script.getAttribute("data-pickup-id");
  var token = script.getAttribute("data-pickup-token");

  var statusEl = document.getElementById("status");
  var bodyEl = document.getElementById("body");
  var subjectEl = document.getElementById("subject");
  var noticeEl = document.getElementById("notice");

  function fail(message) {
    statusEl.className = "err";
    statusEl.textContent = message;
  }

  function fromBase64(value) {
    return Uint8Array.from(atob(value), function (c) {
      return c.charCodeAt(0);
    });
  }

  function fromBase64Url(value) {
    var padded = value.replace(/-/g, "+").replace(/_/g, "/");
    while (padded.length % 4 !== 0) {
      padded += "=";
    }
    return fromBase64(padded);
  }

  // HTML bodies are rendered as TEXT, never as markup. This page has no
  // sanitizer available, and the content is written by whoever sent the
  // message — inserting it as HTML would be a script-injection sink on this
  // origin. DOMParser does not execute anything it parses, so this extracts
  // readable text without running the sender's markup.
  function toPlainText(value, mode) {
    if (mode !== "html") {
      return value;
    }
    try {
      var parsed = new DOMParser().parseFromString(value, "text/html");
      return parsed.body ? parsed.body.textContent || "" : value;
    } catch (e) {
      return value;
    }
  }

  var fragmentKey = (window.location.hash || "").replace(/^#/, "").trim();
  if (!fragmentKey) {
    // The single most likely real-world failure: corporate mail security
    // products (Safe Links, Proofpoint, Mimecast) rewrite inbound URLs and
    // some drop everything after the '#'. Say so, because "decryption
    // failed" would send the recipient chasing the wrong problem.
    fail(
      "This link is missing its decryption key. That usually means a mail security product rewrote the link. " +
        "Ask the sender to resend it, or open the original message in a different mail client."
    );
    return;
  }

  if (!window.crypto || !window.crypto.subtle) {
    fail("This browser cannot decrypt the message (WebCrypto is unavailable, which usually means an insecure connection).");
    return;
  }

  fetch("/pickup/" + encodeURIComponent(id) + "/blob?t=" + encodeURIComponent(token), {
    cache: "no-store"
  })
    .then(function (response) {
      if (response.status === 410) {
        throw new Error("This message has already been viewed, or the link has expired.");
      }
      if (response.status === 403) {
        throw new Error("This link is invalid or has expired.");
      }
      if (!response.ok) {
        throw new Error("Could not fetch the message (" + response.status + ").");
      }
      return response.json();
    })
    .then(function (sealed) {
      var rawKey = fromBase64Url(fragmentKey);
      if (rawKey.length !== 32) {
        throw new Error("The key in this link is malformed.");
      }
      return window.crypto.subtle
        .importKey("raw", rawKey, "AES-GCM", false, ["decrypt"])
        .then(function (key) {
          return window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: fromBase64(sealed.iv) },
            key,
            fromBase64(sealed.ciphertext)
          );
        });
    })
    .then(function (plain) {
      var contents = JSON.parse(new TextDecoder().decode(plain));
      if (contents.subject) {
        subjectEl.textContent = contents.subject;
        document.title = contents.subject;
      }
      statusEl.hidden = true;
      bodyEl.hidden = false;
      bodyEl.textContent = toPlainText(contents.body || "", contents.mode);
      noticeEl.hidden = false;
      // Drop the key from the address bar so it does not sit in browser
      // history or get shoulder-surfed. The message is already decrypted in
      // memory; a reload would correctly fail, since the link is one-time.
      if (window.history && window.history.replaceState) {
        window.history.replaceState(null, "", window.location.pathname);
      }
    })
    .catch(function (err) {
      // An AES-GCM failure here means the key does not match the ciphertext,
      // which for a link that carried a key means it was altered in transit.
      var message = err && err.message ? err.message : "";
      if (!message || err instanceof DOMException) {
        message = "Could not decrypt this message. The link may have been altered.";
      }
      fail(message);
    });
})();
