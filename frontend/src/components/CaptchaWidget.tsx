import { useEffect, useId, useRef } from "react";

// CaptchaWidget renders whichever CAPTCHA provider the backend has
// configured (see GET /api/auth/captcha-config), loading that provider's
// script on demand — no third-party script is ever loaded unless an
// operator has actually turned CAPTCHA on. Both supported providers
// (Cloudflare Turnstile, Friendly Captcha) auto-render any element with
// their marker class + data-sitekey once their script loads, and invoke a
// named global callback with the resulting token — the declarative
// approach documented by both, rather than each provider's separate
// imperative render API.
export type CaptchaProvider = "turnstile" | "friendly";

type CaptchaWidgetProps = {
  provider: CaptchaProvider;
  siteKey: string;
  onToken: (token: string) => void;
};

// Third-party script sources, each pinned and — where the CDN serves immutable
// versioned artifacts — checked with Subresource Integrity.
//
// integrity matters most for jsDelivr: it serves arbitrary npm and GitHub
// content, so without a hash the login page executes whatever that URL returns
// on the day. The value below was computed from the pinned artifact
// (friendly-challenge@0.9.12/widget.module.min.js, 40904 bytes) and verified
// reproducible across two independent fetches. Bumping the version REQUIRES
// recomputing it:
//
//   curl -fsSL <url> | openssl dgst -sha384 -binary | openssl base64 -A
//
// Turnstile has no integrity hash on purpose: Cloudflare serves that URL as a
// rolling, deliberately-unversioned loader, so pinning a hash would break the
// widget the next time they ship. Its origin is at least named explicitly in
// the CSP, and only when Turnstile is the configured provider.
const PROVIDER_SCRIPT: Record<CaptchaProvider, { src: string; markerAttr: string; integrity?: string }> = {
  turnstile: {
    src: "https://challenges.cloudflare.com/turnstile/v0/api.js",
    markerAttr: "data-kypost-captcha-turnstile"
  },
  friendly: {
    src: "https://cdn.jsdelivr.net/npm/friendly-challenge@0.9.12/widget.module.min.js",
    markerAttr: "data-kypost-captcha-friendly",
    integrity: "sha384-dBo7K67Ql3VCbsnnnv4Ooln0dQckF64+vgnSdbIYj/8HAT4XvlIJkmgwmOx1HWgu"
  }
};

function loadCaptchaScript(provider: CaptchaProvider) {
  const { src, markerAttr, integrity } = PROVIDER_SCRIPT[provider];
  if (document.querySelector(`script[${markerAttr}]`)) {
    return;
  }
  const script = document.createElement("script");
  script.src = src;
  script.async = true;
  script.defer = true;
  if (integrity) {
    script.integrity = integrity;
    // Required for SRI on a cross-origin script: without it the response is
    // opaque and the browser cannot check the hash, so it refuses to run it.
    script.crossOrigin = "anonymous";
  }
  if (provider === "friendly") {
    script.type = "module";
  }
  script.setAttribute(markerAttr, "true");
  document.head.appendChild(script);
}

declare global {
  interface Window {
    [callbackName: `__kypostCaptchaToken_${string}`]: ((token: string) => void) | undefined;
  }
}

export function CaptchaWidget({ provider, siteKey, onToken }: CaptchaWidgetProps) {
  const rawId = useId().replace(/[^a-zA-Z0-9]/g, "");
  const callbackName = `__kypostCaptchaToken_${rawId}` as const;
  const onTokenRef = useRef(onToken);
  onTokenRef.current = onToken;

  useEffect(() => {
    window[callbackName] = (token: string) => onTokenRef.current(token);
    loadCaptchaScript(provider);
    return () => {
      delete window[callbackName];
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [provider, callbackName]);

  if (provider === "turnstile") {
    return <div className="cf-turnstile" data-sitekey={siteKey} data-callback={callbackName} />;
  }
  return <div className="frc-captcha" data-sitekey={siteKey} data-callback={callbackName} />;
}
