// The download channels the Apps page lists. Data, not behaviour: when a store
// listing goes live, fill in its href and the placeholder becomes a link.

type ClientPlatform = {
  name: string;
  blurb: string;
  /** A channel without an href is "coming soon" and renders as a placeholder. */
  channels: ReadonlyArray<{ label: string; href?: string }>;
};

const GITHUB = "https://github.com/Busness-app";

export const CLIENT_PLATFORMS: ReadonlyArray<ClientPlatform> = [
  {
    name: "Android",
    blurb: "Native app with push notifications and device pairing.",
    channels: [
      { label: "Google Play" },
      { label: "F-Droid" },
      { label: "GitHub Releases", href: `${GITHUB}/KyPost-for-Android/releases` }
    ]
  },
  {
    name: "iPhone & iPad",
    blurb: "Native app with Secure Enclave key protection.",
    channels: [{ label: "App Store" }, { label: "TestFlight" }]
  },
  {
    name: "macOS",
    blurb: "The same app as iOS, built for the desktop.",
    channels: [{ label: "Mac App Store" }, { label: "GitHub Releases", href: `${GITHUB}/KyPost-for-Mac/releases` }]
  },
  {
    name: "Linux",
    blurb: "Qt desktop app, distributed as a signed Flatpak.",
    channels: [{ label: "Flatpak remote" }, { label: "GitHub Releases", href: `${GITHUB}/KyPost-for-Linux/releases` }]
  }
];
