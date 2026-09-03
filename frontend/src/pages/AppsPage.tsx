import { CLIENT_PLATFORMS } from "../app/clients";

export type PwaState = {
  installed: boolean;
  /** False until the browser fires beforeinstallprompt; Firefox and Safari never do. */
  canInstall: boolean;
  install: () => void;
};

/**
 * Every way to get KyPost on a device. The web app card drives the PWA
 * prompt that used to live in the sidebar; the native cards link to each
 * store, or show a placeholder until the listing is live.
 */
export function AppsPage({ pwa, platforms = CLIENT_PLATFORMS }: { pwa: PwaState; platforms?: typeof CLIENT_PLATFORMS }) {
  return (
    <section className="panel config-page">
      <div className="config-header">
        <h2>Get KyPost</h2>
        <p>Use it here in the browser, or install a client on each of your devices.</p>
      </div>
      <div className="apps-grid">
        <article className="config-card app-card">
          <h3>Web app</h3>
          <p className="config-muted">Install this site as an app for a window of its own and offline access.</p>
          <div className="app-channels">
            {pwa.installed ? (
              <span className="app-channel app-channel-soon">Installed</span>
            ) : pwa.canInstall ? (
              <button type="button" className="app-channel" onClick={pwa.install}>
                Install web app
              </button>
            ) : (
              <p className="config-muted app-install-hint">
                Your browser did not offer to install. Use its menu: Share, then Add to Home Screen on iPhone and iPad, or the install icon in the address bar.
              </p>
            )}
          </div>
        </article>
        {platforms.map((platform) => (
          <article key={platform.name} className="config-card app-card">
            <h3>{platform.name}</h3>
            <p className="config-muted">{platform.blurb}</p>
            <div className="app-channels">
              {platform.channels.map((channel) =>
                channel.href ? (
                  <a key={channel.label} className="app-channel" href={channel.href} target="_blank" rel="noopener noreferrer">
                    {channel.label}
                  </a>
                ) : (
                  <span key={channel.label} className="app-channel app-channel-soon">
                    {channel.label} <small>Coming soon</small>
                  </span>
                )
              )}
            </div>
          </article>
        ))}
      </div>
    </section>
  );
}
