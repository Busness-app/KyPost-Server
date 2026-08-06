import { PanelTabs } from "../../components/PanelTabs";
import { EmailServer } from "../../settings/sections/EmailServer";
import { SendAs } from "../../settings/sections/SendAs";
import { CardDavClient } from "../../settings/sections/CardDavClient";
import { Filters } from "../../settings/sections/Filters";

/**
 * Everything about getting mail in and out: the server it comes from, the
 * addresses it can go out as, the contacts that ride alongside it, and the
 * rules applied on arrival.
 *
 * Tabbed rather than stacked — four sections, each with its own save action,
 * is more than one scroll can present clearly.
 */
export function MailPanel() {
  return (
    <section className="panel">
      <div className="config-header">
        <h2>Mail</h2>
        <p>Your mail server, the addresses you send as, contact sync, and mailbox rules.</p>
      </div>
      <PanelTabs
        ariaLabel="Mail sections"
        tabs={[
          { id: "email-server", label: "Email Settings", body: <EmailServer /> },
          { id: "send-as", label: "Send-As Addresses", body: <SendAs /> },
          { id: "carddav-client", label: "CardDAV Client", body: <CardDavClient /> },
          { id: "rules", label: "Mailbox Rules", body: <Filters /> }
        ]}
      />
    </section>
  );
}
