import { EmailServer } from "../../settings/sections/EmailServer";
import { SendAs } from "../../settings/sections/SendAs";
import { CardDavClient } from "../../settings/sections/CardDavClient";
import { Filters } from "../../settings/sections/Filters";

/**
 * Everything about getting mail in and out: the server it comes from, the
 * addresses it can go out as, the contacts that ride alongside it, and the
 * rules applied on arrival.
 */
export function MailPanel() {
  return (
    <section className="panel">
      <div className="config-header">
        <h2>Mail</h2>
        <p>Your mail server, the addresses you send as, contact sync, and filters.</p>
      </div>
      <div id="email-server"><EmailServer /></div>
      <div id="send-as"><SendAs /></div>
      <div id="contacts-sync"><CardDavClient /></div>
      <div id="filters"><Filters /></div>
    </section>
  );
}
