// The old standalone user-management route. The UI now lives in
// admin/sections/Users so the Server panel can compose it; this page is the
// shell that keeps /users working until that route becomes a redirect.
import { Users } from "../admin/sections/Users";

export function UsersPage() {
  return (
    <section className="panel users-page">
      <h2>Manage Users</h2>
      <Users />
    </section>
  );
}
