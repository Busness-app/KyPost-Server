import { createContext, useContext } from "react";

export type Role = "admin" | "user";

export type AuthState = {
  authenticated: boolean;
  userId?: string;
  username?: string;
  role?: Role;
  mustChangePassword?: boolean;
  ssoSub?: string;
  ssoUsername?: string;
  ssoEmail?: string;
  ssoLinkedAt?: number;
  // The subject outlives the credential: revocation keeps ssoSub so directory
  // sync can still address the account. Read this, not ssoSub, to decide
  // whether the link can sign anyone in.
  ssoLinkRevoked?: boolean;
};

export const AuthContext = createContext<AuthState>({ authenticated: false });

export function useAuth(): AuthState {
  return useContext(AuthContext);
}
