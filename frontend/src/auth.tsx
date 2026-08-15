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
};

export const AuthContext = createContext<AuthState>({ authenticated: false });

export function useAuth(): AuthState {
  return useContext(AuthContext);
}
