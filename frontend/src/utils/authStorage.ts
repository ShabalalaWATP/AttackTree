import type { AuthUserData } from '@/types';

const AUTH_STORAGE_KEY = 'atb-auth-session';

interface StoredAuthSession {
  token: string;
  user: AuthUserData | null;
}

export function getStoredAuthSession(): StoredAuthSession | null {
  try {
    const raw = localStorage.getItem(AUTH_STORAGE_KEY);
    if (!raw) return null;
    return JSON.parse(raw) as StoredAuthSession;
  } catch {
    return null;
  }
}

export function getStoredToken(): string | null {
  return getStoredAuthSession()?.token || null;
}

export function storeAuthSession(token: string, user: AuthUserData): void {
  try {
    localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify({ token, user }));
  } catch {
    // localStorage may be unavailable
  }
}

export function clearStoredAuthSession(): void {
  try {
    localStorage.removeItem(AUTH_STORAGE_KEY);
  } catch {
    // localStorage may be unavailable
  }
}
