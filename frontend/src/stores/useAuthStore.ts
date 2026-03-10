import { create } from 'zustand';

import type { AuthLoginResponseData, AuthUserData } from '@/types';
import { api } from '@/utils/api';
import { clearStoredAuthSession, getStoredAuthSession, storeAuthSession } from '@/utils/authStorage';

interface AuthState {
  token: string | null;
  user: AuthUserData | null;
  initializing: boolean;
  restoreSession: () => Promise<void>;
  setSession: (session: AuthLoginResponseData) => void;
  setUser: (user: AuthUserData) => void;
  logout: () => void;
}

const storedSession = getStoredAuthSession();

export const useAuthStore = create<AuthState>((set) => ({
  token: storedSession?.token || null,
  user: storedSession?.user || null,
  initializing: true,
  restoreSession: async () => {
    const session = getStoredAuthSession();
    if (!session?.token) {
      set({ token: null, user: null, initializing: false });
      return;
    }

    try {
      const user = await api.getCurrentUser();
      storeAuthSession(session.token, user);
      set({ token: session.token, user, initializing: false });
    } catch {
      clearStoredAuthSession();
      set({ token: null, user: null, initializing: false });
    }
  },
  setSession: (session) => {
    storeAuthSession(session.access_token, session.user);
    set({ token: session.access_token, user: session.user, initializing: false });
  },
  setUser: (user) => {
    const currentToken = getStoredAuthSession()?.token;
    if (currentToken) {
      storeAuthSession(currentToken, user);
    }
    set({ user });
  },
  logout: () => {
    clearStoredAuthSession();
    set({ token: null, user: null, initializing: false });
  },
}));
