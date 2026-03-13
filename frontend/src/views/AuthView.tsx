import { useState, type ReactNode } from 'react';
import toast from 'react-hot-toast';
import { Loader2, Lock, Shield, UserPlus } from 'lucide-react';

import ocpLogo from '@/assets/ocp.png';
import type { AuthLoginResponseData } from '@/types';
import { queryClient } from '@/lib/queryClient';
import { useAuthStore } from '@/stores/useAuthStore';
import { useStore } from '@/stores/useStore';
import { api } from '@/utils/api';
import { cn } from '@/utils/cn';

type AuthMode = 'login' | 'signup';

export function AuthView() {
  const setSession = useAuthStore((state) => state.setSession);
  const resetWorkspaceState = useStore((state) => state.resetWorkspaceState);

  const [mode, setMode] = useState<AuthMode>('login');
  const [submitting, setSubmitting] = useState(false);
  const [loginIdentifier, setLoginIdentifier] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [signupName, setSignupName] = useState('');
  const [signupUsername, setSignupUsername] = useState('');
  const [signupEmail, setSignupEmail] = useState('');
  const [signupPassword, setSignupPassword] = useState('');
  const [signupPasswordConfirm, setSignupPasswordConfirm] = useState('');

  const handleSuccess = (session: AuthLoginResponseData) => {
    queryClient.clear();
    resetWorkspaceState();
    setSession(session);
    if (session.user.password_reset_required) {
      toast('Password reset is required for this account.', { icon: '!' });
    } else {
      toast.success(`Signed in as ${session.user.name}`);
    }
  };

  const handleLogin = async () => {
    if (!loginIdentifier.trim() || !loginPassword.trim()) {
      toast.error('Enter your username or email and password.');
      return;
    }

    setSubmitting(true);
    try {
      handleSuccess(await api.login({ identifier: loginIdentifier.trim(), password: loginPassword }));
    } catch (error: any) {
      toast.error(error.message || 'Login failed');
    } finally {
      setSubmitting(false);
    }
  };

  const handleSignup = async () => {
    if (!signupName.trim() || !signupUsername.trim() || !signupEmail.trim() || !signupPassword.trim() || !signupPasswordConfirm.trim()) {
      toast.error('Complete the sign-up form, including both password fields.');
      return;
    }
    if (signupPassword !== signupPasswordConfirm) {
      toast.error('Passwords do not match.');
      return;
    }

    setSubmitting(true);
    try {
      const response = await api.signup({
        name: signupName.trim(),
        username: signupUsername.trim(),
        email: signupEmail.trim(),
        password: signupPassword,
      });
      setMode('login');
      setLoginIdentifier(signupUsername.trim() || signupEmail.trim());
      setSignupPassword('');
      setSignupPasswordConfirm('');
      toast.success(response.message);
    } catch (error: any) {
      toast.error(error.message || 'Sign-up failed');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-[radial-gradient(circle_at_top_left,_rgba(34,211,238,0.12),_transparent_35%),radial-gradient(circle_at_bottom_right,_rgba(59,130,246,0.12),_transparent_28%),linear-gradient(145deg,_hsl(var(--background)),_hsl(var(--card)))] text-foreground">
      <div className="mx-auto flex min-h-screen max-w-6xl items-center px-6 py-10">
        <div className="grid w-full gap-8 lg:grid-cols-[1.1fr_0.9fr]">
          <section className="rounded-[28px] border border-border/50 bg-card/70 p-8 shadow-2xl shadow-black/10 backdrop-blur">
            <div className="relative mb-8 flex justify-center overflow-hidden rounded-[32px] border border-cyan-400/15 bg-slate-950/30 px-6 py-8 shadow-[0_24px_80px_rgba(8,47,73,0.3)]">
              <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,_rgba(34,211,238,0.18),_transparent_58%)]" />
              <div className="absolute inset-x-10 bottom-4 h-16 rounded-full bg-cyan-400/20 blur-3xl" />
              <img
                src={ocpLogo}
                alt="Offensive Cyber Planner logo"
                className="animate-auth-logo-float relative w-full max-w-[22rem] drop-shadow-[0_18px_40px_rgba(34,211,238,0.28)]"
              />
            </div>

            <div className="mb-8 max-w-xl">
              <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-cyan-500/20 bg-cyan-500/10 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.2em] text-cyan-400">
                <Shield size={12} />
                Authenticated Workspace
              </div>
              <h1 className="text-4xl font-black tracking-tight">Offensive Cyber Planner</h1>
              <p className="mt-3 text-sm leading-6 text-muted-foreground">
                This tool is designed to support offensive cyber planning and authorised red-team assessment of your own
                systems. It combines AI-assisted attack trees, threat modelling, kill-chain planning, scenario work, and
                infrastructure mapping so you can organise complex assessments into structured projects with shared
                objectives, notes, and analysis context. The workspace also includes thousands of built-in references
                across ATT&amp;CK, CAPEC, CWE, OWASP, and environment catalogs, with room to attach CVE and advisory
                context where it matters.
              </p>
            </div>

            <div className="grid gap-4 sm:grid-cols-3">
              <FeatureCard
                title="Isolated Data"
                body="Projects, standalone scans, API providers, and tags are scoped to the signed-in user."
              />
              <FeatureCard
                title="Bring Your Own API Keys"
                body="Connect your own OpenAI-compatible, local, or hosted models so AI-assisted planning runs against infrastructure and credentials you control."
              />
              <FeatureCard
                title="VM Ready"
                body="Designed for shared VM use so multiple analysts can work concurrently with separate sessions."
              />
            </div>
          </section>

          <section className="rounded-[28px] border border-border/50 bg-card/85 p-6 shadow-2xl shadow-black/10 backdrop-blur">
            <div className="mb-5 flex rounded-2xl border border-border/50 bg-background/60 p-1">
              <TabButton active={mode === 'login'} onClick={() => setMode('login')} icon={<Lock size={14} />} label="Login" />
              <TabButton active={mode === 'signup'} onClick={() => setMode('signup')} icon={<UserPlus size={14} />} label="Sign Up" />
            </div>

            {mode === 'login' ? (
              <div className="space-y-4">
                <div>
                  <label className="text-[11px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">Username Or Email</label>
                  <input
                    value={loginIdentifier}
                    onChange={(event) => setLoginIdentifier(event.target.value)}
                    onKeyDown={(event) => event.key === 'Enter' && handleLogin()}
                    className="input-field mt-2"
                    placeholder="admin12345 or adminaccount@attacktree.local"
                    autoComplete="username"
                  />
                </div>
                <div>
                  <label className="text-[11px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">Password</label>
                  <input
                    type="password"
                    value={loginPassword}
                    onChange={(event) => setLoginPassword(event.target.value)}
                    onKeyDown={(event) => event.key === 'Enter' && handleLogin()}
                    className="input-field mt-2"
                    placeholder="Enter your password"
                    autoComplete="current-password"
                  />
                </div>
                <button
                  onClick={handleLogin}
                  disabled={submitting}
                  className="flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 px-4 py-3 text-sm font-semibold text-white shadow-lg shadow-blue-500/20 transition hover:shadow-blue-500/35 disabled:opacity-60"
                >
                  {submitting ? <Loader2 size={15} className="animate-spin" /> : <Lock size={15} />}
                  Sign In
                </button>
              </div>
            ) : (
              <div className="space-y-4">
                <div>
                  <label className="text-[11px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">Name</label>
                  <input
                    value={signupName}
                    onChange={(event) => setSignupName(event.target.value)}
                    className="input-field mt-2"
                    placeholder="Analyst name"
                    autoComplete="name"
                  />
                </div>
                <div>
                  <label className="text-[11px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">Username</label>
                  <input
                    value={signupUsername}
                    onChange={(event) => setSignupUsername(event.target.value)}
                    onKeyDown={(event) => event.key === 'Enter' && handleSignup()}
                    className="input-field mt-2"
                    placeholder="Required username"
                    autoComplete="username"
                  />
                </div>
                <div>
                  <label className="text-[11px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">Email</label>
                  <input
                    value={signupEmail}
                    onChange={(event) => setSignupEmail(event.target.value)}
                    className="input-field mt-2"
                    placeholder="analyst@example.com"
                    autoComplete="email"
                  />
                </div>
                <div>
                  <label className="text-[11px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">Password</label>
                  <input
                    type="password"
                    value={signupPassword}
                    onChange={(event) => setSignupPassword(event.target.value)}
                    className="input-field mt-2"
                    placeholder="At least 8 characters"
                    autoComplete="new-password"
                  />
                </div>
                <div>
                  <label className="text-[11px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">Confirm Password</label>
                  <input
                    type="password"
                    value={signupPasswordConfirm}
                    onChange={(event) => setSignupPasswordConfirm(event.target.value)}
                    onKeyDown={(event) => event.key === 'Enter' && handleSignup()}
                    className="input-field mt-2"
                    placeholder="Re-enter your password"
                    autoComplete="new-password"
                  />
                </div>
                <button
                  onClick={handleSignup}
                  disabled={submitting}
                  className="flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-emerald-500 to-teal-600 px-4 py-3 text-sm font-semibold text-white shadow-lg shadow-emerald-500/20 transition hover:shadow-emerald-500/35 disabled:opacity-60"
                >
                  {submitting ? <Loader2 size={15} className="animate-spin" /> : <UserPlus size={15} />}
                  Create Account
                </button>
              </div>
            )}

          </section>
        </div>
      </div>
    </div>
  );
}

function TabButton({
  active,
  onClick,
  icon,
  label,
}: {
  active: boolean;
  onClick: () => void;
  icon: ReactNode;
  label: string;
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'flex flex-1 items-center justify-center gap-2 rounded-xl px-3 py-2 text-sm font-semibold transition-colors',
        active ? 'bg-primary text-primary-foreground shadow' : 'text-muted-foreground hover:text-foreground'
      )}
    >
      {icon}
      {label}
    </button>
  );
}

function FeatureCard({ title, body }: { title: string; body: string }) {
  return (
    <div className="rounded-2xl border border-border/50 bg-background/45 p-4">
      <div className="text-sm font-semibold">{title}</div>
      <div className="mt-2 text-xs leading-5 text-muted-foreground">{body}</div>
    </div>
  );
}
