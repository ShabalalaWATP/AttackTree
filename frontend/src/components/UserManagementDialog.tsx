import { useMemo, useState, type Dispatch, type SetStateAction } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Loader2, Shield, Trash2, UserCog, UserPlus, X } from 'lucide-react';
import toast from 'react-hot-toast';

import { api } from '@/utils/api';
import { cn } from '@/utils/cn';

type UserDraftMap = Record<string, { name: string; username: string; email: string; role: 'admin' | 'user'; is_active: boolean }>;
type PasswordDraftMap = Record<string, { new_password: string; require_reset: boolean }>;

export function UserManagementDialog({
  open,
  onClose,
}: {
  open: boolean;
  onClose: () => void;
}) {
  const queryClient = useQueryClient();
  const [createName, setCreateName] = useState('');
  const [createUsername, setCreateUsername] = useState('');
  const [createEmail, setCreateEmail] = useState('');
  const [createPassword, setCreatePassword] = useState('');
  const [createRole, setCreateRole] = useState<'admin' | 'user'>('user');
  const [editingUsers, setEditingUsers] = useState<UserDraftMap>({});
  const [passwordDrafts, setPasswordDrafts] = useState<PasswordDraftMap>({});

  const { data: users, isLoading } = useQuery({
    queryKey: ['admin-users'],
    queryFn: api.listUsers,
    enabled: open,
  });

  const invalidateUsers = async () => {
    await queryClient.invalidateQueries({ queryKey: ['admin-users'] });
  };

  const createMutation = useMutation({
    mutationFn: api.createUser,
    onSuccess: async () => {
      await invalidateUsers();
      setCreateName('');
      setCreateUsername('');
      setCreateEmail('');
      setCreatePassword('');
      setCreateRole('user');
      toast.success('User created');
    },
    onError: (error: any) => toast.error(error.message || 'User creation failed'),
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: { name?: string; username?: string; email?: string; role?: 'admin' | 'user'; is_active?: boolean } }) =>
      api.updateUser(id, data),
    onSuccess: async (_, variables) => {
      await invalidateUsers();
      setEditingUsers((current) => {
        const next = { ...current };
        delete next[variables.id];
        return next;
      });
      toast.success('User updated');
    },
    onError: (error: any) => toast.error(error.message || 'User update failed'),
  });

  const resetPasswordMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: { new_password: string; require_reset?: boolean } }) =>
      api.resetUserPassword(id, data),
    onSuccess: async (_, variables) => {
      await invalidateUsers();
      setPasswordDrafts((current) => {
        const next = { ...current };
        delete next[variables.id];
        return next;
      });
      toast.success('Password updated');
    },
    onError: (error: any) => toast.error(error.message || 'Password reset failed'),
  });

  const deleteMutation = useMutation({
    mutationFn: api.deleteUser,
    onSuccess: async () => {
      await invalidateUsers();
      toast.success('User deleted');
    },
    onError: (error: any) => toast.error(error.message || 'User deletion failed'),
  });

  const orderedUsers = useMemo(
    () => (users || []).slice().sort((left, right) => left.name.localeCompare(right.name)),
    [users],
  );

  if (!open) {
    return null;
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 px-4 backdrop-blur-sm">
      <div className="flex h-[min(88vh,920px)] w-full max-w-5xl flex-col overflow-hidden rounded-3xl border border-border/50 bg-card shadow-2xl">
        <div className="flex items-start justify-between border-b border-border/50 px-6 py-5">
          <div>
            <div className="flex items-center gap-2 text-lg font-semibold">
              <UserCog size={18} />
              User Management
            </div>
            <div className="mt-1 text-sm text-muted-foreground">
              Admin controls for account creation, roles, access state, and password resets.
            </div>
          </div>
          <button onClick={onClose} className="rounded-lg p-1.5 text-muted-foreground hover:bg-accent">
            <X size={16} />
          </button>
        </div>

        <div className="grid flex-1 gap-0 overflow-hidden lg:grid-cols-[340px_1fr]">
          <aside className="border-r border-border/50 bg-background/50 p-5">
            <div className="mb-4 flex items-center gap-2 text-sm font-semibold">
              <UserPlus size={15} />
              Create User
            </div>
            <div className="space-y-3">
              <input
                value={createName}
                onChange={(event) => setCreateName(event.target.value)}
                className="input-field"
                placeholder="Name"
              />
              <input
                value={createUsername}
                onChange={(event) => setCreateUsername(event.target.value)}
                className="input-field"
                placeholder="Username"
              />
              <input
                value={createEmail}
                onChange={(event) => setCreateEmail(event.target.value)}
                className="input-field"
                placeholder="Email"
              />
              <input
                type="password"
                value={createPassword}
                onChange={(event) => setCreatePassword(event.target.value)}
                className="input-field"
                placeholder="Temporary password"
              />
              <select
                value={createRole}
                onChange={(event) => setCreateRole(event.target.value as 'admin' | 'user')}
                className="input-field"
              >
                <option value="user">User</option>
                <option value="admin">Admin</option>
              </select>
              <button
                onClick={() => createMutation.mutate({
                  name: createName.trim(),
                  username: createUsername.trim() || undefined,
                  email: createEmail.trim(),
                  password: createPassword,
                  role: createRole,
                })}
                disabled={createMutation.isPending}
                className="flex w-full items-center justify-center gap-2 rounded-xl bg-primary px-4 py-2.5 text-sm font-semibold text-primary-foreground disabled:opacity-60"
              >
                {createMutation.isPending ? <Loader2 size={14} className="animate-spin" /> : <UserPlus size={14} />}
                Create User
              </button>
            </div>

            <div className="mt-5 rounded-2xl border border-amber-500/15 bg-amber-500/5 p-4 text-xs leading-5 text-muted-foreground">
              Seeded placeholder accounts should be treated as temporary bootstrap users. Rotate or disable them before wider deployment.
            </div>
          </aside>

          <section className="min-h-0 overflow-auto p-5">
            {isLoading ? (
              <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
                <Loader2 size={16} className="mr-2 animate-spin" />
                Loading users...
              </div>
            ) : (
              <div className="space-y-3">
                {orderedUsers.map((user) => {
                  const draft = editingUsers[user.id] || {
                    name: user.name,
                    username: user.username,
                    email: user.email,
                    role: user.role,
                    is_active: user.is_active,
                  };
                  const passwordDraft = passwordDrafts[user.id] || {
                    new_password: '',
                    require_reset: user.password_reset_required,
                  };
                  const isEditing = Boolean(editingUsers[user.id]);
                  const isPasswordEditing = Boolean(passwordDrafts[user.id]);

                  return (
                    <div key={user.id} className="rounded-2xl border border-border/50 bg-background/55 p-4">
                      <div className="flex flex-wrap items-start justify-between gap-3">
                        <div>
                          <div className="flex items-center gap-2">
                            <div className="font-semibold">{user.name}</div>
                            <span className={cn(
                              'rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.16em]',
                              user.role === 'admin' ? 'bg-cyan-500/10 text-cyan-400' : 'bg-muted text-muted-foreground'
                            )}>
                              {user.role}
                            </span>
                            {!user.is_active && (
                              <span className="rounded-full bg-red-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.16em] text-red-400">
                                disabled
                              </span>
                            )}
                          </div>
                          <div className="mt-1 text-xs text-muted-foreground">Username: {user.username}</div>
                          <div className="mt-1 text-sm text-muted-foreground">{user.email}</div>
                          {user.password_reset_required && (
                            <div className="mt-2 inline-flex items-center gap-1 rounded-full bg-amber-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.16em] text-amber-400">
                              <Shield size={11} />
                              Password reset required
                            </div>
                          )}
                        </div>

                        <div className="flex flex-wrap gap-2">
                          <button
                            onClick={() => setEditingUsers((current) => current[user.id]
                              ? withoutKey(current, user.id)
                              : { ...current, [user.id]: draft })}
                            className="rounded-xl border border-border/60 px-3 py-1.5 text-xs font-semibold hover:bg-accent"
                          >
                            {isEditing ? 'Cancel Edit' : 'Edit'}
                          </button>
                          <button
                            onClick={() => setPasswordDrafts((current) => current[user.id]
                              ? withoutKey(current, user.id)
                              : { ...current, [user.id]: passwordDraft })}
                            className="rounded-xl border border-border/60 px-3 py-1.5 text-xs font-semibold hover:bg-accent"
                          >
                            {isPasswordEditing ? 'Cancel Password' : 'Set Password'}
                          </button>
                          <button
                            onClick={() => {
                              if (confirm(`Delete ${user.name}?`)) {
                                deleteMutation.mutate(user.id);
                              }
                            }}
                            className="rounded-xl border border-destructive/30 px-3 py-1.5 text-xs font-semibold text-destructive hover:bg-destructive/10"
                          >
                            <Trash2 size={12} className="inline-block" />
                          </button>
                        </div>
                      </div>

                      {isEditing && (
                        <div className="mt-4 grid gap-3 md:grid-cols-2">
                          <input
                            value={draft.name}
                            onChange={(event) => updateDraft(setEditingUsers, user.id, { ...draft, name: event.target.value })}
                            className="input-field"
                            placeholder="Name"
                          />
                          <input
                            value={draft.username}
                            onChange={(event) => updateDraft(setEditingUsers, user.id, { ...draft, username: event.target.value })}
                            className="input-field"
                            placeholder="Username"
                          />
                          <input
                            value={draft.email}
                            onChange={(event) => updateDraft(setEditingUsers, user.id, { ...draft, email: event.target.value })}
                            className="input-field"
                            placeholder="Email"
                          />
                          <select
                            value={draft.role}
                            onChange={(event) => updateDraft(setEditingUsers, user.id, { ...draft, role: event.target.value as 'admin' | 'user' })}
                            className="input-field"
                          >
                            <option value="user">User</option>
                            <option value="admin">Admin</option>
                          </select>
                          <label className="flex items-center gap-2 rounded-xl border border-border/50 px-3 py-2 text-sm">
                            <input
                              type="checkbox"
                              checked={draft.is_active}
                              onChange={(event) => updateDraft(setEditingUsers, user.id, { ...draft, is_active: event.target.checked })}
                            />
                            Account active
                          </label>
                          <div className="md:col-span-2 flex justify-end">
                            <button
                              onClick={() => updateMutation.mutate({ id: user.id, data: draft })}
                              disabled={updateMutation.isPending}
                              className="inline-flex items-center gap-2 rounded-xl bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground disabled:opacity-60"
                            >
                              {updateMutation.isPending ? <Loader2 size={14} className="animate-spin" /> : null}
                              Save Changes
                            </button>
                          </div>
                        </div>
                      )}

                      {isPasswordEditing && (
                        <div className="mt-4 grid gap-3 md:grid-cols-[1fr_auto]">
                          <div className="space-y-3">
                            <input
                              type="password"
                              value={passwordDraft.new_password}
                              onChange={(event) => updateDraft(setPasswordDrafts, user.id, { ...passwordDraft, new_password: event.target.value })}
                              className="input-field"
                              placeholder="New password"
                            />
                            <label className="flex items-center gap-2 text-sm text-muted-foreground">
                              <input
                                type="checkbox"
                                checked={passwordDraft.require_reset}
                                onChange={(event) => updateDraft(setPasswordDrafts, user.id, { ...passwordDraft, require_reset: event.target.checked })}
                              />
                              Require user to rotate password after login
                            </label>
                          </div>
                          <div className="flex items-end justify-end">
                            <button
                              onClick={() => resetPasswordMutation.mutate({ id: user.id, data: passwordDraft })}
                              disabled={resetPasswordMutation.isPending}
                              className="inline-flex items-center gap-2 rounded-xl bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground disabled:opacity-60"
                            >
                              {resetPasswordMutation.isPending ? <Loader2 size={14} className="animate-spin" /> : null}
                              Save Password
                            </button>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </section>
        </div>
      </div>
    </div>
  );
}

function updateDraft<T>(
  setDraftMap: Dispatch<SetStateAction<Record<string, T>>>,
  userId: string,
  nextValue: T,
) {
  setDraftMap((current) => ({ ...current, [userId]: nextValue }));
}

function withoutKey<T>(draftMap: Record<string, T>, keyToRemove: string): Record<string, T> {
  const next = { ...draftMap };
  delete next[keyToRemove];
  return next;
}
