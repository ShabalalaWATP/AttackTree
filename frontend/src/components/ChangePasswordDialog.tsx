import { useState } from 'react';
import { Loader2, Lock, X } from 'lucide-react';
import toast from 'react-hot-toast';

import { useAuthStore } from '@/stores/useAuthStore';
import { api } from '@/utils/api';

export function ChangePasswordDialog({
  open,
  onClose,
}: {
  open: boolean;
  onClose: () => void;
}) {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [saving, setSaving] = useState(false);
  const setUser = useAuthStore((state) => state.setUser);

  if (!open) {
    return null;
  }

  const handleSubmit = async () => {
    if (!currentPassword.trim() || !newPassword.trim()) {
      toast.error('Enter your current and new password.');
      return;
    }

    setSaving(true);
    try {
      await api.changePassword({
        current_password: currentPassword,
        new_password: newPassword,
      });
      setUser(await api.getCurrentUser());
      setCurrentPassword('');
      setNewPassword('');
      toast.success('Password updated');
      onClose();
    } catch (error: any) {
      toast.error(error.message || 'Password update failed');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/55 px-4 backdrop-blur-sm">
      <div className="w-full max-w-md rounded-3xl border border-border/50 bg-card p-6 shadow-2xl">
        <div className="mb-5 flex items-start justify-between">
          <div>
            <div className="text-lg font-semibold">Change Password</div>
            <div className="mt-1 text-sm text-muted-foreground">Update your account password for this workspace.</div>
          </div>
          <button onClick={onClose} className="rounded-lg p-1.5 text-muted-foreground hover:bg-accent">
            <X size={16} />
          </button>
        </div>

        <div className="space-y-4">
          <div>
            <label className="text-[11px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">Current Password</label>
            <input
              type="password"
              value={currentPassword}
              onChange={(event) => setCurrentPassword(event.target.value)}
              className="input-field mt-2"
              autoComplete="current-password"
            />
          </div>
          <div>
            <label className="text-[11px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">New Password</label>
            <input
              type="password"
              value={newPassword}
              onChange={(event) => setNewPassword(event.target.value)}
              onKeyDown={(event) => event.key === 'Enter' && handleSubmit()}
              className="input-field mt-2"
              autoComplete="new-password"
            />
          </div>
        </div>

        <div className="mt-6 flex justify-end gap-2">
          <button onClick={onClose} className="rounded-xl border border-border/60 px-4 py-2 text-sm font-medium hover:bg-accent">
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            disabled={saving}
            className="inline-flex items-center gap-2 rounded-xl bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground disabled:opacity-60"
          >
            {saving ? <Loader2 size={14} className="animate-spin" /> : <Lock size={14} />}
            Save Password
          </button>
        </div>
      </div>
    </div>
  );
}
