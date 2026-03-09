import * as AlertDialog from '@radix-ui/react-alert-dialog';
import { cn } from '@/utils/cn';

interface ConfirmDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onConfirm: () => void;
  title: string;
  description: string;
  confirmLabel?: string;
  destructive?: boolean;
}

export function ConfirmDialog({
  open,
  onOpenChange,
  onConfirm,
  title,
  description,
  confirmLabel = 'Confirm',
  destructive = true,
}: ConfirmDialogProps) {
  return (
    <AlertDialog.Root open={open} onOpenChange={onOpenChange}>
      <AlertDialog.Portal>
        <AlertDialog.Overlay className="fixed inset-0 bg-black/50 z-50 animate-fade-in" />
        <AlertDialog.Content className="fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 bg-card border rounded-xl p-6 shadow-xl z-50 max-w-sm w-[calc(100%-2rem)] animate-scale-in">
          <AlertDialog.Title className="font-semibold text-base">
            {title}
          </AlertDialog.Title>
          <AlertDialog.Description className="text-sm text-muted-foreground mt-2 leading-relaxed">
            {description}
          </AlertDialog.Description>
          <div className="flex justify-end gap-2 mt-5">
            <AlertDialog.Cancel className="px-3.5 py-1.5 text-sm rounded-lg border hover:bg-accent transition-colors">
              Cancel
            </AlertDialog.Cancel>
            <AlertDialog.Action
              className={cn(
                'px-3.5 py-1.5 text-sm rounded-lg font-medium transition-colors',
                destructive
                  ? 'bg-destructive text-destructive-foreground hover:opacity-90'
                  : 'bg-primary text-primary-foreground hover:opacity-90'
              )}
              onClick={onConfirm}
            >
              {confirmLabel}
            </AlertDialog.Action>
          </div>
        </AlertDialog.Content>
      </AlertDialog.Portal>
    </AlertDialog.Root>
  );
}
