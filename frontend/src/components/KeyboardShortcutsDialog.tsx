import * as Dialog from '@radix-ui/react-dialog';
import { X } from 'lucide-react';

const SHORTCUT_GROUPS = [
  {
    title: 'Tree Editor',
    shortcuts: [
      { keys: ['Ctrl', 'Z'], description: 'Undo last action' },
      { keys: ['Ctrl', 'Y'], description: 'Redo last action' },
      { keys: ['Ctrl', 'Enter'], description: 'Add child to selected node' },
      { keys: ['Delete'], description: 'Delete selected node' },
      { keys: ['Click'], description: 'Select a node' },
      { keys: ['Drag'], description: 'Move a node on canvas' },
      { keys: ['Scroll'], description: 'Zoom in / out' },
    ],
  },
  {
    title: 'Navigation',
    shortcuts: [
      { keys: ['?'], description: 'Show keyboard shortcuts' },
    ],
  },
];

interface KeyboardShortcutsDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function KeyboardShortcutsDialog({ open, onOpenChange }: KeyboardShortcutsDialogProps) {
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/50 z-50 animate-fade-in" />
        <Dialog.Content className="fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 bg-card border rounded-xl p-6 shadow-xl z-50 max-w-md w-[calc(100%-2rem)] animate-scale-in">
          <div className="flex items-center justify-between mb-4">
            <Dialog.Title className="font-semibold text-base">
              Keyboard Shortcuts
            </Dialog.Title>
            <Dialog.Close className="p-1 rounded hover:bg-accent transition-colors">
              <X size={16} />
            </Dialog.Close>
          </div>

          <div className="space-y-5">
            {SHORTCUT_GROUPS.map((group) => (
              <div key={group.title}>
                <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">
                  {group.title}
                </h3>
                <div className="space-y-1.5">
                  {group.shortcuts.map((shortcut) => (
                    <div
                      key={shortcut.description}
                      className="flex items-center justify-between py-1"
                    >
                      <span className="text-sm">{shortcut.description}</span>
                      <div className="flex items-center gap-1">
                        {shortcut.keys.map((key, i) => (
                          <span key={i}>
                            {i > 0 && (
                              <span className="text-xs text-muted-foreground mx-0.5">+</span>
                            )}
                            <kbd className="inline-flex items-center justify-center min-w-[24px] h-6 px-1.5 text-xs font-mono rounded border bg-muted text-muted-foreground shadow-sm">
                              {key}
                            </kbd>
                          </span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>

          <Dialog.Description className="sr-only">
            List of keyboard shortcuts available in the application
          </Dialog.Description>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
