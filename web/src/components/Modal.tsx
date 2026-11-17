import { useEffect, useRef, type ReactNode } from 'react';

interface ModalProps {
  onClose: () => void;
  className: string;
  labelledBy: string;
  children: ReactNode;
}

/**
 * A native modal <dialog>, shown while mounted: the browser handles focus,
 * Escape and the backdrop. Clicking the backdrop closes it too.
 */
export function Modal({ onClose, className, labelledBy, children }: ModalProps) {
  const ref = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    const d = ref.current;
    if (d && !d.open) {
      d.showModal();
    }
    return () => d?.close();
  }, []);

  return (
    <dialog
      ref={ref}
      className={className}
      aria-labelledby={labelledBy}
      onClose={onClose}
      onClick={(e) => {
        // A click on the dialog element itself (not its content) is the backdrop.
        if (e.target === e.currentTarget) {
          ref.current?.close();
        }
      }}
    >
      <div className="dialog-body">{children}</div>
    </dialog>
  );
}
