import { useEffect, useId, useRef, useState } from 'react';
import { docsURL } from '../docs.ts';
import { tips, type TipId } from '../tips.ts';

/**
 * A "?" beside a title that opens a short explanation of what the page is
 * about, for whoever asks, so the page carries no standing help text. A press
 * opens and closes it; Escape, a press elsewhere or leaving it with Tab close it.
 */
export function Tip({ id }: { id: TipId }) {
  const tip = tips[id];
  const [open, setOpen] = useState(false);
  const wrap = useRef<HTMLSpanElement>(null);
  const boxId = useId();

  useEffect(() => {
    if (!open) {
      return;
    }
    const onDown = (e: PointerEvent) => {
      if (e.target instanceof Node && !wrap.current?.contains(e.target)) {
        setOpen(false);
      }
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setOpen(false);
      }
    };
    document.addEventListener('pointerdown', onDown);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('pointerdown', onDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  return (
    <span
      ref={wrap}
      className="tip"
      onBlur={(e) => {
        if (!e.currentTarget.contains(e.relatedTarget)) {
          setOpen(false);
        }
      }}
    >
      <button
        type="button"
        className="tip-mark"
        aria-label={`About ${tip.about}`}
        aria-expanded={open}
        aria-controls={boxId}
        onClick={() => {
          setOpen(!open);
        }}
      >
        ?
      </button>
      {open ? (
        <span id={boxId} className="tip-box" role="note">
          {tip.lines.map((line) => (
            <span key={line} className="tip-line">
              {line}
            </span>
          ))}
          {tip.docs ? (
            <a href={docsURL(tip.docs)} target="_blank" rel="noreferrer">
              Read the docs
            </a>
          ) : null}
        </span>
      ) : null}
    </span>
  );
}
