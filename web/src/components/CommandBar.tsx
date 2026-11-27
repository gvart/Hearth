import { useEffect, useId, useRef, useState } from 'react';
import { useRunbookFiles } from '../api/admin.ts';
import { useDevices, useKubeClusters, useRunbooks } from '../api/hooks.ts';
import { useESPHomeDevices } from '../api/esphome.ts';
import { useProxmoxServers } from '../api/proxmox.ts';
import { findCommands, type Command } from '../nav.ts';
import { kindLabel, platformCards } from '../platforms.ts';
import { chooseTheme, useTheme } from '../theme.ts';

/**
 * Finds a page, a device, a platform or a runbook by name and opens it, and
 * runs what the UI itself can do (add a device, switch the theme). "/" focuses
 * it from anywhere, the arrow keys move through the results, Enter takes one
 * and Escape clears. It never acts on a device: a runbook opens at its plan.
 */
export function CommandBar({ cluster, className }: { cluster: boolean; className?: string }) {
  const devices = useDevices().data ?? [];
  const [query, setQuery] = useState('');
  const [active, setActive] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  const listId = useId();
  const typed = query.trim() !== '';
  // Read only once something is typed: the bar is on every page, and these lists are not.
  const clusters = useKubeClusters(typed);
  const servers = useProxmoxServers(typed);
  const esp = useESPHomeDevices(typed);
  const runbooks = useRunbooks(typed);
  const files = useRunbookFiles(typed);
  const theme = useTheme();
  const results = findCommands(query, {
    devices,
    platforms: platformCards(clusters.data ?? [], servers.data ?? [], esp.data ?? []).map((p) => ({
      name: p.name,
      kind: kindLabel[p.kind],
      hash: p.hash,
    })),
    runbooks: runbooks.data?.runbooks,
    cluster,
    theme,
    editable: files.isSuccess,
  });
  const current = Math.min(active, results.length - 1);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== '/' || e.metaKey || e.ctrlKey || e.altKey) {
        return;
      }
      const t = e.target;
      if (t instanceof HTMLElement && (t.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(t.tagName))) {
        return;
      }
      // Two bars exist, one for wide screens and one for phones: only the one in sight answers.
      const el = input.current;
      if (!el || el.offsetParent === null) {
        return;
      }
      e.preventDefault();
      el.focus();
    };
    window.addEventListener('keydown', onKey);
    return () => {
      window.removeEventListener('keydown', onKey);
    };
  }, []);

  const open = (cmd: Command) => {
    if (cmd.theme) {
      chooseTheme(cmd.theme);
    }
    if (cmd.hash !== undefined) {
      window.location.hash = cmd.hash;
    }
    setQuery('');
    setActive(0);
    input.current?.blur();
  };

  return (
    <div className={className ? `cmd ${className}` : 'cmd'}>
      <label className="cmdbar">
        <span className="cmdbar-label">Find</span>
        <input
          ref={input}
          type="text"
          role="combobox"
          aria-label="Find a page, a device or something to run"
          aria-expanded={results.length > 0}
          aria-controls={listId}
          aria-autocomplete="list"
          aria-activedescendant={results.length > 0 ? `${listId}-${String(current)}` : undefined}
          placeholder="a page, a device, a runbook"
          autoComplete="off"
          spellCheck={false}
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setActive(0);
          }}
          onKeyDown={(e) => {
            if (e.key === 'ArrowDown' && results.length > 0) {
              e.preventDefault();
              setActive((current + 1) % results.length);
            } else if (e.key === 'ArrowUp' && results.length > 0) {
              e.preventDefault();
              setActive((current + results.length - 1) % results.length);
            } else if (e.key === 'Enter' && results.length > 0) {
              e.preventDefault();
              const pick = results[current];
              if (pick) {
                open(pick);
              }
            } else if (e.key === 'Escape') {
              setQuery('');
              setActive(0);
            }
          }}
        />
        <kbd aria-hidden="true">/</kbd>
      </label>
      {results.length > 0 ? (
        <ul id={listId} role="listbox" aria-label="Results" className="cmd-results">
          {results.map((r, i) => (
            <li
              key={`${r.kind}:${r.label}`}
              id={`${listId}-${String(i)}`}
              role="option"
              aria-selected={i === current}
              className="cmd-result"
              // mousedown, not click: the input must not lose focus before the result opens.
              onMouseDown={(e) => {
                e.preventDefault();
                open(r);
              }}
              onMouseEnter={() => {
                setActive(i);
              }}
            >
              <span className="cmd-kind">{r.kind}</span>
              <span className="cmd-label">{r.label}</span>
              <span className="cmd-hint">{r.hint}</span>
            </li>
          ))}
        </ul>
      ) : typed ? (
        <p id={listId} className="cmd-results cmd-none" role="status">
          Nothing matches “{query.trim()}”.
        </p>
      ) : null}
    </div>
  );
}
