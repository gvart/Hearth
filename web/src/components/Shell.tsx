import { Fragment, lazy, Suspense, useEffect, useRef, useState } from 'react';
import { isNotAPCluster, useClusterMembers } from '../api/cluster.ts';
import { useApprovals, useDeviceEvents, useLogout } from '../api/hooks.ts';
import { ApprovalsPage } from './ApprovalsPage.tsx';
import { AuditPage } from './AuditPage.tsx';
import { deviceOfHash, pageOf, pagesOf, sheetHash, sheetOf, sheets } from '../nav.ts';
import { platformOfHash } from '../platforms.ts';
import { ClusterPage } from './ClusterPage.tsx';
import { CommandBar } from './CommandBar.tsx';
import { ConfigDriftBanner } from './ConfigDriftBanner.tsx';
import { DevicePage } from './DevicePage.tsx';
import { DevicesPage } from './DevicesPage.tsx';
import { IntegrationsPage } from './IntegrationsPage.tsx';
import { KubernetesPage } from './KubernetesPage.tsx';
import { Logo } from './Logo.tsx';
import { NetworkPage } from './NetworkPage.tsx';
import { NotificationsPage } from './NotificationsPage.tsx';
import { PanelsPage } from './PanelsPage.tsx';
import { PlatformsPage } from './PlatformsPage.tsx';
import { ESPHomePage } from './ESPHomePage.tsx';
import { OpenWrtPage } from './OpenWrtPage.tsx';
import { OPNsensePage } from './OPNsensePage.tsx';
import { ProxmoxPage } from './ProxmoxPage.tsx';
import { UniFiPage } from './UniFiPage.tsx';
import { ReauthHost } from './ReauthDialog.tsx';
import { RunbooksPage } from './RunbooksPage.tsx';
import { SettingsPage } from './SettingsPage.tsx';
import { TelemetryPrompt, TelemetryStatus } from './TelemetryPrompt.tsx';
import './Shell.css';

// Loaded when opened: the editor brings a YAML parser no other page needs.
const AutomationsPage = lazy(() => import('./AutomationsPage.tsx'));

/** The URL hash, which chooses the page, so reloads and links keep it. */
function useHash(): string {
  const [hash, setHash] = useState(() => window.location.hash);
  useEffect(() => {
    const onHash = () => {
      setHash(window.location.hash);
    };
    window.addEventListener('hashchange', onHash);
    return () => {
      window.removeEventListener('hashchange', onHash);
    };
  }, []);
  return hash;
}

/** How many approvals wait, beside the name of what leads to them. */
function Waiting({ count }: { count: number }) {
  return count > 0 ? (
    <span className="badge nav-badge" aria-label={`${String(count)} waiting`}>
      {count}
    </span>
  ) : null;
}

/**
 * The signed-in app: the top bar with the command bar, the sheet index, the
 * page, and the live event stream. On a phone the index is a tab bar at the
 * bottom, the open sheet's pages are links above the page, and the command bar
 * sits at the thumb.
 */
export function Shell() {
  useDeviceEvents();
  const logout = useLogout();
  const hash = useHash();
  const page = pageOf(hash);
  // A device link (#/devices/<id>) opens that device's page inside Devices.
  const deviceId = page === 'devices' ? deviceOfHash(hash) : undefined;
  // A platform link (#/platforms/<kind>/<id>) opens that cluster or server inside Platforms.
  const platform = page === 'platforms' ? platformOfHash(hash) : undefined;
  const sheet = sheetOf(page);
  const waiting = useApprovals('pending').data?.length ?? 0;
  // The Cluster page is offered on a member of an AP cluster only.
  const cluster = useClusterMembers();
  const apCluster = cluster.isSuccess || (cluster.isError && !isNotAPCluster(cluster.error));
  const shown = pagesOf(sheet, { cluster: apCluster, current: page });
  // On a phone the open sheet's pages are one line that scrolls sideways: keep the open page in sight.
  const subnav = useRef<HTMLElement>(null);
  useEffect(() => {
    subnav.current?.querySelector('[aria-current]')?.scrollIntoView({ block: 'nearest', inline: 'nearest' });
  }, [page]);

  return (
    <div className={`app sheet-${sheet.id}`}>
      <header className="topbar">
        <a className="brand" href="#/">
          <Logo size={28} />
          <span>Hearth</span>
        </a>
        <CommandBar cluster={apCluster} className="cmd-top" />
        <div className="topbar-right">
          {waiting > 0 ? (
            <a className="nav-link" href="#/approvals" aria-current={page === 'approvals' ? 'page' : undefined}>
              Approvals
              <Waiting count={waiting} />
            </a>
          ) : null}
          <button
            className="btn btn-ghost"
            type="button"
            onClick={() => {
              logout.mutate();
            }}
          >
            Sign out
          </button>
        </div>
      </header>
      <div className="shell-body">
        <nav className="sheet-nav shell-rail" aria-label="Sections">
          {sheets.map((s) => (
            <Fragment key={s.id}>
              <a className="sheet-tab" href={sheetHash(s)} aria-current={s.id === sheet.id ? 'true' : undefined}>
                <span className={`sheet-no sheet-no-${s.id}`}>{s.no}</span>
                {s.label}
                {s.id === 'activity' && s.id !== sheet.id ? <Waiting count={waiting} /> : null}
              </a>
              {s.id === sheet.id
                ? shown.map((p) => (
                    <a key={p.id} className="sheet-sub" href={p.hash} aria-current={page === p.id ? 'page' : undefined}>
                      {p.label}
                      {p.id === 'approvals' ? <Waiting count={waiting} /> : null}
                    </a>
                  ))
                : null}
            </Fragment>
          ))}
        </nav>
        <div className="shell-main">
          {shown.length > 1 ? (
            <nav ref={subnav} className="shell-subnav" aria-label={`${sheet.label} pages`}>
              {shown.map((p) => (
                <a key={p.id} href={p.hash} aria-current={page === p.id ? 'page' : undefined}>
                  {p.label}
                  {p.id === 'approvals' ? <Waiting count={waiting} /> : null}
                </a>
              ))}
            </nav>
          ) : null}
          <ConfigDriftBanner />
          <TelemetryPrompt />
          {page === 'approvals' ? (
            <ApprovalsPage />
          ) : page === 'network' ? (
            <NetworkPage />
          ) : page === 'platforms' ? (
            platform?.kind === 'kubernetes' ? (
              <KubernetesPage id={platform.id} />
            ) : platform?.kind === 'proxmox' ? (
              <ProxmoxPage id={platform.id} />
            ) : platform?.kind === 'esphome' ? (
              <ESPHomePage id={platform.id} />
            ) : platform?.kind === 'openwrt' ? (
              <OpenWrtPage id={platform.id} />
            ) : platform?.kind === 'opnsense' ? (
              <OPNsensePage id={platform.id} />
            ) : platform?.kind === 'unifi' ? (
              <UniFiPage id={platform.id} />
            ) : (
              <PlatformsPage />
            )
          ) : page === 'runbooks' ? (
            <RunbooksPage />
          ) : page === 'automations' ? (
            <Suspense fallback={<main className="content muted">Loading automations…</main>}>
              <AutomationsPage />
            </Suspense>
          ) : page === 'panels' ? (
            <PanelsPage />
          ) : page === 'notifications' ? (
            <NotificationsPage />
          ) : page === 'audit' ? (
            <AuditPage />
          ) : page === 'cluster' ? (
            <ClusterPage />
          ) : page === 'integrations' ? (
            <IntegrationsPage />
          ) : page === 'settings' || page === 'access' || page === 'policy' || page === 'backup' ? (
            <SettingsPage section={page} />
          ) : deviceId !== undefined ? (
            <DevicePage key={deviceId} id={deviceId} />
          ) : (
            <DevicesPage />
          )}
          <TelemetryStatus />
        </div>
      </div>
      <div className="shell-bottom">
        <CommandBar cluster={apCluster} />
        <nav className="tabbar" aria-label="Sections">
          {sheets.map((s) => (
            <a key={s.id} className="sheet-tab" href={sheetHash(s)} aria-current={s.id === sheet.id ? 'true' : undefined}>
              <span className={`sheet-no sheet-no-${s.id}`}>{s.no}</span>
              {s.label}
              {s.id === 'activity' ? <Waiting count={waiting} /> : null}
            </a>
          ))}
        </nav>
      </div>
      <ReauthHost />
    </div>
  );
}
