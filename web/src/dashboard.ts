// Dashboard tokens: the Homepage snippet shown once a token is made, kept
// apart from the component so node --test can check it
// (web/test/dashboard.test.mjs). See docs/homepage.md.

/** The path a dashboard reads. */
export const dashboardSummaryPath = '/api/v1/dashboard/summary';

/**
 * A ready services.yaml entry for Homepage's customapi widget, reading the
 * hub at origin with the token's secret.
 */
export function homepageSnippet(origin: string, secret: string): string {
  return [
    '- Homelab:',
    '    - Hearth:',
    '        icon: mdi-fireplace',
    `        href: ${origin}/`,
    '        description: Devices',
    '        widget:',
    '          type: customapi',
    `          url: ${origin}${dashboardSummaryPath}`,
    '          refreshInterval: 30000',
    '          headers:',
    `            Authorization: Bearer ${secret}`,
    '          mappings:',
    '            - field: counts.total',
    '              label: Devices',
    '              format: number',
    '            - field: counts.online',
    '              label: Online',
    '              format: number',
    '            - field: counts.offline',
    '              label: Offline',
    '              format: number',
    '',
  ].join('\n');
}
