// The pages of the docs site. Every page except the landing page is a
// Markdown file in the repository's docs/ directory, which stays the one
// source of truth: the site renders those files, it does not copy them.
// A page's URL is its file name without .md (docs/cluster.md -> /cluster/).
// To publish a new docs/*.md page, add it here.

/** @type {{ label: string, pages: string[] }[]} */
export const sections = [
	{ label: 'Start here', pages: ['getting-started', 'concepts', 'comparison'] },
	{ label: 'Automations', pages: ['automations', 'notifications'] },
	{ label: 'Integrations', pages: ['prometheus', 'kubernetes', 'mcp'] },
	{ label: 'Operating', pages: ['guardrails', 'https', 'cluster', 'security'] },
];

export const pages = sections.flatMap((s) => s.pages);

export const repoURL = 'https://github.com/gvart/hearth';
