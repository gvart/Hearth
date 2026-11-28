// @ts-check
import path from 'node:path';
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import mermaid from 'astro-mermaid';
import { unified } from '@astrojs/markdown-remark';
import { pages, repoURL, sections } from './src/pages.mjs';

// The site is served from a GitHub Pages project site: https://gvart.dev/Hearth/.
const site = 'https://gvart.dev';
const base = '/Hearth';

// The pages in docs/ link to each other and to the repository with relative
// links that work on GitHub. On the site, a link to a published page becomes
// that page's URL, and any other relative link points at the file on GitHub.
// Root-relative links in the landing page get the site's base path.
function docsLinks() {
	const docsDir = path.resolve('../docs');
	/** @param {any} node @param {(n: any) => void} fn */
	const walk = (node, fn) => {
		fn(node);
		for (const child of node.children ?? []) walk(child, fn);
	};
	/** @param {any} tree @param {any} file */
	return (tree, file) => {
		const dir = path.dirname(file.path ?? '');
		const inDocs = !path.relative(docsDir, dir).startsWith('..');
		walk(tree, (node) => {
			if (node.type !== 'link') return;
			if (!inDocs && /^\/(?!\/)/.test(node.url)) {
				if (!node.url.startsWith(`${base}/`)) node.url = `${base}${node.url}`;
				return;
			}
			if (!inDocs || /^([a-z]+:|\/|#)/i.test(node.url)) return;
			const [target, hash = ''] = node.url.split('#');
			const repoPath = path.relative(path.resolve('..'), path.resolve(dir, target));
			const page = repoPath.match(/^docs\/((?:spec\/)?[a-z0-9-]+)\.md$/)?.[1];
			const anchor = hash ? `#${hash}` : '';
			node.url = page && pages.includes(page) ? `${base}/${page}/${anchor}` : `${repoURL}/blob/main/${repoPath}${anchor}`;
		});
	};
}

export default defineConfig({
	site,
	base,
	markdown: { processor: unified({ remarkPlugins: [docsLinks] }) },
	integrations: [
		// Renders ```mermaid fences in the browser, in the site's light or dark
		// theme. It must come before Starlight, so Expressive Code leaves them alone.
		mermaid({ autoTheme: true }),
		starlight({
			title: 'Hearth',
			description: 'Open-source control plane for homelabs: every device an entity you can see, control and automate.',
			favicon: '/favicon.svg',
			customCss: ['./src/styles/theme.css'],
			// Long commands wrap instead of scrolling sideways; wrapped lines keep their indentation.
			expressiveCode: { defaultProps: { wrap: true, preserveIndent: true } },
			social: [{ icon: 'github', label: 'GitHub', href: repoURL }],
			sidebar: sections.map((s) => ({ label: s.label, items: s.pages })),
		}),
	],
});
