import { defineCollection } from 'astro:content';
import { glob } from 'astro/loaders';
import { docsSchema } from '@astrojs/starlight/schema';
import { pages } from './pages.mjs';

// One collection from two places, relative to the repository root: the landing
// page in site/src/content/docs and the published pages in docs/ (see
// pages.mjs). Each entry's id is its URL: the file name without extension.
const siteDir = 'site/src/content/docs/';

export const collections = {
	docs: defineCollection({
		loader: glob({
			base: '..',
			pattern: [`${siteDir}**/*.{md,mdx}`, ...pages.map((p) => `docs/${p}.md`)],
			generateId: ({ entry }) =>
				entry
					.replace(siteDir, '')
					.replace(/^docs\//, '')
					.replace(/\.mdx?$/, ''),
		}),
		schema: docsSchema(),
	}),
};
