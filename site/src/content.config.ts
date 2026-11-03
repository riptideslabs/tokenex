import { readFile } from 'node:fs/promises';
import { defineCollection } from 'astro:content';
import { glob, type Loader } from 'astro/loaders';
import { docsSchema } from '@astrojs/starlight/schema';

// The front page, and a page for each file in the repo's docs/, so the docs
// are written once and read the same on GitHub. Those files have no
// frontmatter; the title comes from their first heading.
const files = glob({
	base: '..',
	pattern: ['site/src/content/docs/**/[^_]*.mdx', 'docs/*.md'],
	generateId: ({ entry }) => entry.replace(/^(site\/src\/content\/)?docs\//, '').replace(/\.mdx?$/, ''),
});

const loader: Loader = {
	name: 'tokenex-docs',
	load: (context) =>
		files.load({
			...context,
			parseData: async (props) => {
				if (!props.data.title && props.filePath) {
					const heading = (await readFile(props.filePath, 'utf8')).match(/^# (.+)$/m);
					props = { ...props, data: { ...props.data, title: heading?.[1] } };
				}
				return context.parseData(props);
			},
		}),
};

export const collections = {
	docs: defineCollection({ loader, schema: docsSchema() }),
};
