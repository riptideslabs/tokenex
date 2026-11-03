import { fileURLToPath } from "node:url";

const docsDir = fileURLToPath(new URL("../../docs/", import.meta.url));

// README sections that the front page covers.
const front = { "../README.md#channel-behavior": "#the-credential-channel" };

// Turns the files in the repo's docs/ into site pages. Their first heading is
// the page title, so it's dropped from the body; links to other files point at
// their pages, and the rest of the repo at GitHub.
export function remarkDocs({ base, repo }) {
  const pageUrl = (url) => {
    if (/^([a-z]+:|#)/.test(url)) return url;
    if (url in front) return `${base}/${front[url]}`;
    const page = url.match(/^([\w-]+)\.md(#.*)?$/);
    if (page) return `${base}/${page[1]}/${page[2] ?? ""}`;
    return new URL(url, `${repo}/blob/main/docs/`).href;
  };
  const walk = (node) => {
    if (node.type === "link") node.url = pageUrl(node.url);
    node.children?.forEach(walk);
  };

  return () => (tree, file) => {
    if (!file.path?.startsWith(docsDir)) return;
    if (tree.children[0]?.type === "heading" && tree.children[0].depth === 1) tree.children.shift();
    walk(tree);
  };
}
