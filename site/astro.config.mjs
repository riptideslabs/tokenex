// @ts-check
import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";
import { providers } from "./src/providers.ts";
import { remarkDocs } from "./src/remark-docs.mjs";

const repo = "https://github.com/riptideslabs/tokenex";

// On GitHub Pages the workflow passes the origin and base path from
// actions/configure-pages; locally the site is served from the root.
const base = process.env.BASE_PATH || "/";

// Providers with a page of their own, in the front page's order.
const pages = (/** @type {keyof typeof providers} */ group) =>
    providers[group].filter((p) => !p.hash).map((p) => ({ slug: p.page, label: p.name }));

export default defineConfig({
    site: process.env.SITE_URL || "https://riptideslabs.github.io",
    base,
    markdown: {
        remarkPlugins: [remarkDocs({ base: base.replace(/\/$/, ""), repo })],
    },
    integrations: [
        starlight({
            title: "tokenex",
            description:
                "tokenex is a Go library that exchanges the identity token your workload already has for short-lived credentials from cloud providers, secret stores and OAuth2 servers, and keeps them fresh.",
            logo: { src: "./src/assets/tokenex.svg" },
            favicon: "/favicon.svg",
            customCss: ["@fontsource-variable/inter", "./src/styles/custom.css"],
            components: { Hero: "./src/components/Hero.astro" },
            expressiveCode: {
                styleOverrides: {
                    borderRadius: "0.75rem",
                    borderColor: "var(--sl-color-gray-5)",
                    frames: { frameBoxShadowCssValue: "none" },
                },
            },
            // The pages from docs/ get Starlight's heading links too.
            markdown: { processedDirs: ["../docs"] },
            sidebar: [
                { label: "Overview", link: "/" },
                { slug: "common-setup", label: "Common setup" },
                { label: "Identity token sources", items: pages("sources") },
                { label: "Exchanged for", items: pages("exchanges") },
                { label: "Other refreshed credentials", items: pages("others") },
            ],
            social: [{ icon: "github", label: "GitHub", href: repo }],
            // Edit URLs resolve the pages from docs/ (../docs/aws.md) to the repo's docs/.
            editLink: { baseUrl: `${repo}/edit/main/site/` },
        }),
    ],
});
