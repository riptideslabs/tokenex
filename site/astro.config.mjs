// @ts-check
import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";

const repo = "https://github.com/riptideslabs/tokenex";

// On GitHub Pages the workflow passes the origin and base path from
// actions/configure-pages; locally the site is served from the root.
export default defineConfig({
    site: process.env.SITE_URL || "https://riptideslabs.github.io",
    base: process.env.BASE_PATH || "/",
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
            social: [{ icon: "github", label: "GitHub", href: repo }],
            editLink: { baseUrl: `${repo}/edit/main/site/` },
        }),
    ],
});
