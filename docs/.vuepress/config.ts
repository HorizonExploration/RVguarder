import { viteBundler } from "@vuepress/bundler-vite";
import { defaultTheme } from "@vuepress/theme-default";
import { defineUserConfig } from "vuepress";

export default defineUserConfig({
  lang: "zh-CN",
  title: "Openclaw Guard",
  description: "龙虾卫士文档站，覆盖快速开始、架构说明、部署、安全能力与运维说明。",
  base: "/",
  bundler: viteBundler(),
  head: [
    ["meta", { name: "theme-color", content: "#111827" }],
    ["meta", { name: "apple-mobile-web-app-capable", content: "yes" }],
  ],
  theme: defaultTheme({
    logo: "/mark.svg",
    repo: "https://example.invalid/openclaw-guard",
    docsDir: "docs",
    navbar: [
      { text: "首页", link: "/" },
      { text: "快速开始", link: "/guide/quick-start.html" },
      { text: "简洁模式", link: "/guide/normal-mode.html" },
      { text: "架构", link: "/architecture/overview.html" },
      { text: "核心功能", link: "/features/baseline.html" },
      { text: "运行时 Hook", link: "/features/runtime-hook.html" },
      { text: "部署运维", link: "/deployment/local.html" },
      { text: "API", link: "/api/http.html" },
      { text: "FAQ", link: "/ops/faq.html" },
    ],
    sidebar: {
      "/guide/": [
        {
          text: "使用指南",
          children: [
            "/guide/README.md",
            "/guide/quick-start.md",
            "/guide/normal-mode.md",
          ],
        },
        {
          text: "项目梳理",
          children: [
            "/improve/README.md",
            "/improve/normal-mode.md",
            "/improve/plugin-positioning.md",
            "/improve/restructure-plan.md",
            "/improve/frontend.md",
            "/improve/project-overview.md",
            "/improve/project-structure.md",
            "/improve/project-cleanup.md",
          ],
        },
      ],
      "/architecture/": [
        {
          text: "架构设计",
          children: ["/architecture/overview.md", "/architecture/modules.md"],
        },
      ],
      "/features/": [
        {
          text: "核心能力",
          children: [
            "/features/baseline.md",
            "/features/action-gate.md",
            "/features/runtime-hook.md",
            "/features/audit.md",
          ],
        },
      ],
      "/deployment/": [
        {
          text: "部署说明",
          children: [
            "/deployment/local.md",
            "/deployment/docker-k8s.md",
          ],
        },
      ],
      "/api/": [
        {
          text: "接口文档",
          children: ["/api/http.md"],
        },
      ],
      "/ops/": [
        {
          text: "运维与 FAQ",
          children: ["/ops/faq.md", "/ops/roadmap.md"],
        },
      ],
    },
    editLink: false,
    contributors: false,
    lastUpdated: false,
  }),
});
