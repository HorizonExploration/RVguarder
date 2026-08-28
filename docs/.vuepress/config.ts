import { viteBundler } from "@vuepress/bundler-vite";
import { defaultTheme } from "@vuepress/theme-default";
import { defineUserConfig } from "vuepress";

export default defineUserConfig({
  lang: "zh-CN",
  title: "Openclaw Guard",
  description: "龙虾卫士文档站，覆盖快速开始、架构说明、部署、安全能力与运维说明。",
  base: "/",
  pagePatterns: ["**/*.md", "!superpowers/**", "!archive/**"],
  bundler: viteBundler(),
  head: [
    ["meta", { name: "theme-color", content: "#111827" }],
    ["meta", { name: "apple-mobile-web-app-capable", content: "yes" }],
  ],
  theme: defaultTheme({
    logo: "/mark.svg",
    docsDir: "docs",
    navbar: [
      { text: "首页", link: "/" },
      { text: "快速开始", link: "/deployment/local.html" },
      { text: "架构", link: "/architecture/overview.html" },
      { text: "核心功能", link: "/features/baseline.html" },
      { text: "运行时 Hook", link: "/features/runtime-hook.html" },
      { text: "部署运维", link: "/deployment/local.html" },
      { text: "API", link: "/api/http.html" },
      { text: "FAQ", link: "/ops/faq.html" },
      { text: "调研", link: "/research/index.html" },
    ],
    sidebar: {
      "/architecture/": [
        {
          text: "架构设计",
          children: [
            "/architecture/index.md",
            "/architecture/overview.md",
            "/architecture/permission-kb-runtime-architecture.md",
            "/architecture/project-memory.md",
            "/architecture/frontend-handoff-redesign-report.md",
            "/architecture/rv-engine-report.md",
            "/architecture/nl-automata-rv-landing-report.md",
            "/architecture/project-status-analysis.md",
            "/architecture/target-architecture.md",
            "/architecture/quality-assurance.md",
          ],
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
      "/comparison/": [
        {
          text: "对比分析",
          children: [
            "/comparison/rvguard-vs-agent-security-tools.md",
          ],
        },
      ],
      "/research/": [
        {
          text: "调研与规划",
          children: [
            "/research/index.md",
            "/research/permission-model-kb-and-cross-session-rv-plan.md",
            "/research/agent-permission-rv-research-report-2026-08-25.md",
            "/research/pmkb-network-baseline-implementation-report-2026-08-28.md",
          ],
        },
      ],
      "/semantic/": [
        {
          text: "语义理解",
          children: [
            "/semantic/index.md",
            "/semantic/method.md",
            "/semantic/office-scenario-matrix.md",
            "/semantic/pmkb-network-case-baseline.md",
          ],
        },
      ],
      "/test-design/": [
        {
          text: "测试设计",
          children: [
            "/test-design/index.md",
            "/test-design/openclaw-guard-test-design.md",
          ],
        },
      ],
      "/dev/": [
        {
          text: "开发文档",
          children: [
            "/dev/frontend.md",
          ],
        },
      ],
    },
    editLink: false,
    contributors: false,
    lastUpdated: false,
  }),
});
