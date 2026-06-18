// docs/.vuepress/config.ts
import { viteBundler } from "@vuepress/bundler-vite";
import { defaultTheme } from "@vuepress/theme-default";
import { defineUserConfig } from "vuepress";
var config_default = defineUserConfig({
  lang: "zh-CN",
  title: "Openclaw Guard",
  description: "\u9F99\u867E\u536B\u58EB\u6587\u6863\u7AD9\uFF0C\u8986\u76D6\u5FEB\u901F\u5F00\u59CB\u3001\u67B6\u6784\u8BF4\u660E\u3001\u90E8\u7F72\u3001\u5B89\u5168\u80FD\u529B\u4E0E\u8FD0\u7EF4\u8BF4\u660E\u3002",
  base: "/",
  bundler: viteBundler(),
  head: [
    ["meta", { name: "theme-color", content: "#111827" }],
    ["meta", { name: "apple-mobile-web-app-capable", content: "yes" }]
  ],
  theme: defaultTheme({
    logo: "/mark.svg",
    repo: "https://example.invalid/openclaw-guard",
    docsDir: "docs",
    navbar: [
      { text: "\u9996\u9875", link: "/" },
      { text: "\u5FEB\u901F\u5F00\u59CB", link: "/guide/quick-start.html" },
      { text: "\u7B80\u6D01\u6A21\u5F0F", link: "/guide/normal-mode.html" },
      { text: "\u67B6\u6784", link: "/architecture/overview.html" },
      { text: "\u6838\u5FC3\u529F\u80FD", link: "/features/baseline.html" },
      { text: "\u8FD0\u884C\u65F6 Hook", link: "/features/runtime-hook.html" },
      { text: "\u90E8\u7F72\u8FD0\u7EF4", link: "/deployment/local.html" },
      { text: "API", link: "/api/http.html" },
      { text: "FAQ", link: "/ops/faq.html" }
    ],
    sidebar: {
      "/guide/": [
        {
          text: "\u4F7F\u7528\u6307\u5357",
          children: ["/guide/quick-start.md", "/guide/normal-mode.md"]
        }
      ],
      "/architecture/": [
        {
          text: "\u67B6\u6784\u8BBE\u8BA1",
          children: ["/architecture/overview.md", "/architecture/modules.md"]
        }
      ],
      "/features/": [
        {
          text: "\u6838\u5FC3\u80FD\u529B",
          children: [
            "/features/baseline.md",
            "/features/action-gate.md",
            "/features/runtime-hook.md",
            "/features/audit.md"
          ]
        }
      ],
      "/deployment/": [
        {
          text: "\u90E8\u7F72\u8BF4\u660E",
          children: [
            "/deployment/local.md",
            "/deployment/docker-k8s.md"
          ]
        }
      ],
      "/api/": [
        {
          text: "\u63A5\u53E3\u6587\u6863",
          children: ["/api/http.md"]
        }
      ],
      "/ops/": [
        {
          text: "\u8FD0\u7EF4\u4E0E FAQ",
          children: ["/ops/faq.md", "/ops/roadmap.md"]
        }
      ]
    },
    editLink: false,
    contributors: false,
    lastUpdated: false
  })
});
export {
  config_default as default
};
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsiZG9jcy8udnVlcHJlc3MvY29uZmlnLnRzIl0sCiAgInNvdXJjZXNDb250ZW50IjogWyJpbXBvcnQgeyB2aXRlQnVuZGxlciB9IGZyb20gXCJAdnVlcHJlc3MvYnVuZGxlci12aXRlXCI7XG5pbXBvcnQgeyBkZWZhdWx0VGhlbWUgfSBmcm9tIFwiQHZ1ZXByZXNzL3RoZW1lLWRlZmF1bHRcIjtcbmltcG9ydCB7IGRlZmluZVVzZXJDb25maWcgfSBmcm9tIFwidnVlcHJlc3NcIjtcblxuZXhwb3J0IGRlZmF1bHQgZGVmaW5lVXNlckNvbmZpZyh7XG4gIGxhbmc6IFwiemgtQ05cIixcbiAgdGl0bGU6IFwiT3BlbmNsYXcgR3VhcmRcIixcbiAgZGVzY3JpcHRpb246IFwiXHU5Rjk5XHU4NjdFXHU1MzZCXHU1OEVCXHU2NTg3XHU2ODYzXHU3QUQ5XHVGRjBDXHU4OTg2XHU3NkQ2XHU1RkVCXHU5MDFGXHU1RjAwXHU1OUNCXHUzMDAxXHU2N0I2XHU2Nzg0XHU4QkY0XHU2NjBFXHUzMDAxXHU5MEU4XHU3RjcyXHUzMDAxXHU1Qjg5XHU1MTY4XHU4MEZEXHU1MjlCXHU0RTBFXHU4RkQwXHU3RUY0XHU4QkY0XHU2NjBFXHUzMDAyXCIsXG4gIGJhc2U6IFwiL1wiLFxuICBidW5kbGVyOiB2aXRlQnVuZGxlcigpLFxuICBoZWFkOiBbXG4gICAgW1wibWV0YVwiLCB7IG5hbWU6IFwidGhlbWUtY29sb3JcIiwgY29udGVudDogXCIjMTExODI3XCIgfV0sXG4gICAgW1wibWV0YVwiLCB7IG5hbWU6IFwiYXBwbGUtbW9iaWxlLXdlYi1hcHAtY2FwYWJsZVwiLCBjb250ZW50OiBcInllc1wiIH1dLFxuICBdLFxuICB0aGVtZTogZGVmYXVsdFRoZW1lKHtcbiAgICBsb2dvOiBcIi9tYXJrLnN2Z1wiLFxuICAgIHJlcG86IFwiaHR0cHM6Ly9leGFtcGxlLmludmFsaWQvb3BlbmNsYXctZ3VhcmRcIixcbiAgICBkb2NzRGlyOiBcImRvY3NcIixcbiAgICBuYXZiYXI6IFtcbiAgICAgIHsgdGV4dDogXCJcdTk5OTZcdTk4NzVcIiwgbGluazogXCIvXCIgfSxcbiAgICAgIHsgdGV4dDogXCJcdTVGRUJcdTkwMUZcdTVGMDBcdTU5Q0JcIiwgbGluazogXCIvZ3VpZGUvcXVpY2stc3RhcnQuaHRtbFwiIH0sXG4gICAgICB7IHRleHQ6IFwiXHU3QjgwXHU2RDAxXHU2QTIxXHU1RjBGXCIsIGxpbms6IFwiL2d1aWRlL25vcm1hbC1tb2RlLmh0bWxcIiB9LFxuICAgICAgeyB0ZXh0OiBcIlx1NjdCNlx1Njc4NFwiLCBsaW5rOiBcIi9hcmNoaXRlY3R1cmUvb3ZlcnZpZXcuaHRtbFwiIH0sXG4gICAgICB7IHRleHQ6IFwiXHU2ODM4XHU1RkMzXHU1MjlGXHU4MEZEXCIsIGxpbms6IFwiL2ZlYXR1cmVzL2Jhc2VsaW5lLmh0bWxcIiB9LFxuICAgICAgeyB0ZXh0OiBcIlx1OEZEMFx1ODg0Q1x1NjVGNiBIb29rXCIsIGxpbms6IFwiL2ZlYXR1cmVzL3J1bnRpbWUtaG9vay5odG1sXCIgfSxcbiAgICAgIHsgdGV4dDogXCJcdTkwRThcdTdGNzJcdThGRDBcdTdFRjRcIiwgbGluazogXCIvZGVwbG95bWVudC9sb2NhbC5odG1sXCIgfSxcbiAgICAgIHsgdGV4dDogXCJBUElcIiwgbGluazogXCIvYXBpL2h0dHAuaHRtbFwiIH0sXG4gICAgICB7IHRleHQ6IFwiRkFRXCIsIGxpbms6IFwiL29wcy9mYXEuaHRtbFwiIH0sXG4gICAgXSxcbiAgICBzaWRlYmFyOiB7XG4gICAgICBcIi9ndWlkZS9cIjogW1xuICAgICAgICB7XG4gICAgICAgICAgdGV4dDogXCJcdTRGN0ZcdTc1MjhcdTYzMDdcdTUzNTdcIixcbiAgICAgICAgICBjaGlsZHJlbjogW1wiL2d1aWRlL3F1aWNrLXN0YXJ0Lm1kXCIsIFwiL2d1aWRlL25vcm1hbC1tb2RlLm1kXCJdLFxuICAgICAgICB9LFxuICAgICAgXSxcbiAgICAgIFwiL2FyY2hpdGVjdHVyZS9cIjogW1xuICAgICAgICB7XG4gICAgICAgICAgdGV4dDogXCJcdTY3QjZcdTY3ODRcdThCQkVcdThCQTFcIixcbiAgICAgICAgICBjaGlsZHJlbjogW1wiL2FyY2hpdGVjdHVyZS9vdmVydmlldy5tZFwiLCBcIi9hcmNoaXRlY3R1cmUvbW9kdWxlcy5tZFwiXSxcbiAgICAgICAgfSxcbiAgICAgIF0sXG4gICAgICBcIi9mZWF0dXJlcy9cIjogW1xuICAgICAgICB7XG4gICAgICAgICAgdGV4dDogXCJcdTY4MzhcdTVGQzNcdTgwRkRcdTUyOUJcIixcbiAgICAgICAgICBjaGlsZHJlbjogW1xuICAgICAgICAgICAgXCIvZmVhdHVyZXMvYmFzZWxpbmUubWRcIixcbiAgICAgICAgICAgIFwiL2ZlYXR1cmVzL2FjdGlvbi1nYXRlLm1kXCIsXG4gICAgICAgICAgICBcIi9mZWF0dXJlcy9ydW50aW1lLWhvb2subWRcIixcbiAgICAgICAgICAgIFwiL2ZlYXR1cmVzL2F1ZGl0Lm1kXCIsXG4gICAgICAgICAgXSxcbiAgICAgICAgfSxcbiAgICAgIF0sXG4gICAgICBcIi9kZXBsb3ltZW50L1wiOiBbXG4gICAgICAgIHtcbiAgICAgICAgICB0ZXh0OiBcIlx1OTBFOFx1N0Y3Mlx1OEJGNFx1NjYwRVwiLFxuICAgICAgICAgIGNoaWxkcmVuOiBbXG4gICAgICAgICAgICBcIi9kZXBsb3ltZW50L2xvY2FsLm1kXCIsXG4gICAgICAgICAgICBcIi9kZXBsb3ltZW50L2RvY2tlci1rOHMubWRcIixcbiAgICAgICAgICBdLFxuICAgICAgICB9LFxuICAgICAgXSxcbiAgICAgIFwiL2FwaS9cIjogW1xuICAgICAgICB7XG4gICAgICAgICAgdGV4dDogXCJcdTYzQTVcdTUzRTNcdTY1ODdcdTY4NjNcIixcbiAgICAgICAgICBjaGlsZHJlbjogW1wiL2FwaS9odHRwLm1kXCJdLFxuICAgICAgICB9LFxuICAgICAgXSxcbiAgICAgIFwiL29wcy9cIjogW1xuICAgICAgICB7XG4gICAgICAgICAgdGV4dDogXCJcdThGRDBcdTdFRjRcdTRFMEUgRkFRXCIsXG4gICAgICAgICAgY2hpbGRyZW46IFtcIi9vcHMvZmFxLm1kXCIsIFwiL29wcy9yb2FkbWFwLm1kXCJdLFxuICAgICAgICB9LFxuICAgICAgXSxcbiAgICB9LFxuICAgIGVkaXRMaW5rOiBmYWxzZSxcbiAgICBjb250cmlidXRvcnM6IGZhbHNlLFxuICAgIGxhc3RVcGRhdGVkOiBmYWxzZSxcbiAgfSksXG59KTtcbiJdLAogICJtYXBwaW5ncyI6ICI7QUFBQTtBQUNBO0FBQ0E7QUFFQSxJQUFPLGlCQUFRLGlCQUFpQjtBQUFBLEVBQzlCLE1BQU07QUFBQSxFQUNOLE9BQU87QUFBQSxFQUNQLGFBQWE7QUFBQSxFQUNiLE1BQU07QUFBQSxFQUNOLFNBQVM7QUFBQSxFQUNULE1BQU07QUFBQSxJQUNKLENBQUMsUUFBUSxFQUFFLE1BQU0sZUFBZSxTQUFTO0FBQUEsSUFDekMsQ0FBQyxRQUFRLEVBQUUsTUFBTSxnQ0FBZ0MsU0FBUztBQUFBO0FBQUEsRUFFNUQsT0FBTyxhQUFhO0FBQUEsSUFDbEIsTUFBTTtBQUFBLElBQ04sTUFBTTtBQUFBLElBQ04sU0FBUztBQUFBLElBQ1QsUUFBUTtBQUFBLE1BQ04sRUFBRSxNQUFNLGdCQUFNLE1BQU07QUFBQSxNQUNwQixFQUFFLE1BQU0sNEJBQVEsTUFBTTtBQUFBLE1BQ3RCLEVBQUUsTUFBTSw0QkFBUSxNQUFNO0FBQUEsTUFDdEIsRUFBRSxNQUFNLGdCQUFNLE1BQU07QUFBQSxNQUNwQixFQUFFLE1BQU0sNEJBQVEsTUFBTTtBQUFBLE1BQ3RCLEVBQUUsTUFBTSwyQkFBWSxNQUFNO0FBQUEsTUFDMUIsRUFBRSxNQUFNLDRCQUFRLE1BQU07QUFBQSxNQUN0QixFQUFFLE1BQU0sT0FBTyxNQUFNO0FBQUEsTUFDckIsRUFBRSxNQUFNLE9BQU8sTUFBTTtBQUFBO0FBQUEsSUFFdkIsU0FBUztBQUFBLE1BQ1AsV0FBVztBQUFBLFFBQ1Q7QUFBQSxVQUNFLE1BQU07QUFBQSxVQUNOLFVBQVUsQ0FBQyx5QkFBeUI7QUFBQTtBQUFBO0FBQUEsTUFHeEMsa0JBQWtCO0FBQUEsUUFDaEI7QUFBQSxVQUNFLE1BQU07QUFBQSxVQUNOLFVBQVUsQ0FBQyw2QkFBNkI7QUFBQTtBQUFBO0FBQUEsTUFHNUMsY0FBYztBQUFBLFFBQ1o7QUFBQSxVQUNFLE1BQU07QUFBQSxVQUNOLFVBQVU7QUFBQSxZQUNSO0FBQUEsWUFDQTtBQUFBLFlBQ0E7QUFBQSxZQUNBO0FBQUE7QUFBQTtBQUFBO0FBQUEsTUFJTixnQkFBZ0I7QUFBQSxRQUNkO0FBQUEsVUFDRSxNQUFNO0FBQUEsVUFDTixVQUFVO0FBQUEsWUFDUjtBQUFBLFlBQ0E7QUFBQTtBQUFBO0FBQUE7QUFBQSxNQUlOLFNBQVM7QUFBQSxRQUNQO0FBQUEsVUFDRSxNQUFNO0FBQUEsVUFDTixVQUFVLENBQUM7QUFBQTtBQUFBO0FBQUEsTUFHZixTQUFTO0FBQUEsUUFDUDtBQUFBLFVBQ0UsTUFBTTtBQUFBLFVBQ04sVUFBVSxDQUFDLGVBQWU7QUFBQTtBQUFBO0FBQUE7QUFBQSxJQUloQyxVQUFVO0FBQUEsSUFDVixjQUFjO0FBQUEsSUFDZCxhQUFhO0FBQUE7QUFBQTsiLAogICJuYW1lcyI6IFtdCn0K
