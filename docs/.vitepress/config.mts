import { defineConfig } from "vitepress";

// Public documentation site for DIP. Built from the markdown in this folder.
// Served from https://pavancharak.github.io/dip/ by .github/workflows/docs.yml.
export default defineConfig({
  title: "DIP",
  description:
    "Decision Integrity Protocol: deterministic ALLOW/DENY authorization with signed, verifiable evidence.",
  base: "/dip/",
  cleanUrls: true,
  // Each folder's README.md is its index page (the repository browser shows it, and the site serves it at the folder URL).
  rewrites: {
    "README.md": "index.md",
    "deployment/README.md": "deployment/index.md",
    "deployment/aws/README.md": "deployment/aws/index.md",
    "how-to/README.md": "how-to/index.md",
    "spec/README.md": "spec/index.md",
  },
  lastUpdated: true,
  // Some pages link to files at the repository root (examples, CONTRIBUTING, CHANGELOG).
  // Those files are not part of the site, so their links are excluded from the dead-link check.
  ignoreDeadLinks: [/\.\.\//],
  themeConfig: {
    nav: [
      { text: "How to use", link: "/how-to/" },
      { text: "Deploy", link: "/deployment/" },
      { text: "Reference", link: "/SDK" },
      { text: "Specification", link: "/spec/" },
      { text: "GitHub", link: "https://github.com/pavancharak/dip" },
    ],
    sidebar: [
      {
        text: "Start",
        items: [
          { text: "Overview", link: "/" },
          { text: "Quick start", link: "/QUICKSTART" },
          { text: "Installation", link: "/INSTALL" },
          { text: "Integration guide", link: "/INTEGRATION" },
        ],
      },
      {
        text: "How to use DIP",
        collapsed: false,
        items: [
          { text: "Introduction", link: "/how-to/" },
          { text: "1. Concepts", link: "/how-to/01-concepts" },
          { text: "2. Run the example", link: "/how-to/02-run-the-example" },
          { text: "3. Declare an authority", link: "/how-to/03-declare-an-authority" },
          { text: "4. Authorize and execute", link: "/how-to/04-authorize-and-execute" },
          { text: "5. Approvals", link: "/how-to/05-approvals" },
          { text: "6. Evidence and verification", link: "/how-to/06-evidence-and-verification" },
          { text: "7. Use the API", link: "/how-to/07-use-the-api" },
          { text: "8. Use the CLI", link: "/how-to/08-use-the-cli" },
          { text: "9. Troubleshooting", link: "/how-to/09-troubleshooting" },
        ],
      },
      {
        text: "Reference",
        items: [
          { text: "SDK", link: "/SDK" },
          { text: "CLI", link: "/CLI" },
          {
            text: "REST API (OpenAPI)",
            link: "https://github.com/pavancharak/dip/blob/main/docs/api/openapi.json",
          },
          { text: "Verification", link: "/VERIFICATION" },
          { text: "Connectors", link: "/CONNECTORS" },
          { text: "Troubleshooting", link: "/TROUBLESHOOTING" },
        ],
      },
      {
        text: "Deploy",
        collapsed: false,
        items: [
          { text: "Deployment overview", link: "/deployment/" },
          { text: "Environment variables", link: "/deployment/ENVIRONMENT" },
          { text: "AWS guide", link: "/deployment/aws/" },
          { text: "AWS 01. Overview", link: "/deployment/aws/01-overview" },
          { text: "AWS 02. Prerequisites", link: "/deployment/aws/02-prerequisites" },
          { text: "AWS 03. KMS keys", link: "/deployment/aws/03-kms-keys" },
          { text: "AWS 04. IAM roles", link: "/deployment/aws/04-iam-roles" },
          { text: "AWS 05. Secrets", link: "/deployment/aws/05-secrets" },
          { text: "AWS 06. Database", link: "/deployment/aws/06-database" },
          { text: "AWS 07. Build and push", link: "/deployment/aws/07-build-and-push" },
          { text: "AWS 08. Deploy", link: "/deployment/aws/08-deploy" },
          { text: "AWS 09. Verify", link: "/deployment/aws/09-verify" },
          { text: "AWS 10. Troubleshooting", link: "/deployment/aws/10-troubleshooting" },
          { text: "AWS 11. Operations", link: "/deployment/aws/11-operations" },
        ],
      },
      {
        text: "Protocol and design",
        items: [
          { text: "Specification", link: "/spec/" },
          { text: "Threat model", link: "/THREAT-MODEL" },
          { text: "Architecture decisions", link: "/ARCHITECTURE_DECISIONS" },
          { text: "Key management", link: "/KEY-MANAGEMENT" },
          { text: "Retention", link: "/RETENTION" },
        ],
      },
      {
        text: "Project status",
        items: [
          { text: "Build status", link: "/BUILD_STATUS" },
          { text: "Implementation matrix", link: "/IMPLEMENTATION_MATRIX" },
          { text: "Release audit", link: "/RELEASE-AUDIT" },
        ],
      },
    ],
    socialLinks: [{ icon: "github", link: "https://github.com/pavancharak/dip" }],
    footer: {
      message: "Released under the Apache License 2.0.",
      copyright: "Copyright 2026 pavancharak",
    },
    search: { provider: "local" },
  },
});
