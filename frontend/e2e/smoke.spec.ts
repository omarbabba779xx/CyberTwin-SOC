import { test, expect } from "@playwright/test";

test.describe("Smoke", () => {
  test("serves SPA shell", async ({ page }) => {
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await expect(page).toHaveTitle(/CyberTwin SOC/i);
    await expect(page.locator("body")).toBeVisible();
  });

  test("root mounts React (#root)", async ({ page }) => {
    await page.goto("/", { waitUntil: "domcontentloaded" });
    const root = page.locator("#root");
    await expect(root).toBeAttached();
  });

  test("authenticates with mocked API and opens Atomic Red Team metadata", async ({ page }) => {
    await page.route("**/api/**", async (route) => {
      const url = new URL(route.request().url());
      const json = (body: unknown, status = 200) =>
        route.fulfill({
          status,
          contentType: "application/json",
          body: JSON.stringify(body),
        });

      if (url.pathname === "/api/auth/login") {
        return json({ token: "mock-access-token", username: "admin", role: "admin" });
      }
      if (url.pathname === "/api/scenarios") return json([]);
      if (url.pathname === "/api/environment") return json({ hosts: {} });
      if (url.pathname === "/api/mitre/techniques") return json({});
      if (url.pathname === "/api/threat-intel") {
        return json({ threat_actors: [], iocs: {}, references: [] });
      }
      if (url.pathname === "/api/mitre/atomic-red-team") {
        return json({
          configured: true,
          available: true,
          root: "C:/atomic-red-team",
          atomics_dir: "C:/atomic-red-team/atomics",
          technique_count: 2,
          techniques: ["T1059", "T1110"],
        });
      }
      if (url.pathname === "/api/mitre/atomic-red-team/T1059") {
        return json({
          technique_id: "T1059",
          display_name: "Command and Scripting Interpreter",
          source_path: "C:/atomic-red-team/atomics/T1059/T1059.yaml",
          atomic_test_count: 1,
          supported_platforms: ["windows"],
          executors: ["command_prompt"],
          tests: [
            {
              name: "Command Prompt",
              guid: "00000000-0000-4000-8000-000000000001",
              description: "Metadata-only fixture without executable commands.",
              supported_platforms: ["windows"],
              executor: "command_prompt",
              elevation_required: false,
              input_arguments: ["command"],
              dependency_count: 0,
            },
          ],
        });
      }

      return json({}, 404);
    });

    await page.goto("/", { waitUntil: "domcontentloaded" });
    await page.getByPlaceholder("admin").fill("admin");
    await page.getByPlaceholder("cybertwin2024").fill("cybertwin2024");
    await page.locator('button[type="submit"]').click();

    await expect(page.locator("text=CyberTwin").first()).toBeVisible();
    await page.getByRole("button", { name: /Atomic Red Team/i }).click();
    await expect(page.getByRole("heading", { name: "Atomic Red Team" })).toBeVisible();
    await expect(page.getByText("Commands exposed")).toBeVisible();
    await expect(page.getByText("Command Prompt")).toBeVisible();
  });

  test("runs a mocked SOC case lifecycle from creation to closure", async ({ page }) => {
    let currentCase: any = null;

    await page.route("**/api/**", async (route) => {
      const request = route.request();
      const url = new URL(request.url());
      const json = (body: unknown, status = 200) =>
        route.fulfill({
          status,
          contentType: "application/json",
          body: JSON.stringify(body),
        });

      if (url.pathname === "/api/auth/login") {
        return json({ token: "mock-access-token", username: "admin", role: "admin" });
      }
      if (url.pathname === "/api/scenarios") return json([]);
      if (url.pathname === "/api/environment") return json({ hosts: {} });
      if (url.pathname === "/api/mitre/techniques") return json({});
      if (url.pathname === "/api/threat-intel") {
        return json({ threat_actors: [], iocs: {}, references: [] });
      }
      if (url.pathname === "/api/cases" && request.method() === "GET") {
        return json({ total: currentCase ? 1 : 0, cases: currentCase ? [currentCase] : [] });
      }
      if (url.pathname === "/api/cases" && request.method() === "POST") {
        const body = JSON.parse(request.postData() || "{}");
        currentCase = {
          case_id: "CASE-E2E",
          title: body.title,
          description: body.description || "",
          severity: body.severity || "medium",
          status: "new",
          assignee: null,
          sla_due_at: "2026-05-01T20:00:00+00:00",
          alert_ids: [],
          mitre_techniques: [],
          comments: [],
          evidence: [],
        };
        return json(currentCase);
      }
      if (url.pathname === "/api/cases/CASE-E2E" && request.method() === "GET") {
        return json(currentCase || {}, currentCase ? 200 : 404);
      }
      if (url.pathname === "/api/cases/CASE-E2E/comments" && request.method() === "POST") {
        const body = JSON.parse(request.postData() || "{}");
        currentCase.comments.push({
          comment_id: 1,
          author: "admin",
          timestamp: "2026-05-01T19:00:00+00:00",
          body: body.body,
        });
        return json(currentCase.comments[0]);
      }
      if (url.pathname === "/api/cases/CASE-E2E/close" && request.method() === "POST") {
        currentCase.status = "closed";
        currentCase.closed_at = "2026-05-01T19:05:00+00:00";
        return json(currentCase);
      }

      return json({}, 404);
    });

    await page.goto("/", { waitUntil: "domcontentloaded" });
    await page.getByPlaceholder("admin").fill("admin");
    await page.getByPlaceholder("cybertwin2024").fill("cybertwin2024");
    await page.locator('button[type="submit"]').click();

    await page.getByRole("button", { name: /nav\.cases|Cases/i }).click();
    await expect(page.getByRole("heading", { name: "Case Management" })).toBeVisible();
    await page.getByPlaceholder(/Case title/i).fill("E2E analyst case");
    await page.getByPlaceholder("Description").fill("Suspicious login investigation");
    await page.getByRole("button", { name: "Create case" }).click();

    await expect(page.getByText("E2E analyst case").first()).toBeVisible();
    await page.getByText("E2E analyst case").first().click();
    await page.getByPlaceholder("Add a comment...").fill("Initial triage complete");
    await page.getByRole("button", { name: "Add" }).click();
    await expect(page.getByText("Initial triage complete")).toBeVisible();
    await page.getByPlaceholder(/Closure reason/i).fill("Issue fully investigated");
    await page.getByRole("button", { name: "Close case" }).click();
    await expect(page.getByText("closed").first()).toBeVisible();
  });
});
