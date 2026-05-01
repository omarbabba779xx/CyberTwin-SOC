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
});
