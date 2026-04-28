import { test, expect } from "@playwright/test";

test.describe("Smoke", () => {
  test("serves SPA shell", async ({ page }) => {
    await page.goto("/");
    await expect(page).toHaveTitle(/CyberTwin SOC/i);
    await expect(page.locator("body")).toBeVisible();
  });

  test("root mounts React (#root)", async ({ page }) => {
    await page.goto("/");
    const root = page.locator("#root");
    await expect(root).toBeAttached();
  });
});
