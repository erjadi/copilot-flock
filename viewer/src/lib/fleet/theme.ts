export type Theme = "light" | "dark";
export const THEME_KEY = "copilot-flock-theme";
export function resolveTheme(value: string | null): Theme {
  return value === "light" ? "light" : "dark";
}
