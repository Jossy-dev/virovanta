import { render, screen } from "@testing-library/react";
import App from "./App";

describe("App", () => {
  it("renders authentication view when no session exists", async () => {
    localStorage.clear();

    render(<App />);

    expect(
      await screen.findByRole("heading", { name: /scan suspicious files in seconds before they hit your systems/i })
    ).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: /quick guest scan/i })).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: /sign in/i }).length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: /create account/i })).toBeInTheDocument();
  });
});
