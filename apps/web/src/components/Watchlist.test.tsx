import type { Me, Watch } from "@bluebench/shared";
import { renderToString } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { Watchlist } from "./Watchlist";

const text = (html: string) => html.replace(/<!-- -->/g, "").replace(/&#x27;/g, "'");
const noop = async () => null;
const signedIn: Me = { ok: true, signedIn: true, accountsEnabled: true, email: "a@example.org", emailAlerts: true, pushKey: null };
const props = { onAdd: noop, onRemove: noop };

describe("Watchlist", () => {
  it("invites signed-out visitors to sign in", () => {
    const html = text(renderToString(<Watchlist me={{ ok: true, signedIn: false, accountsEnabled: true }} watches={null} {...props} />));
    expect(html).toContain("Watch your products");
    expect(html).toContain('href="/alerts"');
  });

  it("lists watches with a labelled remove button, and a vendor/product picker", () => {
    const watches: Watch[] = [
      { id: "1", vendor: "Fortinet", product: null, createdAt: "" },
      { id: "2", vendor: "Microsoft", product: "Exchange Server", createdAt: "" },
    ];
    const html = text(renderToString(<Watchlist me={signedIn} watches={watches} {...props} />));
    expect(html).toContain("Fortinet<span class=\"text-muted\"> (all products)</span>");
    expect(html).toContain('aria-label="Stop watching Microsoft Exchange Server"');
    expect(html).toMatch(/<label[^>]*>Vendor<\/label>/);
    expect(html).toContain("All products");
  });

  it("renders nothing while the account is loading", () => {
    expect(renderToString(<Watchlist me={null} watches={null} {...props} />)).toBe("");
  });
});
