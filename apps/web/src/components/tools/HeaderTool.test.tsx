import { renderToString } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { TOOLS } from "../../routes";
import { HeaderTool } from "./HeaderTool";

const text = (html: string) => html.replace(/<!-- -->/g, "").replace(/&#x27;/g, "'");

describe("HeaderTool explanations", () => {
  it("explains SPF, DKIM, DMARC and the hop path where they're shown", () => {
    const example = TOOLS.find((t) => t.slug === "email-header-analyzer")!.example;
    const html = text(renderToString(<HeaderTool raw={example} />));
    expect(html.match(/<summary[^>]*>What's this\?<\/summary>/g)).toHaveLength(4);
    expect(html).toContain("This is the result that matters most for spotting a forged sender.");
    expect(html).toContain("Only the hops added by your own provider can be trusted");
  });
});
