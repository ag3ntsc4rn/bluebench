import { analyzeUrl, decodeLayers } from "../../lib/url";
import { summarizeUrl } from "../../lib/summaries";
import { CodeBlock, CopyButton, Facts, FindingList, Panel } from "../ui";
import { Reputation } from "./Reputation";

export function UrlTool({ href }: { href: string }) {
  const url = analyzeUrl(href);
  if (!url) return <Panel title="URL">Couldn't parse this URL.</Panel>;
  return (
    <Panel title="URL" aside={<CopyButton value={summarizeUrl(url)} label="Copy result" />}>
      <FindingList findings={url.findings} empty="Nothing unusual in how this URL is built." />
      <Facts
        rows={[
          ["Scheme", url.scheme],
          ["Host", url.host],
          ...(url.port ? [["Port", url.port] as [string, string]] : []),
          ["Path", url.path],
          ...(url.fragment ? [["Fragment", url.fragment] as [string, string]] : []),
        ]}
      />
      {url.params.length > 0 && (
        <div>
          <h3 className="mb-1 text-sm font-medium text-muted">Query parameters (decoded)</h3>
          <Facts rows={url.params.map(([k, v]) => [k, v || "(empty)"])} />
        </div>
      )}
      {url.decoded !== url.href && <CodeBlock label="Decoded URL">{url.decoded}</CodeBlock>}
      <CodeBlock label="Normalized URL">{url.href}</CodeBlock>
      <Reputation kind="url" value={url.href} />
    </Panel>
  );
}

export function UrlDecodeTool({ text }: { text: string }) {
  const layers = decodeLayers(text).slice(1);
  return (
    <Panel title="URL decode">
      {layers.length > 1 && <p className="text-sm text-muted">Encoded {layers.length} times. Each layer is shown below.</p>}
      {layers.map((layer, i) => (
        <CodeBlock key={i} label={layers.length > 1 ? `Layer ${i + 1}` : "Decoded"}>
          {layer}
        </CodeBlock>
      ))}
    </Panel>
  );
}
