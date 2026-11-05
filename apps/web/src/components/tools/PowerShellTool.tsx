import { extractIndicators } from "@bluebench/shared";
import { useEffect, useMemo, useState } from "react";
import { MAX_INFLATED_BYTES, MAX_LAYERS, decodePowerShell, type DecodedPowerShell } from "../../lib/powershell";
import { CodeBlock, Facts, FindingList, Panel } from "../ui";
import { BulkTool } from "./BulkTool";

export function PowerShellTool({ command, onUseAsInput }: { command: string; onUseAsInput: (text: string) => void }) {
  // Decompression is async, so the first render shows nothing until it's done (a few ms).
  const [decoded, setDecoded] = useState<DecodedPowerShell | null | undefined>(undefined);
  useEffect(() => {
    let current = true;
    void decodePowerShell(command).then((d) => current && setDecoded(d));
    return () => {
      current = false;
    };
  }, [command]);
  const indicators = useMemo(() => (decoded ? extractIndicators(decoded.layers.map((l) => l.text).join("\n")) : []), [decoded]);

  if (decoded === undefined) return <Panel title="PowerShell">Decoding…</Panel>;
  if (decoded === null) return <Panel title="PowerShell">The encoded command isn't valid base64 text.</Panel>;
  const last = decoded.layers[decoded.layers.length - 1]!;

  return (
    <>
      <Panel title="PowerShell">
        <p className="text-sm text-muted">Decoded only: nothing here was run, opened or sent anywhere.</p>
        <Facts
          rows={[
            ["Layers", decoded.layers.map((l) => l.how).join(" → "), true],
            ["Script encoding", last.encoding ?? "Unknown", true],
          ]}
        />
        <FindingList findings={decoded.findings} empty="Nothing in the script matched a known attack technique. That doesn't make it safe." />
        {decoded.truncated && (
          <p className="text-sm text-muted">
            Stopped early: a layer was over {MAX_INFLATED_BYTES / (1 << 20)} MB once decompressed, or there were more than {MAX_LAYERS} layers.
          </p>
        )}
        <CodeBlock label={decoded.layers.length > 1 ? "Innermost script" : "Decoded script"}>{last.text}</CodeBlock>
        {decoded.layers.length > 1 && (
          <details className="text-sm">
            <summary className="inline-flex min-h-11 cursor-pointer items-center text-muted underline hover:text-fg">
              Outer layers ({decoded.layers.length - 1})
            </summary>
            <div className="space-y-4">
              {decoded.layers.slice(0, -1).map((l, i) => (
                <CodeBlock key={i} label={`Layer ${i + 1}: ${l.how}`}>
                  {l.text}
                </CodeBlock>
              ))}
            </div>
          </details>
        )}
        {decoded.payload && (
          <CodeBlock label={`${decoded.payload.fileType ?? "Binary data"}, ${decoded.payload.size.toLocaleString("en")} bytes (hex dump)`}>
            {decoded.payload.hexDump}
          </CodeBlock>
        )}
      </Panel>
      {indicators.length > 0 && <BulkTool items={indicators} onUseAsInput={onUseAsInput} />}
    </>
  );
}
