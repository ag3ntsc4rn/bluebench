import { base64ToBytes, bytesToText, detect, KIND_LABELS } from "@bluebench/shared";
import { useEffect, useState } from "react";
import { decodeBase64, HEX_DUMP_LIMIT, hexDump } from "../../lib/base64";
import { inflate, MAX_INFLATED_BYTES } from "../../lib/powershell";
import { Badge, CodeBlock, Facts, Panel } from "../ui";

/** What a gzip blob holds: text if it's text, else a hex dump. Undefined until decompressed. */
function useGunzipped(value: string, isGzip: boolean) {
  const [out, setOut] = useState<{ text?: string; hexDump?: string; truncated: boolean } | null | undefined>(undefined);
  useEffect(() => {
    if (!isGzip) return;
    let current = true;
    void inflate(base64ToBytes(value)!, "gzip").then((r) => {
      if (!current) return;
      if (!r) return setOut(null);
      const text = bytesToText(r.bytes);
      setOut(text ? { text: text.text, truncated: r.truncated } : { hexDump: hexDump(r.bytes), truncated: r.truncated });
    });
    return () => {
      current = false;
    };
  }, [value, isGzip]);
  return out;
}

export function Base64Tool({ value, onUseAsInput }: { value: string; onUseAsInput: (text: string) => void }) {
  const decoded = decodeBase64(value);
  const gunzipped = useGunzipped(value, decoded?.fileType === "gzip archive");
  if (!decoded) return <Panel title="Base64">This isn't valid base64.</Panel>;
  const nested = decoded.text ? detect(decoded.text)[0] : undefined;

  return (
    <Panel title="Base64">
      <Facts
        rows={[
          ["Size", `${decoded.size.toLocaleString("en")} bytes`, true],
          ["Content", decoded.fileType ?? (decoded.text ? `Text (${decoded.encoding})` : "Binary data"), true],
        ]}
      />
      {decoded.fileType && (
        <p className="flex items-start gap-2 text-sm">
          <Badge tone="warn">Warning</Badge>
          <span>Decoded to a file. Don't save or open it unless you're working in a safe analysis environment.</span>
        </p>
      )}
      {decoded.encoding === "UTF-16LE" && (
        <p className="text-sm text-muted">UTF-16LE text is typical of PowerShell -EncodedCommand payloads.</p>
      )}
      {decoded.text !== undefined && <CodeBlock label="Decoded text">{decoded.text}</CodeBlock>}
      {gunzipped === null && <p className="text-sm text-muted">It looks like gzip but didn't decompress.</p>}
      {gunzipped && (
        <>
          {gunzipped.truncated && <p className="text-sm text-muted">Showing the first {MAX_INFLATED_BYTES / (1 << 20)} MB once decompressed.</p>}
          {gunzipped.text !== undefined ? (
            <CodeBlock label="Decompressed text">{gunzipped.text}</CodeBlock>
          ) : (
            <CodeBlock label={`Decompressed (hex dump, first ${HEX_DUMP_LIMIT} bytes)`}>{gunzipped.hexDump!}</CodeBlock>
          )}
        </>
      )}
      {decoded.hexDump && (
        <CodeBlock label={decoded.truncated ? `Hex dump (first ${HEX_DUMP_LIMIT} bytes)` : "Hex dump"}>{decoded.hexDump}</CodeBlock>
      )}
      {nested && decoded.text && (
        <button
          type="button"
          onClick={() => onUseAsInput(decoded.text!)}
          className="min-h-11 rounded-md bg-accent px-4 text-sm font-medium text-on-accent"
        >
          Analyse decoded text ({KIND_LABELS[nested.kind]})
        </button>
      )}
    </Panel>
  );
}
