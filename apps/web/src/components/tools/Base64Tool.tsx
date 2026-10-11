import { detect, KIND_LABELS } from "@bluebench/shared";
import { decodeBase64, HEX_DUMP_LIMIT } from "../../lib/base64";
import { Badge, CodeBlock, Facts, Panel } from "../ui";

export function Base64Tool({ value, onUseAsInput }: { value: string; onUseAsInput: (text: string) => void }) {
  const decoded = decodeBase64(value);
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
