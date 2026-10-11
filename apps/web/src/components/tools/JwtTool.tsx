import { decodeJwt } from "../../lib/jwt";
import { CodeBlock, Facts, FindingList, Panel } from "../ui";

export function JwtTool({ token }: { token: string }) {
  const jwt = decodeJwt(token);
  if (!jwt) return <Panel title="JWT">Couldn't decode this token.</Panel>;
  return (
    <Panel title="JWT">
      <FindingList findings={jwt.findings} />
      {jwt.times.length > 0 && <Facts rows={jwt.times.map((t) => [t.label, t.display])} />}
      <CodeBlock label="Header">{JSON.stringify(jwt.header, null, 2)}</CodeBlock>
      <CodeBlock label="Payload">{jwt.payloadText ?? JSON.stringify(jwt.payload, null, 2)}</CodeBlock>
      {jwt.signature && <CodeBlock label="Signature (base64url)">{jwt.signature}</CodeBlock>}
    </Panel>
  );
}
