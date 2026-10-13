/** Save text as a file, entirely in the browser (a blob URL; nothing is uploaded). */
export function downloadText(filename: string, text: string, type: string): void {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.append(a);
  a.click();
  a.remove();
  // Give the browser a moment to start the download before releasing the blob.
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

/** e.g. bluebench-iocs-20261013-1405 (local time). */
export function stampedName(prefix: string, now = new Date()): string {
  const p = (n: number) => String(n).padStart(2, "0");
  return `${prefix}-${now.getFullYear()}${p(now.getMonth() + 1)}${p(now.getDate())}-${p(now.getHours())}${p(now.getMinutes())}`;
}
