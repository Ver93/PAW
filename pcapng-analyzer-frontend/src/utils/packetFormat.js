
export function chunkHex(bytes = []) {
  const lines = [];

  for (let i = 0; i < bytes.length; i += 16) {
    const slice = bytes.slice(i, i + 16);

    const offset = i
      .toString(16)
      .padStart(8, "0");

    const hex = slice
      .map((byte) =>
        byte.toString(16).padStart(2, "0")
      )
      .join(" ");

    const paddedHex = hex.padEnd(47, " ");

    lines.push(
      `${offset}  ${paddedHex}`
    );
  }

  return lines.join("\n");
}

export function chunkAscii(bytes = []) {
  const lines = [];

  for (let i = 0; i < bytes.length; i += 16) {
    const slice = bytes.slice(i, i + 16);

    const ascii = slice
      .map((byte) =>
        byte >= 32 && byte <= 126
          ? String.fromCharCode(byte)
          : "."
      )
      .join("");

    lines.push(ascii);
  }

  return lines.join("\n");
}

export function formatNumber(value) {
  return new Intl.NumberFormat("en-US").format(
    Number(value) || 0
  );
}

export function formatBytes(bytes) {
  if (!bytes) {
    return "0 B";
  }

  if (bytes < 1024) {
    return `${bytes} B`;
  }

  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }

  if (bytes < 1024 * 1024 * 1024) {
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  }

  return `${(
    bytes /
    (1024 * 1024 * 1024)
  ).toFixed(1)} GB`;
}

