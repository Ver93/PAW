export function decodeHexUtf8(hex) {
  try {
    const clean = String(hex).replace(
      /\s+/g,
      ""
    );

    const matches = clean.match(/.{1,2}/g);

    if (!matches) {
      return null;
    }

    const bytes = new Uint8Array(
      matches.map((byte) =>
        parseInt(byte, 16)
      )
    );

    return new TextDecoder("utf-8").decode(bytes);
  } catch {
    return null;
  }
}

export function fixMojibake(text) {
  try {
    const bytes = new Uint8Array(
      [...text].map((char) =>
        char.charCodeAt(0)
      )
    );

    return new TextDecoder("utf-8").decode(
      bytes
    );
  } catch {
    return text;
  }
}

export function getPacketPayload(packet) {
  if (packet.payloadText) {
    return {
      text: fixMojibake(packet.payloadText),
      type: "text",
    };
  }

  const payloadHex =
    packet.payloadHex ||
    packet.payload ||
    null;

  if (!payloadHex) {
    return {
      text: null,
      type: null,
    };
  }

  const decoded = decodeHexUtf8(payloadHex);

  if (decoded) {
    return {
      text: decoded,
      type: "text",
    };
  }

  return {
    text: payloadHex,
    type: "hex",
  };
}

export function preparePackets(flow, packets) {
  if (!flow) {
    return [];
  }

  return packets.map((packet, index) => {
    const outgoing =
      packet.direction === "A_TO_B";

    const source = outgoing
      ? flow.src
      : flow.dst;

    const destination = outgoing
      ? flow.dst
      : flow.src;

    return {
      packet,
      index,
      outgoing,
      source,
      destination,
      payload: getPacketPayload(packet),
    };
  });
}

export function getPacketKey(item) {
  return (
    item.packet.packet ??
    item.packet.index ??
    item.index
  );
}