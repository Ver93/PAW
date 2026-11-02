function formatMac(value) {
  if (!value) return "—";
  return String(value);
}

function formatIp(value) {
  if (!value) return "—";
  return String(value);
}

function formatHex(value) {
  if (value === undefined || value === null) {
    return "—";
  }

  if (typeof value === "number") {
    return `0x${value.toString(16).padStart(4, "0")}`;
  }

  return String(value);
}

function formatFlags(packet) {
  const flags = [];

  if (packet.ns) flags.push("NS");
  if (packet.cwr) flags.push("CWR");
  if (packet.ece) flags.push("ECE");
  if (packet.urg) flags.push("URG");
  if (packet.ack) flags.push("ACK");
  if (packet.psh) flags.push("PSH");
  if (packet.rst) flags.push("RST");
  if (packet.syn) flags.push("SYN");
  if (packet.fin) flags.push("FIN");

  return flags.length ? flags.join(" · ") : "—";
}

function Field({ label, value }) {
  return (
    <div className="fi-field">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function Layer({ title, type, children }) {
  return (
    <section className="fi-inspector-layer">
      <div className="fi-layer-header">
        <div>
          <span className="fi-layer-type">{type}</span>
          <h4>{title}</h4>
        </div>
      </div>

      <div className="fi-layer-fields">
        {children}
      </div>
    </section>
  );
}

function EthernetLayer({ packet }) {
  return (
    <Layer title="Ethernet II" type="L2">
      <Field
        label="Source MAC"
        value={formatMac(packet.sourceMac)}
      />

      <Field
        label="Destination MAC"
        value={formatMac(packet.destinationMac)}
      />

      <Field
        label="EtherType"
        value={formatHex(packet.etherType)}
      />
    </Layer>
  );
}

function IPv4Layer({ packet }) {
  return (
    <Layer title="Internet Protocol Version 4" type="L3">
      <Field
        label="Source"
        value={formatIp(packet.source)}
      />

      <Field
        label="Destination"
        value={formatIp(packet.destination)}
      />

      <Field
        label="Version"
        value={packet.version ?? "—"}
      />

      <Field
        label="Header length"
        value={
          packet.headerLength !== undefined
            ? `${packet.headerLength} bytes`
            : "—"
        }
      />

      <Field
        label="Total length"
        value={
          packet.totalLength !== undefined
            ? `${packet.totalLength} bytes`
            : "—"
        }
      />

      <Field
        label="Identification"
        value={packet.identification ?? "—"}
      />

      <Field
        label="TTL"
        value={packet.ttl ?? "—"}
      />

      <Field
        label="Protocol"
        value={packet.protocol ?? "—"}
      />

      <Field
        label="Checksum"
        value={formatHex(packet.checksum)}
      />

      <Field
        label="Fragment offset"
        value={packet.fragmentOffset ?? 0}
      />

      <Field
        label="Payload length"
        value={
          packet.payloadLength !== undefined
            ? `${packet.payloadLength} bytes`
            : "—"
        }
      />
    </Layer>
  );
}

function IPv6Layer({ packet }) {
  return (
    <Layer title="Internet Protocol Version 6" type="L3">
      <Field
        label="Source"
        value={formatIp(packet.source)}
      />

      <Field
        label="Destination"
        value={formatIp(packet.destination)}
      />

      <Field
        label="Version"
        value={packet.version ?? "—"}
      />

      <Field
        label="Traffic class"
        value={packet.trafficClass ?? "—"}
      />

      <Field
        label="Flow label"
        value={packet.flowLabel ?? "—"}
      />

      <Field
        label="Payload length"
        value={
          packet.payloadLength !== undefined
            ? `${packet.payloadLength} bytes`
            : "—"
        }
      />

      <Field
        label="Next header"
        value={packet.nextHeader ?? "—"}
      />

      <Field
        label="Hop limit"
        value={packet.hopLimit ?? "—"}
      />
    </Layer>
  );
}

function TCPLayer({ packet }) {
  return (
    <Layer title="Transmission Control Protocol" type="L4">
      <Field
        label="Source port"
        value={packet.sourcePort ?? "—"}
      />

      <Field
        label="Destination port"
        value={packet.destinationPort ?? "—"}
      />

      <Field
        label="Sequence number"
        value={packet.sequenceNumber ?? "—"}
      />

      <Field
        label="Acknowledgment number"
        value={packet.acknowledgmentNumber ?? "—"}
      />

      <Field
        label="Header length"
        value={
          packet.headerLength !== undefined
            ? `${packet.headerLength} bytes`
            : "—"
        }
      />

      <Field
        label="Flags"
        value={formatFlags(packet)}
      />

      <Field
        label="Window size"
        value={packet.windowSize ?? "—"}
      />

      <Field
        label="Checksum"
        value={formatHex(packet.checksum)}
      />

      <Field
        label="Urgent pointer"
        value={packet.urgentPointer ?? "—"}
      />

      {packet.has_mss && (
        <Field
          label="Maximum segment size"
          value={packet.maximumSegmentSize ?? "—"}
        />
      )}

      {packet.has_window_scale && (
        <Field
          label="Window scale"
          value={packet.windowScale ?? "—"}
        />
      )}

      <Field
        label="SACK permitted"
        value={
          packet.sackPermitted === undefined
            ? "—"
            : packet.sackPermitted
              ? "Yes"
              : "No"
        }
      />

      {packet.has_timestamp && (
        <>
          <Field
            label="Timestamp"
            value={packet.timestampValue ?? "—"}
          />

          <Field
            label="Timestamp echo"
            value={packet.timestampEchoReply ?? "—"}
          />
        </>
      )}

      <Field
        label="Payload length"
        value={
          packet.payloadLength !== undefined
            ? `${packet.payloadLength} bytes`
            : "—"
        }
      />
    </Layer>
  );
}

function UDPLayer({ packet }) {
  return (
    <Layer title="User Datagram Protocol" type="L4">
      <Field
        label="Source port"
        value={packet.sourcePort ?? "—"}
      />

      <Field
        label="Destination port"
        value={packet.destinationPort ?? "—"}
      />

      <Field
        label="Length"
        value={
          packet.length !== undefined
            ? `${packet.length} bytes`
            : "—"
        }
      />

      <Field
        label="Checksum"
        value={formatHex(packet.checksum)}
      />

      <Field
        label="Payload length"
        value={
          packet.payloadLength !== undefined
            ? `${packet.payloadLength} bytes`
            : "—"
        }
      />
    </Layer>
  );
}

function ICMPLayer({ packet }) {
  return (
    <Layer title="Internet Control Message Protocol" type="L3">
      <Field
        label="Type"
        value={packet.type ?? "—"}
      />

      <Field
        label="Code"
        value={packet.code ?? "—"}
      />

      <Field
        label="Checksum"
        value={formatHex(packet.checksum)}
      />

      <Field
        label="Rest of header"
        value={formatHex(packet.restOfHeader)}
      />

      <Field
        label="Payload length"
        value={
          packet.payloadLength !== undefined
            ? `${packet.payloadLength} bytes`
            : "—"
        }
      />
    </Layer>
  );
}

function PayloadLayer({ selectedPacket }) {
  const hex =
    selectedPacket?.payloadHex ||
    selectedPacket?.payload?.hex ||
    "";

  const text =
    selectedPacket?.payloadText ||
    selectedPacket?.payload?.text ||
    "";

  if (!hex && !text) {
    return (
      <Layer title="Payload" type="DATA">
        <div className="fi-no-payload">
          No payload available.
        </div>
      </Layer>
    );
  }

  return (
    <Layer title="Payload" type="DATA">
      {text && (
        <div className="fi-payload-block">
          <span>Text</span>
          <pre>{text}</pre>
        </div>
      )}

      {hex && (
        <div className="fi-payload-block">
          <span>Hex</span>
          <pre>{hex}</pre>
        </div>
      )}
    </Layer>
  );
}

export default function PacketInspector({
  flow,
  packets = [],
  selectedPacket,
  onClose,
}) {
  if (!selectedPacket) {
    return (
      <aside className="fi-packet-inspector">
        <div className="fi-inspector-empty">
          <div className="fi-inspector-icon">◇</div>

          <span className="fi-inspector-eyebrow">
            PACKET INSPECTOR
          </span>

          <h3>Select a packet</h3>

          <p>
            Select a packet from the list to inspect its
            protocol layers and payload.
          </p>
        </div>
      </aside>
    );
  }

  /*
   * selectedPacket comes from flow.packets.
   *
   * Example:
   * {
   *   packet: 0,
   *   direction: "A_TO_B",
   *   payloadLength: 20,
   *   ...
   * }
   *
   * The complete protocol information lives in
   * analysis.packets, where every protocol layer has
   * the same packet number.
   */
  const packetIndex =
    selectedPacket.packet?.packet ??
    selectedPacket.packet?.index ??
    selectedPacket.packet ??
    selectedPacket.index;

  const packetLayers = packets.filter(
    (item) =>
      String(item.packet) === String(packetIndex)
  );

  const ethernet = packetLayers.find(
    (item) => item.type === "Ethernet"
  );

  const ipv4 = packetLayers.find(
    (item) => item.type === "IPv4"
  );

  const ipv6 = packetLayers.find(
    (item) => item.type === "IPv6"
  );

  const tcp = packetLayers.find(
    (item) => item.type === "TCP"
  );

  const udp = packetLayers.find(
    (item) => item.type === "UDP"
  );

  const icmp = packetLayers.find(
    (item) => item.type === "ICMP"
  );

  return (
    <aside className="fi-packet-inspector">
      <div className="fi-inspector-header">
        <div>
          <span className="fi-inspector-eyebrow">
            PACKET
          </span>

          <h3>#{Number(packetIndex) + 1}</h3>
        </div>

        <button
          type="button"
          className="fi-inspector-close"
          onClick={onClose}
          aria-label="Close packet inspector"
        >
          ×
        </button>
      </div>

      <div className="fi-inspector-direction">
        <span>
          {selectedPacket.source || flow?.src || "—"}
        </span>

        <strong>→</strong>

        <span>
          {selectedPacket.destination || flow?.dst || "—"}
        </span>
      </div>

      {packetLayers.length === 0 ? (
        <div className="fi-inspector-empty">
          <div className="fi-inspector-icon">!</div>

          <span className="fi-inspector-eyebrow">
            NO PROTOCOL DATA
          </span>

          <h3>
            Packet #{Number(packetIndex) + 1}
          </h3>

          <p>
            No protocol-layer information was found for
            packet index {packetIndex}.
          </p>
        </div>
      ) : (
        <div className="fi-protocol-stack">
          {ethernet && (
            <EthernetLayer packet={ethernet} />
          )}

          {ipv4 && (
            <IPv4Layer packet={ipv4} />
          )}

          {ipv6 && (
            <IPv6Layer packet={ipv6} />
          )}

          {tcp && (
            <TCPLayer packet={tcp} />
          )}

          {udp && (
            <UDPLayer packet={udp} />
          )}

          {icmp && (
            <ICMPLayer packet={icmp} />
          )}

          <PayloadLayer
            selectedPacket={selectedPacket}
          />
        </div>
      )}
    </aside>
  );
}