import { useMemo } from "react";

import PacketList from "./PacketList";
import PacketInspector from "./PacketInspector";

import {
  preparePackets,
} from "./packetUtils";

export default function FlowTraffic({
  flow,
  packets,
  protocolPackets,
  viewMode,
  selectedPacket,
  onViewModeChange,
  onSelectPacket,
  onCloseInspector,
}) {
  const preparedPackets = useMemo(() => {
    return preparePackets(flow, packets);
  }, [flow, packets]);

  const fullStream = useMemo(() => {
    return preparedPackets
      .filter((item) => item.payload.text)
      .map((item) => item.payload.text)
      .join("");
  }, [preparedPackets]);

  const fullStreamHex = useMemo(() => {
    return preparedPackets
      .map((item) => {
        const payload =
          item.packet.payloadHex ||
          item.packet.payload ||
          "";

        return String(payload).replace(/\s+/g, "");
      })
      .filter(Boolean)
      .join("");
  }, [preparedPackets]);

  return (
    <section className="fi-stream-section">
      <div className="fi-stream-header">
        <div className="fi-stream-title">
          <span className="fi-traffic-label">
            TRAFFIC
          </span>

          <h2>Follow Stream</h2>

          <p>
            Inspect individual packets or view the complete payload.
          </p>
        </div>

        <div className="fi-stream-controls">
          <div className="fi-toggle">
            <button
              type="button"
              className={viewMode === "packets" ? "active" : ""}
              onClick={() => onViewModeChange("packets")}
            >
              Packets
            </button>

            <button
              type="button"
              className={viewMode === "stream" ? "active" : ""}
              onClick={() => onViewModeChange("stream")}
            >
              Full Stream
            </button>
          </div>

          <span className="fi-packet-count">
            {packets.length.toLocaleString()} packets
          </span>
        </div>
      </div>

      {packets.length === 0 ? (
        <div className="fi-empty">
          No packet data is available for this flow.
        </div>
      ) : viewMode === "stream" ? (
        <div className="fi-full-stream">
          {fullStream ? (
            <pre>{fullStream}</pre>
          ) : fullStreamHex ? (
            <pre className="fi-hex-stream">
              {fullStreamHex}
            </pre>
          ) : (
            <div className="fi-empty">
              No payload data is available for this flow.
            </div>
          )}
        </div>
      ) : (
        <div className="fi-analysis-layout">
          <PacketList
            packets={preparedPackets}
            selectedPacket={selectedPacket}
            onSelectPacket={onSelectPacket}
          />

          <PacketInspector
            flow={flow}
            packets={protocolPackets}
            selectedPacket={selectedPacket}
            onClose={onCloseInspector}
          />
        </div>
      )}
    </section>
  );
}