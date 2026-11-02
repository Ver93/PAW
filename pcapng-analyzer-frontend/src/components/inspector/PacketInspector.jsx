import { memo } from "react";
import "./PacketInspector.css";

import PacketMeta from "./PacketMeta";
import PacketDump from "./PacketDump";

const PacketInspector = memo(function PacketInspector({
  packet,
  onClose,
}) {
  if (!packet) {
    return (
      <aside className="inspector-empty">
        <div className="inspector-empty-icon">
          ◇
        </div>

        <h3>No packet selected</h3>

        <p>
          Select a packet from the table to inspect
          its contents.
        </p>
      </aside>
    );
  }

  return (
    <aside className="inspector-card">
      <div className="inspector-header">
        <div>
          <div className="eyebrow">
            PACKET INSPECTOR
          </div>

          <h2>
            Packet #{packet.packet_number}
          </h2>
        </div>

        <button
          className="close-button"
          onClick={onClose}
          aria-label="Close packet inspector"
        >
          ×
        </button>
      </div>

      <PacketMeta packet={packet} />

      <PacketDump packet={packet} />
    </aside>
  );
});

export default PacketInspector;