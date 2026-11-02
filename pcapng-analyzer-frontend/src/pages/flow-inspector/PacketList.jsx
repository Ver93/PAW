import PacketRow from "./PacketRow";

export default function PacketList({
  packets = [],
  selectedPacket,
  onSelectPacket,
}) {
  return (
    <div className="fi-packet-list">
      <div className="fi-panel-header">
        <span>
          PACKETS
        </span>

        <span>
          {packets.length.toLocaleString()}
        </span>
      </div>

      <div className="fi-packet-stream">
        {packets.map((item) => (
          <PacketRow
            key={
              item.packet.packet ??
              item.packet.index ??
              item.index
            }
            item={item}
            selectedPacket={selectedPacket}
            onSelect={onSelectPacket}
          />
        ))}
      </div>
    </div>
  );
}