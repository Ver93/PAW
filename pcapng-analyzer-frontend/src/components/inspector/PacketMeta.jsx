
export default function PacketMeta({
  packet,
}) {
  const fields = [
    [
      "Interface",
      packet.interface_id,
    ],
    [
      "Captured length",
      `${packet.captured_length} B`,
    ],
    [
      "Original length",
      `${packet.original_length} B`,
    ],
    [
      "Entropy",
      Number(packet.entropy).toFixed(4),
    ],
    [
      "Timestamp high",
      packet.timestamp_high,
    ],
    [
      "Timestamp low",
      packet.timestamp_low,
    ],
  ];

  return (
    <div className="packet-meta-grid">
      {fields.map(([label, value]) => (
        <div
          className="meta-item"
          key={label}
        >
          <span>{label}</span>

          <strong>{value}</strong>
        </div>
      ))}
    </div>
  );
}

