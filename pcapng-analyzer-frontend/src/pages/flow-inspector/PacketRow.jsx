import {
  getPacketKey,
} from "./packetUtils";

export default function PacketRow({
  item,
  selectedPacket,
  onSelect,
}) {
  const {
    index,
    outgoing,
    source,
    destination,
    payload,
  } = item;

  const packetKey = getPacketKey(item);

  const selectedKey = selectedPacket
    ? getPacketKey(selectedPacket)
    : null;

  const isSelected =
    selectedKey !== null &&
    String(selectedKey) === String(packetKey);

  return (
    <article
      className={[
        "fi-packet",
        outgoing
          ? "fi-outgoing"
          : "fi-incoming",
        isSelected
          ? "fi-selected"
          : "",
      ].join(" ")}
      onClick={() => onSelect(item)}
    >
      <div className="fi-packet-meta">
        <span className="fi-packet-number">
          #{index + 1}
        </span>

        <span className="fi-direction">
          {source}

          <span>
            →
          </span>

          {destination}
        </span>
      </div>

      <div className="fi-packet-content">
        {payload.text ? (
          <pre>
            {payload.text}
          </pre>
        ) : (
          <span className="fi-no-payload">
            No payload available.
          </span>
        )}
      </div>
    </article>
  );
}