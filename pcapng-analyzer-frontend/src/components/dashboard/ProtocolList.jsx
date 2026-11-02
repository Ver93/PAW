
import { formatNumber } from "../../utils/packetFormat";

export default function ProtocolList({
  items,
  type = "protocol",
}) {
  return (
    <div className="protocol-list">
      {Object.entries(items || {}).map(
        ([key, value]) => (
          <div
            className="protocol-row"
            key={key}
          >
            <div className="protocol-name">
              {type === "protocol" ? (
                <span className="protocol-dot" />
              ) : (
                <span className="block-icon">
                  ◆
                </span>
              )}

              {key}
            </div>

            <div className="protocol-value">
              {formatNumber(value)}
            </div>
          </div>
        )
      )}
    </div>
  );
}

