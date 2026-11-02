export default function FlowIdentity({ flow }) {
  return (
    <section className="fi-identity">
      <div className="fi-heading">
        <div>
          <span className="fi-eyebrow">
            FLOW
          </span>

          <h2>
            {flow.protocol || "Unknown"} Conversation
          </h2>
        </div>

        <span className="fi-id">
          #{flow.id}
        </span>
      </div>

      <div className="fi-endpoints">
        <div className="fi-endpoint fi-source">
          <span className="fi-endpoint-label">
            SOURCE
          </span>

          <div className="fi-address">
            <span>
              {flow.src || "—"}
            </span>

            {flow.srcPort !== undefined &&
              flow.srcPort !== null && (
                <small>
                  :{flow.srcPort}
                </small>
              )}
          </div>
        </div>

        <div className="fi-arrow">
          <span />
          <strong>→</strong>
          <span />
        </div>

        <div className="fi-endpoint fi-destination">
          <span className="fi-endpoint-label">
            DESTINATION
          </span>

          <div className="fi-address">
            <span>
              {flow.dst || "—"}
            </span>

            {flow.dstPort !== undefined &&
              flow.dstPort !== null && (
                <small>
                  :{flow.dstPort}
                </small>
              )}
          </div>
        </div>
      </div>

      <div className="fi-stats">
        <div className="fi-stat">
          <span className="fi-stat-label">
            PROTOCOL
          </span>

          <span className="fi-stat-value fi-protocol">
            {flow.protocol || "Unknown"}
          </span>
        </div>

        <div className="fi-stat">
          <span className="fi-stat-label">
            PACKETS
          </span>

          <span className="fi-stat-value">
            {Number(
              flow.count || 0
            ).toLocaleString()}
          </span>
        </div>

        <div className="fi-stat">
          <span className="fi-stat-label">
            BYTES
          </span>

          <span className="fi-stat-value">
            {flow.bytes
              ? Number(
                  flow.bytes
                ).toLocaleString()
              : "—"}
          </span>
        </div>

        {flow.duration ? (
          <div className="fi-stat">
            <span className="fi-stat-label">
              DURATION
            </span>

            <span className="fi-stat-value">
              {flow.duration}s
            </span>
          </div>
        ) : null}
      </div>
    </section>
  );
}