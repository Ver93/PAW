
export default function NodePanel({
  graph,
  packets,
  flows,
  overview,
  selectedNode,
  onClose,
  onShowPackets,
  openFlows,
}) {
  const incomingEdges = graph.edges.filter(
    (edge) => edge.target === selectedNode.id
  );

  const outgoingEdges = graph.edges.filter(
    (edge) => edge.source === selectedNode.id
  );

  const selectedType =
    selectedNode.type?.toLowerCase() || "";

  const protocolPackets = (packets || []).filter(
    (packet) =>
      packet?.type?.toLowerCase() ===
      selectedType
  );

  const totalPackets = packets.length;
  const count = protocolPackets.length;

  const percent =
    totalPackets > 0
      ? ((count / totalPackets) * 100).toFixed(1)
      : "0.0";

  const topSources = getTop(
    protocolPackets,
    "src"
  );

  const topDestinations = getTop(
    protocolPackets,
    "dst"
  );

  const topPorts = getTop(
    protocolPackets,
    "dst_port"
  );

  /*
   * Flows belonging to the selected protocol.
   *
   * This is kept here because the NodePanel can show
   * how many relevant flows exist, and because the
   * selected protocol is used when opening Flows.
   */
  const protocolFlows = (flows || []).filter(
    (flow) =>
      flow.protocol?.toLowerCase() ===
      selectedType
  );

  /*
   * Display filter used by the Flows view.
   *
   * Example:
   *
   * UDP     -> udp
   * TCP     -> tcp
   * IPv4    -> ipv4
   * Ethernet -> ethernet
   */
  const displayFilter = selectedType;

  return (
    <aside className="node-panel">
      <div className="node-panel-header">
        <div>
          <span className="node-panel-eyebrow">
            PROTOCOL
          </span>

          <h2>{selectedNode.type}</h2>
        </div>

        <button
          className="node-panel-close"
          onClick={onClose}
          type="button"
        >
          ×
        </button>
      </div>

      {/* PACKET COUNT */}

      <div className="node-panel-section">
        <span className="node-panel-label">
          Packets
        </span>

        <strong className="node-panel-value">
          {count}
        </strong>

        <span className="node-panel-subvalue">
          {percent}% of capture
        </span>
      </div>

      {/* FLOW COUNT */}

      <div className="node-panel-section">
        <span className="node-panel-label">
          Flows
        </span>

        <strong className="node-panel-value">
          {protocolFlows.length}
        </strong>

        <span className="node-panel-subvalue">
          {selectedNode.type} conversations
        </span>
      </div>

      {/* INCOMING */}

      <div className="node-panel-section">
        <span className="node-panel-label">
          Incoming
        </span>

        {incomingEdges.length === 0 ? (
          <p className="node-panel-empty">
            No incoming connections
          </p>
        ) : (
          <div className="connection-list">
            {incomingEdges.map((edge) => {
              const sourceNode =
                graph.nodes.find(
                  (node) =>
                    node.id === edge.source
                );

              return (
                <div
                  className="connection-item"
                  key={edge.id}
                >
                  <span>
                    {sourceNode?.type ||
                      edge.source}
                  </span>

                  <strong>
                    {edge.count}
                  </strong>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* OUTGOING */}

      <div className="node-panel-section">
        <span className="node-panel-label">
          Outgoing
        </span>

        {outgoingEdges.length === 0 ? (
          <p className="node-panel-empty">
            No outgoing connections
          </p>
        ) : (
          <div className="connection-list">
            {outgoingEdges.map((edge) => {
              const targetNode =
                graph.nodes.find(
                  (node) =>
                    node.id === edge.target
                );

              return (
                <div
                  className="connection-item"
                  key={edge.id}
                >
                  <span>
                    {targetNode?.type ||
                      edge.target}
                  </span>

                  <strong>
                    {edge.count}
                  </strong>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* TOP SOURCES */}

      <div className="node-panel-section">
        <span className="node-panel-label">
          Top sources
        </span>

        {topSources.length === 0 ? (
          <p className="node-panel-empty">
            No source data
          </p>
        ) : (
          <ul className="stats-list">
            {topSources.map(
              ([ip, sourceCount]) => (
                <li key={ip}>
                  {ip}

                  <strong>
                    {sourceCount}
                  </strong>
                </li>
              )
            )}
          </ul>
        )}
      </div>

      {/* TOP DESTINATIONS */}

      <div className="node-panel-section">
        <span className="node-panel-label">
          Top destinations
        </span>

        {topDestinations.length === 0 ? (
          <p className="node-panel-empty">
            No destination data
          </p>
        ) : (
          <ul className="stats-list">
            {topDestinations.map(
              ([ip, destinationCount]) => (
                <li key={ip}>
                  {ip}

                  <strong>
                    {destinationCount}
                  </strong>
                </li>
              )
            )}
          </ul>
        )}
      </div>

      {/* TOP PORTS */}

      {topPorts.length > 0 && (
        <div className="node-panel-section">
          <span className="node-panel-label">
            Top ports
          </span>

          <ul className="stats-list">
            {topPorts.map(
              ([port, portCount]) => (
                <li key={port}>
                  {port}

                  <strong>
                    {portCount}
                  </strong>
                </li>
              )
            )}
          </ul>
        </div>
      )}

      {/* VIEW PACKETS */}

      <div className="node-panel-section">
        <button
          className="node-panel-button"
          onClick={() =>
            onShowPackets?.(selectedNode)
          }
          type="button"
        >
          View packets
        </button>
      </div>

      {/* VIEW FLOWS */}

      <div className="node-panel-section">
        <button
          className="node-panel-button"
          onClick={() =>
            openFlows?.(displayFilter)
          }
          type="button"
        >
          View flows
        </button>
      </div>
    </aside>
  );
}

function getTop(list, field) {
  const map = new Map();

  for (const item of list) {
    const key = item?.[field];

    if (!key) {
      continue;
    }

    map.set(
      key,
      (map.get(key) || 0) + 1
    );
  }

  return [...map.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);
}
