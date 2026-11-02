import {
  NODE_WIDTH,
  NODE_HEIGHT,
} from "./graphLayout";

export function createGraphNode(
  node,
  selected
) {
  return {
    id: node.id,

    data: {
      label: (
        <div className="protocol-node">
          <div className="protocol-node-type">
            {node.type}
          </div>

          <div className="protocol-node-count">
            {node.count} packets
          </div>
        </div>
      ),
    },

    style: {
      width: NODE_WIDTH,
      minHeight: NODE_HEIGHT,

      background: selected
        ? "#f0f0f0"
        : "#ffffff",

      border: selected
        ? "2px solid #111111"
        : "1px solid #cccccc",

      borderRadius: "8px",

      padding: "10px",

      color: "#222222",

      boxSizing: "border-box",

      boxShadow: selected
        ? "0 3px 10px rgba(0,0,0,0.12)"
        : "0 2px 6px rgba(0,0,0,0.08)",

      cursor: "pointer",
    },
  };
}