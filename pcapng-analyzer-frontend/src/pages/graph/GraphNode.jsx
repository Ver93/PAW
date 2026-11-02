import {
  NODE_WIDTH,
  NODE_HEIGHT,
} from "./graphLayout";

export default function GraphNode({
  node,
  selected,
}) {
  return {
    id: node.id,

    data: {
      label: (
        <div>
          <div>{node.type}</div>

          <div
            style={{
              marginTop: "6px",
              fontSize: "13px",
              fontWeight: "400",
              color: "#666",
            }}
          >
            {node.count} packets
          </div>
        </div>
      ),
    },

    style: {
      width: NODE_WIDTH,
      minHeight: NODE_HEIGHT,

      background: selected
        ? "#eeeeee"
        : "#ffffff",

      border: selected
        ? "3px solid #000"
        : "2px solid #222",

      borderRadius: "10px",
      padding: "12px",
      fontSize: "16px",
      fontWeight: "600",
      color: "#222",
      textAlign: "center",

      boxShadow: selected
        ? "0 0 0 3px rgba(0,0,0,0.08)"
        : "0 4px 12px rgba(0, 0, 0, 0.15)",

      cursor: "pointer",
    },
  };
}