import { useState } from "react";
import { useNavigate } from "react-router-dom";

import GraphCanvas from "./graph/GraphCanvas";
import NodePanel from "./graph/NodePanel";
import PageHeader from "./PageHeader";

import "./Graph.css";

export default function Graph({
  graph,
  packets,
  flows,
  overview,
  filename,
  onReset,
}) {
  const [selectedNode, setSelectedNode] = useState(null);
  const navigate = useNavigate();

  const openFlows = (filter = "") => {
    const value = String(filter || "").trim();

    if (!value) {
      navigate("/flows");
      return;
    }

    navigate(
      `/flows?filter=${encodeURIComponent(value)}`
    );
  };

  return (
    <div className="graph-page">
      <PageHeader
        title="Protocol Graph"
        subtitle="Protocol structure detected in the capture"
        filename={filename}
        backLabel="Back"
        onBack={onReset}
        actions={
          <button
            type="button"
            className="page-header-secondary"
            onClick={() => navigate("/flows")}
          >
            Flows →
          </button>
        }
      />

      <div className="graph-content">
        <GraphCanvas
          graph={graph}
          selectedNode={selectedNode}
          onSelectNode={setSelectedNode}
          openFlows={openFlows}
        />

        {selectedNode && (
          <NodePanel
            graph={graph}
            packets={packets}
            flows={flows}
            overview={overview}
            selectedNode={selectedNode}
            openFlows={openFlows}
            onClose={() => setSelectedNode(null)}
          />
        )}
      </div>
    </div>
  );
}