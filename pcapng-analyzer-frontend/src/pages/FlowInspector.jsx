import { useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";

import PageHeader from "./PageHeader";
import FlowIdentity from "./flow-inspector/FlowIdentity";
import FlowTraffic from "./flow-inspector/FlowTraffic";

import "./FlowInspector.css";

export default function FlowInspector({
  flows = [],
  packets = [],
  filename,
}) {
  const navigate = useNavigate();
  const { id } = useParams();

  const [viewMode, setViewMode] = useState("packets");
  const [selectedPacket, setSelectedPacket] = useState(null);

  const flow = useMemo(() => {
    return flows.find(
      (item) => String(item.id) === String(id)
    );
  }, [flows, id]);

  const flowPackets = useMemo(() => {
    return Array.isArray(flow?.packets)
      ? flow.packets
      : [];
  }, [flow]);

  const handleBack = () => {
    navigate("/flows");
  };

  const handleSelectPacket = (packet) => {
    setSelectedPacket(packet);
  };

  const handleCloseInspector = () => {
    setSelectedPacket(null);
  };

  if (!flow) {
    return (
      <>
        <PageHeader
          title="Flow Inspector"
          subtitle="Detailed inspection of a network flow."
          filename={filename}
        />

        <main className="flow-inspector">
          <button
            type="button"
            className="fi-back"
            onClick={handleBack}
          >
            <span className="fi-back-arrow">
              ←
            </span>

            Back to Flows
          </button>

          <div className="fi-not-found">
            <h2>Flow not found</h2>

            <p>
              The requested flow could not be found
              in the current capture.
            </p>
          </div>
        </main>
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Flow Inspector"
        subtitle="Detailed inspection of a network flow."
        filename={filename}
      />

      <main className="flow-inspector">
        <button
          type="button"
          className="fi-back"
          onClick={handleBack}
        >
          <span className="fi-back-arrow">
            ←
          </span>

          Back to Flows
        </button>

        <FlowIdentity flow={flow} />

        <div className="fi-separator" />

        <FlowTraffic
          flow={flow}
          packets={flowPackets}
          protocolPackets={packets}
          viewMode={viewMode}
          selectedPacket={selectedPacket}
          onViewModeChange={setViewMode}
          onSelectPacket={handleSelectPacket}
          onCloseInspector={handleCloseInspector}
        />
      </main>
    </>
  );
}