import { useState } from "react";
import "@xyflow/react/dist/style.css";
import "./App.css";

import Dropzone from "./components/upload/Dropzone";
import Graph from "./pages/Graph";
import Flows from "./pages/Flows";
import FlowInspector from "./pages/FlowInspector";

import { BrowserRouter, Routes, Route } from "react-router-dom";

export default function App() {
  const [analysis, setAnalysis] = useState(null);

  const handleDataReady = (data) => {
    if (data?.graph) {
      setAnalysis({
        graph: data.graph,
        packets: data.packets || [],
        flows: data.flows || [],
        overview: data.overview || null,
        filename: data.filename || null,
      });
    } else {
      setAnalysis({
        graph: { nodes: [], edges: [] },
        packets: [],
        flows: [],
        overview: null,
        filename: null,
      });
    }
  };

  const handleReset = () => setAnalysis(null);

  if (analysis === null) {
    return (
      <div className="app">
        <Dropzone onDataReady={handleDataReady} />
      </div>
    );
  }

  return (
    <BrowserRouter>
      <Routes>
        <Route
          path="/"
          element={
            <Graph
              graph={analysis.graph}
              packets={analysis.packets}
              flows={analysis.flows}
              overview={analysis.overview}
              filename={analysis.filename}
              onReset={handleReset}
            />
          }
        />

        <Route
          path="/flows"
          element={
            <Flows
              flows={analysis.flows}
              filename={analysis.filename}
            />
          }
        />

        <Route
          path="/flow/:id"
          element={
            <FlowInspector
              flows={analysis.flows}
              packets={analysis.packets}
              filename={analysis.filename}
            />
          }
        />
      </Routes>
    </BrowserRouter>
  );
}