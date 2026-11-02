
import { useState } from "react";
import {
  FileIcon,
  UploadIcon,
} from "../icons/icons";

import "./Dropzone.css";

export default function Dropzone({ onDataReady }) {
  const [dragActive, setDragActive] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  // Normal PCAP/PCAPNG upload
  const analyzeFile = async (file) => {
    if (!file) return;

    setLoading(true);
    setError("");

    try {
      const form = new FormData();
      form.append("file", file);

      const response = await fetch("/api/paw/upload", {
        method: "POST",
        body: form,
      });

      if (!response.ok) {
        throw new Error(`Server returned ${response.status}`);
      }

      const data = await response.json();

      onDataReady({
        graph: data.graph || { nodes: [], edges: [] },
        packets: data.packets || [],
        flows: data.flows || [],
        overview: data.overview || null,
        filename: file.name,
      });
    } catch (err) {
      console.error("Upload/analyze error:", err);
      setError("Could not analyze the file. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  // Load demo capture from backend
  const analyzeDemo = async () => {
    setLoading(true);
    setError("");

    try {
      const response = await fetch("/api/paw/demo");

      if (!response.ok) {
        throw new Error(`Server returned ${response.status}`);
      }

      const data = await response.json();

      onDataReady({
        graph: data.graph || { nodes: [], edges: [] },
        packets: data.packets || [],
        flows: data.flows || [],
        overview: data.overview || null,
        filename: data.filename || "demo.pcapng",
      });
    } catch (err) {
      console.error("Demo analysis error:", err);
      setError(
        "Could not load demo capture. Check that the demo file exists on the server."
      );
    } finally {
      setLoading(false);
    }
  };

  const handleDrop = (event) => {
    event.preventDefault();
    setDragActive(false);

    if (loading) return;

    const file = event.dataTransfer.files?.[0];

    if (file) {
      analyzeFile(file);
    }
  };

  const handleSelect = (event) => {
    const file = event.target.files?.[0];

    if (file) {
      analyzeFile(file);
    }

    event.target.value = "";
  };

  return (
    <div className="upload-page">
      <div className="upload-header">
        <div>
          <div className="eyebrow">
            NETWORK FORENSICS
          </div>

          <h1>PCAPNG Analyzer</h1>

          <p>
            Analyze packet captures,
            inspect traffic and explore
            raw packet data.
          </p>
        </div>
      </div>

      <div
        className={`
          dropzone
          ${dragActive ? "active" : ""}
          ${loading ? "loading" : ""}
        `}
        onDragOver={(event) => {
          event.preventDefault();
          if (!loading) setDragActive(true);
        }}
        onDragLeave={(event) => {
          event.preventDefault();
          setDragActive(false);
        }}
        onDrop={handleDrop}
      >
        <div className="dropzone-icon">
          {loading ? (
            <div className="spinner" />
          ) : (
            <UploadIcon />
          )}
        </div>

        <h2>
          {loading
            ? "Analyzing capture..."
            : "Drop your capture here"}
        </h2>

        <p>
          {loading
            ? "Please wait while the packets are being processed."
            : "Drag & drop a PCAP or PCAPNG file into this area"}
        </p>

        {!loading && (
          <>
            <label className="browse-button">
              <FileIcon />
              Browse files

              <input
                type="file"
                onChange={handleSelect}
                accept=".pcap,.pcapng"
                hidden
              />
            </label>

            <span className="file-hint">
              Supported formats: .pcap, .pcapng
            </span>

            <div className="demo-divider">
              <span>OR</span>
            </div>

            <button
              className="demo-button"
              type="button"
              onClick={analyzeDemo}
            >
              <span className="demo-play">▶</span>
              Try Demo
            </button>

            <span className="demo-hint">
              Explore the analyzer using a sample capture
            </span>
          </>
        )}
      </div>

      {error && (
        <div className="error-box">
          {error}
        </div>
      )}
    </div>
  );
}
