
import express from "express";
import multer from "multer";
import cors from "cors";
import { spawn } from "child_process";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const app = express();
app.use(cors());

const BASE_DIR = path.dirname(fileURLToPath(import.meta.url));
const ENGINE_PATH = path.join(BASE_DIR, "cli", "main.exe");
const DEMO_PATH = path.join(BASE_DIR, "samples", "demo.pcapng");
const UPLOAD_DIR = path.join(BASE_DIR, "uploads");

fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const upload = multer({ dest: UPLOAD_DIR });

function parseEngineOutput(output) {
  const packets = new Map();
  let flows = [];

  const lines = output.split(/\r?\n/).filter(line => line.trim());

  for (const line of lines) {
    try {
      const node = JSON.parse(line);

      if (node.flows) {
        flows = node.flows;
        continue;
      }

      if (node.packet === undefined || node.type === undefined) continue;

      if (!packets.has(node.packet)) {
        packets.set(node.packet, []);
      }

      packets.get(node.packet).push(node);
    } catch {}
  }

  return { packets, flows };
}

function buildProtocolGraph(packets) {
  const nodes = new Map();
  const edges = new Map();

  for (const [, chain] of packets) {
    for (let i = 0; i < chain.length; i++) {
      const current = chain[i];
      const nodeId = current.type.toLowerCase();

      if (!nodes.has(nodeId)) {
        nodes.set(nodeId, {
          id: nodeId,
          type: current.type,
          count: 0
        });
      }

      nodes.get(nodeId).count++;

      if (i < chain.length - 1) {
        const next = chain[i + 1];
        const source = current.type.toLowerCase();
        const target = next.type.toLowerCase();
        const edgeId = `${source}->${target}`;

        if (!edges.has(edgeId)) {
          edges.set(edgeId, {
            id: edgeId,
            source,
            target,
            count: 0
          });
        }

        edges.get(edgeId).count++;
      }
    }
  }

  return {
    nodes: Array.from(nodes.values()),
    edges: Array.from(edges.values())
  };
}

// Shared analysis function for uploads and demo
function analyzeCapture(filePath, filename, res, cleanup = false) {
  const cli = spawn(ENGINE_PATH, [filePath]);

  let output = "";
  let stderr = "";

  cli.stdout.on("data", data => {
    output += data.toString();
  });

  cli.stderr.on("data", data => {
    stderr += data.toString();
    console.error("CLI:", data.toString());
  });

  cli.on("error", err => {
    console.error("Engine start error:", err);

    if (cleanup && fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }

    if (!res.headersSent) {
      res.status(500).json({ error: "Could not start C-engine" });
    }
  });

  cli.on("close", code => {
    if (cleanup && fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }

    if (res.headersSent) return;

    if (code !== 0) {
      console.error("Engine exit code:", code, stderr);
      return res.status(500).json({ error: "C-engine failed" });
    }

    try {
      const result = parseEngineOutput(output);
      const packets = result.packets;
      const flows = result.flows;
      const graph = buildProtocolGraph(packets);
      const packetData = Array.from(packets.values()).flat();

      return res.json({
        graph,
        packets: packetData,
        flows,
        filename
      });
    } catch (err) {
      console.error("Analysis error:", err);
      return res.status(500).json({
        error: "Failed to analyze capture"
      });
    }
  });
}

// Normal file upload
app.post("/upload", upload.single("file"), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: "No file uploaded" });
  }

  analyzeCapture(req.file.path, req.file.originalname, res, true);
});

// Demo capture stored on the server
app.get("/demo", (req, res) => {
  if (!fs.existsSync(DEMO_PATH)) {
    return res.status(404).json({
      error: "Demo capture not found"
    });
  }

  analyzeCapture(DEMO_PATH, "demo.pcapng", res, false);
});

app.listen(8000, () => {
  console.log("Backend running on port 8000");
});
