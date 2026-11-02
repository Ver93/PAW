import express from "express";
import multer from "multer";
import cors from "cors";
import { spawn } from "child_process";
import fs from "fs";

const app = express();
app.use(cors());

const upload = multer({ dest: "uploads/" });

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
        nodes.set(nodeId, { id: nodeId, type: current.type, count: 0 });
      }

      nodes.get(nodeId).count++;

      if (i < chain.length - 1) {
        const next = chain[i + 1];
        const source = current.type.toLowerCase();
        const target = next.type.toLowerCase();
        const edgeId = `${source}->${target}`;

        if (!edges.has(edgeId)) {
          edges.set(edgeId, { id: edgeId, source, target, count: 0 });
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

app.post("/upload", upload.single("file"), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No file uploaded" });

  const filePath = req.file.path;
  const cli = spawn("./cli/main.exe", [filePath]);
  let output = "";

  cli.stdout.on("data", data => {
    output += data.toString();
  });

  cli.stderr.on("data", data => {
    console.error("CLI:", data.toString());
  });

  cli.on("close", code => {
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    if (code !== 0) return res.status(500).json({ error: "C-engine failed" });

    try {
        const result = parseEngineOutput(output);
        const packets = result.packets;
        const flows = result.flows;

        const graph = buildProtocolGraph(packets);
        const packetData = Array.from(packets.values()).flat();

        return res.json({
        graph,
        packets: packetData,
        flows
        });

    } catch (err) {
      console.error("Analysis error:", err);
      return res.status(500).json({ error: "Failed to analyze capture" });
    }
  });
});

app.listen(8000, () => {
  console.log("Backend running on port 8000");
});
