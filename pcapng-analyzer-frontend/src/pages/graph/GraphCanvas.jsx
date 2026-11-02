import {
  useEffect,
  useMemo,
} from "react";

import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
} from "@xyflow/react";

import {
  createLayout,
} from "./graphLayout";

import {
  createGraphNode,
} from "./createGraphNode";

export default function GraphCanvas({
  graph,
  selectedNode,
  onSelectNode,
}) {
  const initialNodes = useMemo(() => {
    if (
      !graph?.nodes ||
      !graph?.edges
    ) {
      return [];
    }

    const rawNodes =
      graph.nodes.map((node) =>
        createGraphNode(
          node,
          selectedNode?.id === node.id
        )
      );

    const flowEdges =
      graph.edges.map((edge) => ({
        id: edge.id,
        source: edge.source,
        target: edge.target,
        type: "smoothstep",
      }));

    return createLayout(
      rawNodes,
      flowEdges
    );
  }, [graph, selectedNode?.id]);

  const [nodes, setNodes, onNodesChange] =
    useNodesState(initialNodes);

  /*
   * När en ny analys laddas:
   * bygg om layouten.
   *
   * Vi gör INTE detta när selectedNode
   * ändras, annars skulle en nod flytta
   * tillbaka varje gång panelen öppnas.
   */
  useEffect(() => {
    setNodes(initialNodes);
  }, [initialNodes, setNodes]);

  const edges = useMemo(() => {
    if (
      !graph?.edges
    ) {
      return [];
    }

    return graph.edges.map((edge) => ({
      id: edge.id,

      source: edge.source,

      target: edge.target,

      type: "smoothstep",

      style: {
        stroke: "#999999",
        strokeWidth: 1.5,
      },

      label: edge.count,

      labelStyle: {
        fontSize: 10,
        fontWeight: 500,
        fill: "#777777",
      },

      labelBgStyle: {
        fill: "#f5f5f5",
        fillOpacity: 0.9,
      },

      labelBgPadding: [4, 2],

      labelBgBorderRadius: 3,
    }));
  }, [graph]);

  if (nodes.length === 0) {
    return (
      <div className="graph-container">
        <div className="graph-no-data">
          <h2>No nodes found</h2>

          <p>
            Backend returned no graph
            nodes.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="graph-container">
      <ReactFlow
        nodes={nodes}
        edges={edges}

        onNodesChange={onNodesChange}

        fitView

        fitViewOptions={{
          padding: 0.35,
        }}

        minZoom={0.2}
        maxZoom={2}

        nodesDraggable={true}

        nodesConnectable={false}

        elementsSelectable={true}

        panOnDrag={true}

        onNodeClick={(_, node) => {
          const originalNode =
            graph.nodes.find(
              (item) =>
                item.id === node.id
            );

          if (originalNode) {
            onSelectNode(
              originalNode
            );
          }
        }}

        onPaneClick={() => {
          onSelectNode(null);
        }}
      >
        <Background
          gap={24}
          size={1}
        />

        <Controls />

        <MiniMap
          nodeStrokeWidth={2}
          zoomable
          pannable
        />
      </ReactFlow>
    </div>
  );
}