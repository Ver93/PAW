import dagre from "@dagrejs/dagre";

export const NODE_WIDTH = 150;
export const NODE_HEIGHT = 64;

export function createLayout(nodes, edges) {
  const graph = new dagre.graphlib.Graph();

  graph.setDefaultEdgeLabel(() => ({}));

  graph.setGraph({
    rankdir: "TB",
    ranksep: 60,
    nodesep: 45,
    marginx: 20,
    marginy: 20,
  });

  nodes.forEach((node) => {
    graph.setNode(node.id, {
      width: NODE_WIDTH,
      height: NODE_HEIGHT,
    });
  });

  edges.forEach((edge) => {
    graph.setEdge(
      edge.source,
      edge.target
    );
  });

  dagre.layout(graph);

  return nodes.map((node) => {
    const position = graph.node(node.id);

    return {
      ...node,

      position: {
        x:
          position.x -
          NODE_WIDTH / 2,

        y:
          position.y -
          NODE_HEIGHT / 2,
      },
    };
  });
}