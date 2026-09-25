import React, { useMemo } from "react";

import {
  ReactFlow,
  Background,
  Controls,
  Handle,
  Position,
} from "@xyflow/react";

import "@xyflow/react/dist/style.css";


/* ============================================================
   TARVEX26
   ANIMATED FORENSIC INFRASTRUCTURE GRAPH
============================================================ */


/* ============================================================
   CUSTOM NODE
============================================================ */

function ForensicNode({ data }) {

  const nodeType = String(
    data?.type || "unknown"
  ).toLowerCase();

  let icon = "◆";
  let title = "NODE";


  if (nodeType === "email") {
    icon = "✉";
    title = "EMAIL";
  }

  else if (nodeType === "domain") {
    icon = "◎";
    title = "DOMAIN";
  }

  else if (
    nodeType === "ip" ||
    nodeType === "ip_address" ||
    nodeType === "ip-address"
  ) {
    icon = "◇";
    title = "IP ADDRESS";
  }

  else if (
    nodeType === "relay" ||
    nodeType === "server" ||
    nodeType === "relay_server"
  ) {
    icon = "⇄";
    title = "RELAY";
  }


  return (
    <div
      style={{
        width: 170,
        minHeight: 118,

        boxSizing: "border-box",

        padding: "15px 14px",

        borderRadius: "14px",

        background:
          "linear-gradient(145deg, #071522 0%, #050e17 100%)",

        border:
          "1px solid rgba(0, 210, 255, 0.32)",

        boxShadow:
          "0 10px 28px rgba(0,0,0,0.38), 0 0 18px rgba(0,210,255,0.05)",

        color: "#e8faff",

        textAlign: "center",

        position: "relative",

        fontFamily:
          "Inter, system-ui, -apple-system, BlinkMacSystemFont, sans-serif",

        userSelect: "none",

        transition:
          "border-color 0.3s ease, box-shadow 0.3s ease",
      }}
    >

      {/* TOP CONNECTION */}

      <Handle
        type="target"
        position={Position.Top}
        style={{
          width: 7,
          height: 7,

          background: "#00d9ff",

          border: "none",

          boxShadow:
            "0 0 8px rgba(0,217,255,0.7)",
        }}
      />


      {/* ICON */}

      <div
        style={{
          width: 32,
          height: 32,

          margin: "0 auto 8px",

          display: "flex",
          alignItems: "center",
          justifyContent: "center",

          borderRadius: "9px",

          background:
            "rgba(0,215,255,0.08)",

          border:
            "1px solid rgba(0,215,255,0.18)",

          color: "#00d9ff",

          fontSize: "16px",

          boxShadow:
            "0 0 12px rgba(0,215,255,0.05)",
        }}
      >
        {icon}
      </div>


      {/* TYPE */}

      <div
        style={{
          fontSize: "8px",

          letterSpacing: "1.8px",

          fontWeight: 700,

          opacity: 0.48,

          marginBottom: "7px",
        }}
      >
        {title}
      </div>


      {/* LABEL */}

      <div
        style={{
          fontSize: "11px",

          fontWeight: 700,

          lineHeight: 1.4,

          wordBreak: "break-word",

          overflowWrap: "anywhere",

          color: "#e5faff",
        }}
      >
        {data?.label || "Unknown"}
      </div>


      {/* BOTTOM CONNECTION */}

      <Handle
        type="source"
        position={Position.Bottom}
        style={{
          width: 7,
          height: 7,

          background: "#00d9ff",

          border: "none",

          boxShadow:
            "0 0 8px rgba(0,217,255,0.7)",
        }}
      />

    </div>
  );
}


const nodeTypes = {
  forensic: ForensicNode,
};


/* ============================================================
   HELPERS
============================================================ */

function getNodeType(node) {

  return String(
    node?.type ||
    node?.data?.type ||
    "unknown"
  ).toLowerCase();

}


function getNodeLabel(node) {

  return (
    node?.label ||
    node?.data?.label ||
    node?.id ||
    "Unknown"
  );

}


/* ============================================================
   FORENSIC LAYOUT
============================================================ */

function createForensicLayout(rawNodes) {

  const emailNodes = [];
  const domainNodes = [];
  const ipNodes = [];
  const relayNodes = [];
  const otherNodes = [];


  rawNodes.forEach((node) => {

    const type = getNodeType(node);


    if (type === "email") {

      emailNodes.push(node);

    }

    else if (type === "domain") {

      domainNodes.push(node);

    }

    else if (
      type === "ip" ||
      type === "ip_address" ||
      type === "ip-address"
    ) {

      ipNodes.push(node);

    }

    else if (
      type === "relay" ||
      type === "server" ||
      type === "relay_server"
    ) {

      relayNodes.push(node);

    }

    else {

      otherNodes.push(node);

    }

  });


  const result = [];


  /* ==========================================================
     EMAIL
  ========================================================== */

  emailNodes.forEach((node, index) => {

    result.push({

      ...node,

      type: "forensic",

      position: {
        x: 520 + index * 210,
        y: 35,
      },

      data: {
        ...node.data,
        label: getNodeLabel(node),
        type: "email",
      },

    });

  });


  /* ==========================================================
     DOMAIN
  ========================================================== */

  domainNodes.forEach((node, index) => {

    result.push({

      ...node,

      type: "forensic",

      position: {
        x: 80,
        y: 235 + index * 155,
      },

      data: {
        ...node.data,
        label: getNodeLabel(node),
        type: "domain",
      },

    });

  });


  /* ==========================================================
     IP ADDRESSES
  ========================================================== */

  const ipPositions = [

    {
      x: 420,
      y: 235,
    },

    {
      x: 700,
      y: 235,
    },

    {
      x: 555,
      y: 420,
    },

    {
      x: 835,
      y: 420,
    },

    {
      x: 285,
      y: 420,
    },

    {
      x: 975,
      y: 420,
    },

  ];


  ipNodes.forEach((node, index) => {

    const fallbackPosition = {

      x:
        300 +
        (index % 3) * 270,

      y:
        420 +
        Math.floor(index / 3) * 180,

    };


    result.push({

      ...node,

      type: "forensic",

      position:
        ipPositions[index] ||
        fallbackPosition,

      data: {
        ...node.data,
        label: getNodeLabel(node),
        type: "ip",
      },

    });

  });


  /* ==========================================================
     RELAYS
  ========================================================== */

  const relayPositions = [

    {
      x: 300,
      y: 610,
    },

    {
      x: 560,
      y: 610,
    },

    {
      x: 820,
      y: 610,
    },

    {
      x: 1080,
      y: 610,
    },

  ];


  relayNodes.forEach((node, index) => {

    const fallbackPosition = {

      x:
        260 +
        (index % 4) * 270,

      y:
        610 +
        Math.floor(index / 4) * 175,

    };


    result.push({

      ...node,

      type: "forensic",

      position:
        relayPositions[index] ||
        fallbackPosition,

      data: {
        ...node.data,
        label: getNodeLabel(node),
        type: "relay",
      },

    });

  });


  /* ==========================================================
     OTHER NODES
  ========================================================== */

  otherNodes.forEach((node, index) => {

    result.push({

      ...node,

      type: "forensic",

      position: {

        x:
          150 +
          (index % 4) * 270,

        y:
          820 +
          Math.floor(index / 4) * 180,

      },

      data: {
        ...node.data,
        label: getNodeLabel(node),
        type: getNodeType(node),
      },

    });

  });


  return result;

}


/* ============================================================
   ANIMATED EDGE BUILDER
============================================================ */

function createEdges(rawRelationships) {

  return rawRelationships
    .map((relationship, index) => {

      const source =
        relationship?.source ??
        relationship?.from ??
        relationship?.source_id;


      const target =
        relationship?.target ??
        relationship?.to ??
        relationship?.target_id;


      if (
        source === undefined ||
        target === undefined
      ) {
        return null;
      }


      return {

        id:
          relationship?.id ||
          `tarvex-edge-${index}`,

        source: String(source),

        target: String(target),

        label:
          relationship?.type ||
          relationship?.label ||
          "RELATION",


        /* ====================================================
           CURVED CONNECTION
        ==================================================== */

        type: "bezier",


        /* ====================================================
           ANIMATION
           
           React Flow's animated edge creates moving
           dashed cyan lines.
        ==================================================== */

        animated: true,


        style: {

          stroke: "#00d9ff",

          strokeWidth: 1.8,

          strokeDasharray: "7 6",

          opacity: 0.82,

          filter:
            "drop-shadow(0 0 3px rgba(0,217,255,0.45))",

        },


        /* ====================================================
           RELATIONSHIP LABEL
        ==================================================== */

        labelStyle: {

          fill: "#8deeff",

          fontSize: 8,

          fontWeight: 700,

          letterSpacing: "0.5px",

        },


        labelBgStyle: {

          fill: "#030b12",

          fillOpacity: 0.94,

        },


        labelBgPadding: [

          5,

          2,

        ],


        labelBgBorderRadius: 4,

      };

    })

    .filter(Boolean);

}


/* ============================================================
   MAIN COMPONENT
============================================================ */

export default function InfrastructureGraph({

  infrastructureGraph,

  graph,

  data,

}) {


  const sourceGraph =
    infrastructureGraph ||
    graph ||
    data ||
    {};


  const rawNodes =
    Array.isArray(sourceGraph?.nodes)
      ? sourceGraph.nodes
      : [];


  const rawRelationships =
    Array.isArray(sourceGraph?.relationships)
      ? sourceGraph.relationships

      : Array.isArray(sourceGraph?.edges)
        ? sourceGraph.edges

        : [];


  /* ==========================================================
     BUILD NODES
  ========================================================== */

  const nodes = useMemo(

    () => createForensicLayout(rawNodes),

    [rawNodes]

  );


  /* ==========================================================
     BUILD ANIMATED EDGES
  ========================================================== */

  const edges = useMemo(

    () => createEdges(rawRelationships),

    [rawRelationships]

  );


  /* ==========================================================
     EMPTY STATE
  ========================================================== */

  if (!nodes.length) {

    return (

      <div
        style={{
          width: "100%",

          height: 600,

          display: "flex",

          alignItems: "center",

          justifyContent: "center",

          borderRadius: 16,

          border:
            "1px solid rgba(0,210,255,0.15)",

          background:
            "#030b12",

          color:
            "rgba(220,245,255,0.55)",

          fontSize: 13,
        }}
      >

        No infrastructure relationships available.

      </div>

    );

  }


  /* ==========================================================
     GRAPH
  ========================================================== */

  return (

    <div
      style={{
        width: "100%",

        height: 680,

        borderRadius: 18,

        overflow: "hidden",

        border:
          "1px solid rgba(0,210,255,0.16)",

        background:
          "#030b12",

        boxShadow:
          "inset 0 0 60px rgba(0,150,200,0.025)",
      }}
    >

      <ReactFlow

        nodes={nodes}

        edges={edges}

        nodeTypes={nodeTypes}


        /* ----------------------------------------------------
           FIT GRAPH
        ---------------------------------------------------- */

        fitView

        fitViewOptions={{
          padding: 0.15,

          minZoom: 0.55,

          maxZoom: 1.15,
        }}


        /* ----------------------------------------------------
           INTERACTION
        ---------------------------------------------------- */

        nodesDraggable={true}

        nodesConnectable={false}

        elementsSelectable={true}

        panOnDrag={true}

        zoomOnScroll={true}

        zoomOnPinch={true}

        zoomOnDoubleClick={false}


        attributionPosition="bottom-left"

      >

        {/* ====================================================
            FORENSIC GRID
        ==================================================== */}

        <Background
          gap={20}

          size={1}

          color="rgba(100,170,190,0.13)"
        />


        {/* ====================================================
            CONTROLS
        ==================================================== */}

        <Controls
          position="bottom-left"

          showInteractive={false}
        />

      </ReactFlow>

    </div>

  );

}