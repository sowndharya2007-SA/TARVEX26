import React, { useMemo } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  Handle,
  Position,
} from "@xyflow/react";

import "@xyflow/react/dist/style.css";


/* =========================================================
   CUSTOM NODE
   ========================================================= */

function ForensicNode({ data }) {

  const typeClass = `forensic-node ${data.type || "default"}`;

  return (
    <div className={typeClass}>

      <Handle
        type="target"
        position={Position.Top}
      />

      <div className="node-icon">
        {data.icon}
      </div>

      <div className="node-type">
        {data.type?.toUpperCase()}
      </div>

      <div className="node-label">
        {data.label}
      </div>

      {data.subtitle && (
        <div className="node-subtitle">
          {data.subtitle}
        </div>
      )}

      <Handle
        type="source"
        position={Position.Bottom}
      />

    </div>
  );
}


/* =========================================================
   NODE TYPES
   ========================================================= */

const nodeTypes = {
  forensic: ForensicNode,
};


/* =========================================================
   ICONS
   ========================================================= */

function getIcon(type) {

  switch (type) {

    case "email":
      return "✉";

    case "domain":
      return "◉";

    case "ip":
      return "◈";

    case "relay":
      return "⇄";

    default:
      return "●";
  }
}


/* =========================================================
   GRAPH COMPONENT
   ========================================================= */

export default function InfrastructureGraph({
  infrastructureGraph
}) {

  /*
   If backend has not returned graph data yet,
   show an empty state instead of breaking the UI.
  */

  if (
    !infrastructureGraph ||
    !infrastructureGraph.nodes ||
    infrastructureGraph.nodes.length === 0
  ) {

    return (
      <div className="infrastructure-empty">

        <div className="empty-icon">
          ◈
        </div>

        <h3>
          No Infrastructure Relationships
        </h3>

        <p>
          Upload and analyze an email to generate
          the infrastructure relationship graph.
        </p>

      </div>
    );
  }


  /* =======================================================
     BUILD GRAPH NODES
     ======================================================= */

  const nodes = useMemo(() => {

    const backendNodes = infrastructureGraph.nodes || [];

    /*
      Create a simple hierarchy:

      Email
        ↓
      Domains / IP
        ↓
      Relay infrastructure
    */

    const emailNodes = backendNodes.filter(
      node => node.type === "email"
    );

    const domainNodes = backendNodes.filter(
      node => node.type === "domain"
    );

    const ipNodes = backendNodes.filter(
      node => node.type === "ip"
    );

    const relayNodes = backendNodes.filter(
      node => node.type === "relay"
    );


    const result = [];


    /* EMAIL */

    emailNodes.forEach((node, index) => {

      result.push({

        id: node.id,

        type: "forensic",

        position: {
          x: 430,
          y: 40
        },

        data: {
          ...node,
          icon: getIcon(node.type)
        }

      });

    });


    /* DOMAINS */

    domainNodes.forEach((node, index) => {

      result.push({

        id: node.id,

        type: "forensic",

        position: {
          x: 120 + index * 280,
          y: 220
        },

        data: {
          ...node,
          icon: getIcon(node.type)
        }

      });

    });


    /* IP */

    ipNodes.forEach((node, index) => {

      result.push({

        id: node.id,

        type: "forensic",

        position: {
          x: 430,
          y: 420
        },

        data: {
          ...node,
          icon: getIcon(node.type)
        }

      });

    });


    /* RELAYS */

    relayNodes.forEach((node, index) => {

      result.push({

        id: node.id,

        type: "forensic",

        position: {
          x: 80 + index * 270,
          y: 620
        },

        data: {
          ...node,
          icon: getIcon(node.type)
        }

      });

    });


    return result;

  }, [infrastructureGraph]);


  /* =======================================================
     BUILD GRAPH EDGES
     ======================================================= */

  const edges = useMemo(() => {

    return (
      infrastructureGraph.relationships || []
    ).map((relationship, index) => ({

      id: `edge-${index}`,

      source: relationship.source,

      target: relationship.target,

      label: relationship.type
        ?.replaceAll("_", " "),

      animated: true,

      style: {
        stroke: "#00d9ff",
        strokeWidth: 2
      },

      labelStyle: {
        fill: "#7f94a8",
        fontSize: 10,
        fontWeight: 600
      },

      labelBgStyle: {
        fill: "#07111c",
        fillOpacity: 0.9
      },

      labelBgPadding: [6, 4],

      labelBgBorderRadius: 4

    }));

  }, [infrastructureGraph]);


  /* =======================================================
     GRAPH UI
     ======================================================= */

  return (

    <div className="infrastructure-graph-wrapper">

      <div className="graph-header">

        <div>

          <span className="section-label">
            INFRASTRUCTURE CORRELATION
          </span>

          <h2>
            Email Infrastructure Relationships
          </h2>

          <p>
            Visual correlation of email, domains,
            IP addresses and relay infrastructure.
          </p>

        </div>


        <div className="graph-stats">

          <div>
            <strong>
              {infrastructureGraph.node_count || nodes.length}
            </strong>

            <span>
              NODES
            </span>
          </div>


          <div>
            <strong>
              {
                infrastructureGraph.relationship_count ||
                edges.length
              }
            </strong>

            <span>
              RELATIONSHIPS
            </span>
          </div>

        </div>

      </div>


      <div className="graph-container">

        <ReactFlow

          nodes={nodes}

          edges={edges}

          nodeTypes={nodeTypes}

          fitView

          fitViewOptions={{
            padding: 0.25
          }}

          attributionPosition="bottom-left"

        >

          <Background
            gap={24}
            size={1}
          />

          <Controls />

        </ReactFlow>

      </div>


      <div className="graph-legend">

        <div className="legend-title">
          FORENSIC GRAPH LEGEND
        </div>


        <div className="legend-items">

          <div>
            <span className="legend-dot email"></span>
            Email
          </div>

          <div>
            <span className="legend-dot domain"></span>
            Domain
          </div>

          <div>
            <span className="legend-dot ip"></span>
            IP Address
          </div>

          <div>
            <span className="legend-dot relay"></span>
            Relay Server
          </div>

        </div>

      </div>

    </div>

  );
}