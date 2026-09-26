import React, { useMemo } from "react";

export default function NeuralNetwork() {
  const nodes = useMemo(
    () => [
      { id: 1, x: 8, y: 25 },
      { id: 2, x: 22, y: 12 },
      { id: 3, x: 22, y: 40 },
      { id: 4, x: 38, y: 25 },
      { id: 5, x: 50, y: 10 },
      { id: 6, x: 50, y: 42 },
      { id: 7, x: 64, y: 25 },
      { id: 8, x: 78, y: 12 },
      { id: 9, x: 78, y: 40 },
      { id: 10, x: 92, y: 25 },
    ],
    []
  );

  const connections = [
    [1, 2],
    [1, 3],
    [2, 4],
    [3, 4],
    [4, 5],
    [4, 6],
    [5, 7],
    [6, 7],
    [7, 8],
    [7, 9],
    [8, 10],
    [9, 10],
  ];

  return (
    <div className="neural-network">

      <div className="neural-grid" />

      <svg
        className="neural-svg"
        viewBox="0 0 100 55"
        preserveAspectRatio="none"
      >
        {connections.map(([a, b], index) => {
          const start = nodes.find((n) => n.id === a);
          const end = nodes.find((n) => n.id === b);

          return (
            <line
              key={`${a}-${b}`}
              x1={start.x}
              y1={start.y}
              x2={end.x}
              y2={end.y}
              className="neural-line"
              style={{
                animationDelay: `${index * 0.25}s`,
              }}
            />
          );
        })}
      </svg>

      <div className="neural-particles">
        {connections.map(([a, b], index) => {
          const start = nodes.find((n) => n.id === a);
          const end = nodes.find((n) => n.id === b);

          return (
            <span
              key={`particle-${a}-${b}`}
              className="neural-particle"
              style={{
                left: `${start.x}%`,
                top: `${start.y}%`,
                "--dx": `${end.x - start.x}%`,
                "--dy": `${end.y - start.y}%`,
                animationDelay: `${index * 0.35}s`,
              }}
            />
          );
        })}
      </div>

      {nodes.map((node) => (
        <span
          key={node.id}
          className="neural-node"
          style={{
            left: `${node.x}%`,
            top: `${node.y}%`,
          }}
        />
      ))}

      <div className="neural-core">
        <span>TARVEX26</span>
        <strong>FORENSIC CORE</strong>
        <small>INTELLIGENCE ACTIVE</small>
      </div>

    </div>
  );
}