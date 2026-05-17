"use client";
import { useEffect, useRef } from "react";
import styles from "./NetworkTopology.module.css";

const NODES = [
  { id: "ca",     x: 500, y: 60,  label: "Certificate Authority", sub: "SDVN-Root-CA", color: "#f59e0b", icon: "🏛️" },
  { id: "c1",     x: 160, y: 280, label: "Vehicle C1",            sub: "C1-LK-1234",   color: "#00d4ff", icon: "🚗" },
  { id: "c2",     x: 840, y: 280, label: "Vehicle C2",            sub: "C2-LK-5678",   color: "#10b981", icon: "🚙" },
  { id: "server", x: 500, y: 420, label: "Monitoring Server",     sub: "PORT 9000/9002", color: "#a855f7", icon: "🖥️" },
];

const EDGES = [
  { from: "ca", to: "c1",  label: "Issues Certificate", dashed: true, color: "#f59e0b" },
  { from: "ca", to: "c2",  label: "Issues Certificate", dashed: true, color: "#f59e0b" },
  { from: "ca", to: "server", label: "Issues Certificate", dashed: true, color: "#f59e0b" },
  { from: "c1", to: "c2",  label: "Ch1 V2V (pseudonym)", dashed: false, color: "#00d4ff" },
  { from: "c1", to: "server", label: "Ch2 Monitor (direct)", dashed: false, color: "#a855f7" },
  { from: "c2", to: "server", label: "Ch3 Relay via C1", dashed: false, color: "#10b981", relay: true },
];

export default function NetworkTopology() {
  const svgRef = useRef<SVGSVGElement>(null);

  useEffect(() => {
    const packets = svgRef.current?.querySelectorAll("[data-packet]");
    packets?.forEach((p, i) => {
      (p as SVGElement).style.animationDelay = `${i * 1.2}s`;
    });
  }, []);

  const getNode = (id: string) => NODES.find((n) => n.id === id)!;

  return (
    <div className={styles.wrapper}>
      <svg ref={svgRef} viewBox="0 0 1000 520" className={styles.svg} role="img" aria-label="SDVN Network Topology">
        <defs>
          <marker id="arrow-teal" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
            <path d="M0,0 L0,6 L8,3 z" fill="#00d4ff" />
          </marker>
          <marker id="arrow-purple" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
            <path d="M0,0 L0,6 L8,3 z" fill="#a855f7" />
          </marker>
          <marker id="arrow-green" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
            <path d="M0,0 L0,6 L8,3 z" fill="#10b981" />
          </marker>
          <marker id="arrow-amber" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
            <path d="M0,0 L0,6 L8,3 z" fill="#f59e0b" />
          </marker>
          <filter id="glow-teal">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
        </defs>

        {/* Edges */}
        {EDGES.map((e, i) => {
          const n1 = getNode(e.from);
          const n2 = getNode(e.to);
          const markerId = e.color === "#00d4ff" ? "arrow-teal" : e.color === "#a855f7" ? "arrow-purple" : e.color === "#10b981" ? "arrow-green" : "arrow-amber";
          return (
            <g key={i}>
              <line
                x1={n1.x} y1={n1.y} x2={n2.x} y2={n2.y}
                stroke={e.color}
                strokeWidth={e.dashed ? 1.5 : 2}
                strokeDasharray={e.dashed ? "6 4" : "none"}
                strokeOpacity={0.5}
                markerEnd={e.dashed ? undefined : `url(#${markerId})`}
              />
              {/* Animated packet */}
              {!e.dashed && (
                <circle r="5" fill={e.color} data-packet="true" className={styles.packet}>
                  <animateMotion
                    dur={`${2 + i * 0.4}s`}
                    repeatCount="indefinite"
                    begin={`${i * 0.8}s`}
                    path={`M${n1.x},${n1.y} L${n2.x},${n2.y}`}
                  />
                </circle>
              )}
            </g>
          );
        })}

        {/* Nodes */}
        {NODES.map((node) => (
          <g key={node.id} className={styles.node}>
            {/* Glow ring */}
            <circle cx={node.x} cy={node.y} r={44} fill={node.color} fillOpacity={0.08} stroke={node.color} strokeOpacity={0.3} strokeWidth={1} />
            {/* Node circle */}
            <circle cx={node.x} cy={node.y} r={36} fill="#0d1f3c" stroke={node.color} strokeWidth={2} />
            {/* Icon */}
            <text x={node.x} y={node.y + 6} textAnchor="middle" fontSize={22} className={styles.nodeIcon}>{node.icon}</text>
            {/* Label */}
            <text x={node.x} y={node.y + 62} textAnchor="middle" fill="#e2e8f0" fontSize={13} fontWeight={700} fontFamily="Inter, sans-serif">
              {node.label}
            </text>
            <text x={node.x} y={node.y + 78} textAnchor="middle" fill={node.color} fontSize={10} fontFamily="JetBrains Mono, monospace" opacity={0.9}>
              {node.sub}
            </text>
          </g>
        ))}

        {/* Channel labels */}
        <text x={500} y={270} textAnchor="middle" fill="#00d4ff" fontSize={11} fontFamily="JetBrains Mono, monospace" opacity={0.8}>Ch1 V2V</text>
        <text x={310} y={380} textAnchor="middle" fill="#a855f7" fontSize={11} fontFamily="JetBrains Mono, monospace" opacity={0.8} transform="rotate(-52, 310, 380)">Ch2 Direct</text>
        <text x={720} y={380} textAnchor="middle" fill="#10b981" fontSize={11} fontFamily="JetBrains Mono, monospace" opacity={0.8} transform="rotate(52, 720, 380)">Ch3 Relay</text>
      </svg>

      {/* Legend */}
      <div className={styles.legend}>
        <div className={styles.legendItem}>
          <span className={styles.legendLine} style={{ borderColor: "#f59e0b", borderStyle: "dashed" }} />
          <span>CA Certificate Issuance</span>
        </div>
        <div className={styles.legendItem}>
          <span className={styles.legendLine} style={{ borderColor: "#00d4ff" }} />
          <span>Ch1 V2V (Pseudonym)</span>
        </div>
        <div className={styles.legendItem}>
          <span className={styles.legendLine} style={{ borderColor: "#a855f7" }} />
          <span>Ch2 Monitor (Real ID)</span>
        </div>
        <div className={styles.legendItem}>
          <span className={styles.legendLine} style={{ borderColor: "#10b981" }} />
          <span>Ch3 Relay (Anonymous)</span>
        </div>
      </div>
    </div>
  );
}
