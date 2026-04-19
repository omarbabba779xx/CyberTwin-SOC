import React from 'react'

export default function ScoreGauge({ score, label, size = 120 }) {
  const radius = (size - 16) / 2
  const circumference = 2 * Math.PI * radius
  const offset = circumference - (score / 100) * circumference
  const color = score >= 80 ? '#22c55e' : score >= 60 ? '#eab308' : score >= 40 ? '#f97316' : '#ef4444'

  return (
    <div className="flex flex-col items-center gap-2">
      <svg width={size} height={size} className="-rotate-90">
        <circle
          cx={size / 2} cy={size / 2} r={radius}
          stroke="#21262d" strokeWidth="8" fill="none"
        />
        <circle
          cx={size / 2} cy={size / 2} r={radius}
          stroke={color} strokeWidth="8" fill="none"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          className="transition-all duration-1000"
        />
        <text
          x={size / 2} y={size / 2}
          textAnchor="middle" dominantBaseline="central"
          className="rotate-90 origin-center"
          fill="white" fontSize={size / 4} fontWeight="bold"
        >
          {Math.round(score)}
        </text>
      </svg>
      <span className="text-xs text-gray-400 font-medium">{label}</span>
    </div>
  )
}
