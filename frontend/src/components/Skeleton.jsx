import React from 'react'

// ─── SkeletonCard ───
// Card-shaped skeleton with pulse animation, matches dark theme card dimensions
export function SkeletonCard({ className = '', style = {} }) {
  return (
    <div
      className={`skeleton-card ${className}`}
      style={{ minHeight: 120, ...style }}
    >
      <div className="skeleton-shimmer skeleton-line" style={{ width: '40%', height: 10, marginBottom: 16 }} />
      <div className="skeleton-shimmer skeleton-line" style={{ width: '60%', height: 28, marginBottom: 12 }} />
      <div className="skeleton-shimmer skeleton-line" style={{ width: '80%', height: 6 }} />
    </div>
  )
}

// ─── SkeletonTable ───
// Table rows skeleton with configurable row count
export function SkeletonTable({ rows = 5, cols = 6, className = '' }) {
  return (
    <div className={`skeleton-table-wrapper ${className}`}>
      {/* Header row */}
      <div className="skeleton-table-header">
        {Array.from({ length: cols }).map((_, c) => (
          <div key={c} className="skeleton-shimmer skeleton-line" style={{ width: `${60 + Math.random() * 30}%`, height: 10 }} />
        ))}
      </div>
      {/* Body rows */}
      {Array.from({ length: rows }).map((_, r) => (
        <div key={r} className="skeleton-table-row" style={{ animationDelay: `${r * 80}ms` }}>
          {Array.from({ length: cols }).map((_, c) => (
            <div key={c} className="skeleton-shimmer skeleton-line" style={{ width: `${50 + ((r + c) * 7) % 40}%`, height: 12 }} />
          ))}
        </div>
      ))}
    </div>
  )
}

// ─── SkeletonChart ───
// Chart-area skeleton placeholder
export function SkeletonChart({ height = 260, className = '' }) {
  return (
    <div className={`skeleton-card ${className}`} style={{ minHeight: height + 60 }}>
      <div className="skeleton-shimmer skeleton-line" style={{ width: '30%', height: 10, marginBottom: 20 }} />
      <div className="skeleton-chart-area" style={{ height }}>
        {/* Fake bar chart bars */}
        <div className="skeleton-chart-bars">
          {[65, 40, 80, 55, 70, 45, 75].map((h, i) => (
            <div
              key={i}
              className="skeleton-shimmer skeleton-bar"
              style={{ height: `${h}%`, animationDelay: `${i * 100}ms` }}
            />
          ))}
        </div>
      </div>
    </div>
  )
}

// ─── SkeletonText ───
// Text line skeleton with configurable line count
export function SkeletonText({ lines = 3, className = '' }) {
  return (
    <div className={`skeleton-text ${className}`}>
      {Array.from({ length: lines }).map((_, i) => (
        <div
          key={i}
          className="skeleton-shimmer skeleton-line"
          style={{
            width: i === lines - 1 ? '60%' : `${85 + (i * 5) % 15}%`,
            height: 12,
            marginBottom: i < lines - 1 ? 10 : 0,
            animationDelay: `${i * 60}ms`,
          }}
        />
      ))}
    </div>
  )
}

// ─── SkeletonMap ───
// Map-area skeleton placeholder
export function SkeletonMap({ height = 500, className = '' }) {
  return (
    <div className={`skeleton-map ${className}`} style={{ height }}>
      <div className="skeleton-map-inner">
        {/* Fake map dots */}
        {[
          { top: '30%', left: '25%', size: 12 },
          { top: '35%', left: '55%', size: 10 },
          { top: '45%', left: '40%', size: 8 },
          { top: '55%', left: '70%', size: 14 },
          { top: '40%', left: '15%', size: 10 },
        ].map((dot, i) => (
          <div
            key={i}
            className="skeleton-shimmer skeleton-map-dot"
            style={{
              top: dot.top,
              left: dot.left,
              width: dot.size,
              height: dot.size,
              animationDelay: `${i * 200}ms`,
            }}
          />
        ))}
        {/* Center label */}
        <div className="skeleton-map-label">
          <div className="skeleton-shimmer skeleton-line" style={{ width: 120, height: 14 }} />
          <div className="skeleton-shimmer skeleton-line" style={{ width: 80, height: 10, marginTop: 8 }} />
        </div>
      </div>
    </div>
  )
}

// ─── DashboardSkeleton ───
// Full dashboard loading skeleton
export function DashboardSkeleton() {
  return (
    <div className="space-y-6">
      {/* Header skeleton */}
      <div className="flex items-center justify-between">
        <div>
          <div className="skeleton-shimmer skeleton-line" style={{ width: 200, height: 24, marginBottom: 8 }} />
          <div className="skeleton-shimmer skeleton-line" style={{ width: 300, height: 14 }} />
        </div>
        <div className="skeleton-shimmer skeleton-line" style={{ width: 100, height: 36, borderRadius: 12 }} />
      </div>

      {/* KPI Cards grid */}
      <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
        {Array.from({ length: 6 }).map((_, i) => (
          <SkeletonCard key={i} style={{ animationDelay: `${i * 80}ms` }} />
        ))}
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <SkeletonChart />
        <SkeletonChart />
      </div>

      {/* Bottom cards */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <SkeletonCard style={{ minHeight: 200 }} />
        <SkeletonCard style={{ minHeight: 200 }} />
      </div>
    </div>
  )
}

// ─── AlertsSkeleton ───
export function AlertsSkeleton() {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="skeleton-shimmer" style={{ width: 44, height: 44, borderRadius: 12 }} />
        <div>
          <div className="skeleton-shimmer skeleton-line" style={{ width: 180, height: 22, marginBottom: 6 }} />
          <div className="skeleton-shimmer skeleton-line" style={{ width: 240, height: 14 }} />
        </div>
      </div>
      {/* KPI row */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {Array.from({ length: 5 }).map((_, i) => (
          <SkeletonCard key={i} style={{ minHeight: 80, animationDelay: `${i * 60}ms` }} />
        ))}
      </div>
      {/* Table */}
      <SkeletonTable rows={8} cols={7} />
    </div>
  )
}

// ─── LogsSkeleton ───
export function LogsSkeleton() {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="skeleton-shimmer" style={{ width: 44, height: 44, borderRadius: 12 }} />
        <div>
          <div className="skeleton-shimmer skeleton-line" style={{ width: 160, height: 22, marginBottom: 6 }} />
          <div className="skeleton-shimmer skeleton-line" style={{ width: 200, height: 14 }} />
        </div>
      </div>
      {/* Search bar */}
      <div className="skeleton-card" style={{ minHeight: 48, padding: 6 }}>
        <div className="skeleton-shimmer skeleton-line" style={{ width: '100%', height: 36, borderRadius: 8 }} />
      </div>
      {/* Filter row */}
      <div className="flex gap-3">
        <div className="skeleton-shimmer skeleton-line" style={{ width: 280, height: 36, borderRadius: 8 }} />
        <div className="skeleton-shimmer skeleton-line" style={{ width: 120, height: 36, borderRadius: 8 }} />
        <div className="skeleton-shimmer skeleton-line" style={{ width: 130, height: 36, borderRadius: 8 }} />
      </div>
      {/* Table */}
      <SkeletonTable rows={10} cols={8} />
    </div>
  )
}

// ─── ThreatMapSkeleton ───
export function ThreatMapSkeleton() {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="skeleton-shimmer" style={{ width: 40, height: 40, borderRadius: 10 }} />
        <div>
          <div className="skeleton-shimmer skeleton-line" style={{ width: 200, height: 20, marginBottom: 6 }} />
          <div className="skeleton-shimmer skeleton-line" style={{ width: 340, height: 13 }} />
        </div>
      </div>
      {/* Stats row */}
      <div className="grid grid-cols-3 gap-4">
        {Array.from({ length: 3 }).map((_, i) => (
          <SkeletonCard key={i} style={{ minHeight: 70, animationDelay: `${i * 80}ms` }} />
        ))}
      </div>
      {/* Map + panel */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        <div className="lg:col-span-3">
          <SkeletonMap height={500} />
        </div>
        <div className="skeleton-card" style={{ minHeight: 500 }}>
          <div className="skeleton-shimmer skeleton-line" style={{ width: '60%', height: 14, marginBottom: 16 }} />
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} style={{ marginBottom: 12 }}>
              <div className="skeleton-shimmer skeleton-line" style={{ width: '80%', height: 12, marginBottom: 6 }} />
              <div className="skeleton-shimmer skeleton-line" style={{ width: '100%', height: 60, borderRadius: 8 }} />
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// ─── MitreSkeleton ───
export function MitreSkeleton() {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="skeleton-shimmer" style={{ width: 44, height: 44, borderRadius: 12 }} />
        <div>
          <div className="skeleton-shimmer skeleton-line" style={{ width: 240, height: 22, marginBottom: 6 }} />
          <div className="skeleton-shimmer skeleton-line" style={{ width: 300, height: 14 }} />
        </div>
      </div>
      {/* KPI row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {Array.from({ length: 3 }).map((_, i) => (
          <SkeletonCard key={i} style={{ minHeight: 90, animationDelay: `${i * 80}ms` }} />
        ))}
      </div>
      {/* Matrix grid skeleton */}
      <div className="skeleton-card" style={{ minHeight: 400, padding: 24 }}>
        <div className="skeleton-shimmer skeleton-line" style={{ width: '20%', height: 16, marginBottom: 20 }} />
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(14, 1fr)', gap: 4 }}>
          {Array.from({ length: 14 }).map((_, c) => (
            <div key={`h-${c}`} className="skeleton-shimmer skeleton-line" style={{ height: 40, borderRadius: 4 }} />
          ))}
          {Array.from({ length: 14 * 4 }).map((_, i) => (
            <div key={`c-${i}`} className="skeleton-shimmer skeleton-line" style={{ height: 28, borderRadius: 4, animationDelay: `${(i % 14) * 30}ms` }} />
          ))}
        </div>
      </div>
    </div>
  )
}
