import React from 'react'
import useAnimatedCounter from '../hooks/useAnimatedCounter'

export default function StatCard({ title, value, subtitle, icon: Icon, color = 'red' }) {
  const isNumeric = typeof value === 'number'
  const animatedValue = useAnimatedCounter(isNumeric ? value : 0, 1200)

  const colors = {
    red: 'border-t-[3px] border-t-[#e63946] bg-[#161b22] border-[#21262d] text-[#e6edf3]',
    amber: 'border-t-[3px] border-t-[#f4a261] bg-[#161b22] border-[#21262d] text-[#e6edf3]',
    steel: 'border-t-[3px] border-t-[#457b9d] bg-[#161b22] border-[#21262d] text-[#e6edf3]',
    teal: 'border-t-[3px] border-t-[#2a9d8f] bg-[#161b22] border-[#21262d] text-[#e6edf3]',
    green: 'border-t-[3px] border-t-[#3fb950] bg-[#161b22] border-[#21262d] text-[#e6edf3]',
    danger: 'border-t-[3px] border-t-[#f85149] bg-[#161b22] border-[#21262d] text-[#e6edf3]',
  }

  return (
    <div className={`rounded-lg border p-5 ${colors[color] || colors.red} transition-all duration-300`}>
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs font-medium uppercase tracking-wider text-[#8b949e]">{title}</span>
        {Icon && <Icon className="w-5 h-5 text-[#6e7681]" />}
      </div>
      <div className="text-3xl font-bold stat-value">{isNumeric ? animatedValue : value}</div>
      {subtitle && <p className="text-xs mt-1 text-[#6e7681]">{subtitle}</p>}
    </div>
  )
}
