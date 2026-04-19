/**
 * Export utilities for CyberTwin SOC
 * Supports CSV and JSON export with automatic file download
 */

export function exportToCSV(data, filename = 'export.csv') {
  if (!data || !data.length) return

  // Flatten nested objects for CSV compatibility
  const flattenObject = (obj, prefix = '') => {
    const flat = {}
    for (const [key, value] of Object.entries(obj)) {
      const fullKey = prefix ? `${prefix}.${key}` : key
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        Object.assign(flat, flattenObject(value, fullKey))
      } else if (Array.isArray(value)) {
        flat[fullKey] = value.join('; ')
      } else {
        flat[fullKey] = value
      }
    }
    return flat
  }

  const flatData = data.map(item => flattenObject(item))

  // Collect all unique headers
  const headers = [...new Set(flatData.flatMap(item => Object.keys(item)))]

  // Escape CSV value
  const escapeCSV = (val) => {
    if (val === null || val === undefined) return ''
    const str = String(val)
    if (str.includes(',') || str.includes('"') || str.includes('\n')) {
      return `"${str.replace(/"/g, '""')}"`
    }
    return str
  }

  const csvRows = [
    headers.map(escapeCSV).join(','),
    ...flatData.map(row =>
      headers.map(h => escapeCSV(row[h])).join(',')
    )
  ]

  const csvContent = csvRows.join('\n')
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' })
  triggerDownload(blob, filename)
}

export function exportToJSON(data, filename = 'export.json') {
  if (!data) return

  const jsonContent = JSON.stringify(data, null, 2)
  const blob = new Blob([jsonContent], { type: 'application/json;charset=utf-8;' })
  triggerDownload(blob, filename)
}

function triggerDownload(blob, filename) {
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  URL.revokeObjectURL(url)
}
