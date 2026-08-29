/**
 * chartConfig.js — Centralized Recharts theme for CipherCrest
 * Standardizes typography (Switzer/Inter), grid strokes, tooltips, axis styling, and color tokens.
 */
import { TOK } from './tokens.js'

export const chartTheme = {
  grid: {
    stroke: '#EEF0F1',
    strokeDasharray: '3 3',
    vertical: false,
  },
  axis: {
    tick: {
      fontFamily: '"Switzer", "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
      fontSize: 11,
      fill: '#6B7280',
    },
    axisLine: {
      stroke: '#E7EAEC',
    },
    tickLine: false,
  },
  tooltip: {
    contentStyle: {
      fontFamily: '"Switzer", "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
      fontSize: 12,
      borderRadius: 10,
      border: '1px solid #E7EAEC',
      boxShadow: '0px 4px 12px rgba(16, 24, 40, 0.08)',
      background: '#FFFFFF',
      color: '#151B1E',
    },
  },
  bar: {
    radius: [6, 6, 0, 0],
    barSize: 26,
  },
  donut: {
    innerRadius: 54,
    outerRadius: 82,
    paddingAngle: 3,
    cornerRadius: 4,
  },
  scatter: {
    dotRadius: 4.5,
  },
  colors: {
    good: '#16A34A',
    warning: '#CA8A04',
    high: '#EA580C',
    bad: '#DC2626',
    info: '#3B82F6',
    neutral: '#6B7280',
    primary: '#1F7A4D',
    primaryLight: '#E7F5EC',
  },
}
