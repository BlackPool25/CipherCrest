import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { visualizer } from 'rollup-plugin-visualizer'

export default defineConfig({
  plugins: [react(), visualizer({ filename: 'dist/bundle-stats.html' })],
  build: { chunkSizeWarningLimit: 600, rollupOptions: { output: { manualChunks: { recharts: ['recharts'] } } } },
  server: { proxy: { '/api': 'http://localhost:8000' } }
})
