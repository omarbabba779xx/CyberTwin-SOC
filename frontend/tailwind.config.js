/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        brand: {
          red: '#e63946',
          amber: '#f4a261',
          steel: '#457b9d',
          teal: '#2a9d8f',
          dark: '#0d1117',
          card: '#161b22',
          border: '#21262d',
          hover: '#1c2333',
        }
      },
      fontFamily: {
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'sans-serif'],
        mono: ['JetBrains Mono', 'Consolas', 'monospace'],
      },
    },
  },
  plugins: [],
}
