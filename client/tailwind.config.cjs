/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{js,jsx,ts,tsx}'],
  corePlugins: {
    preflight: false
  },
  theme: {
    extend: {
      fontFamily: {
        sans: ['Outfit', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'monospace']
      },
      colors: {
        viro: {
          50: '#f4f7f5',
          100: '#e7eeea',
          200: '#d1ddd6',
          300: '#a8beae',
          400: '#6d947d',
          500: '#3e6e56',
          600: '#2a5943',
          700: '#214837',
          800: '#19392c',
          900: '#11251d'
        }
      },
      boxShadow: {
        panel: '0 18px 48px rgba(15, 23, 42, 0.08)',
        soft: '0 8px 24px rgba(15, 23, 42, 0.06)'
      },
      borderRadius: {
        panel: '1.5rem'
      }
    }
  },
  plugins: []
};
