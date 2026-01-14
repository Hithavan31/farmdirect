/**
 * FarmDirect API Configuration
 * Automatically switches between local and production API
 */

const CONFIG = {
  // Determine environment
  isLocal: window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1',
  
  // API URLs
  API_URL: window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? 'http://localhost:3000'
    : 'https://farmdirect-backendd.onrender.com', // ⚠️ CHANGE THIS to your actual Render URL
  
  // App URLs
  APP_URL: window.location.origin,
  
  // Feature flags
  DEBUG: window.location.hostname === 'localhost'
};

// Log configuration (only in development)
if (CONFIG.DEBUG) {
  console.log('🔧 FarmDirect Configuration:', CONFIG);
  console.log('📍 Environment:', CONFIG.isLocal ? 'Local Development' : 'Production');
  console.log('🌐 API URL:', CONFIG.API_URL);
  console.log('🏠 App URL:', CONFIG.APP_URL);
}

// Export for use in other scripts
window.FARMDIRECT_CONFIG = CONFIG;