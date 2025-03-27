import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App'; // Adjust path if App.jsx is in a different directory
import { ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import { ethers } from 'ethers';

// Load environment variables
import './env'; // Assuming you have an env.js or similar to load .env variables

// Polyfill for WebSocket in case of older browsers
if (!window.WebSocket) {
  window.WebSocket = require('websocket').w3cwebsocket;
}

// Function to initialize Web3 provider and signer
async function initializeWeb3() {
  try {
    let provider;
    let signer;
    let account;

    // Check if MetaMask or another Web3 wallet is available
    if (window.ethereum) {
      provider = new ethers.providers.Web3Provider(window.ethereum, 'any');
      
      // Request account access
      await window.ethereum.request({ method: 'eth_requestAccounts' });
      signer = provider.getSigner();
      account = await signer.getAddress();

      // Handle chain changes
      window.ethereum.on('chainChanged', () => {
        window.location.reload();
      });

      // Handle account changes
      window.ethereum.on('accountsChanged', (accounts) => {
        if (accounts.length > 0) {
          window.location.reload();
        } else {
          // User disconnected wallet
          provider = null;
          signer = null;
          account = null;
          renderApp(null, null, null);
        }
      });

      // Handle disconnect
      window.ethereum.on('disconnect', () => {
        provider = null;
        signer = null;
        account = null;
        renderApp(null, null, null);
      });
    } else {
      // Fallback to a read-only provider if no wallet is detected
      provider = new ethers.providers.JsonRpcProvider(process.env.REACT_APP_SONIC_RPC_URL);
      signer = null;
      account = null;
      console.warn('No Web3 wallet detected. Running in read-only mode.');
    }

    return { provider, signer, account };
  } catch (error) {
    console.error('Failed to initialize Web3:', error);
    throw error;
  }
}

// Function to fetch authentication token (simplified example)
async function fetchAuthToken(account) {
  if (!account) return null;
  try {
    // This is a placeholder; replace with actual authentication logic
    const response = await fetch(`${process.env.REACT_APP_API_URL}/auth`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ address: account }),
    });
    const data = await response.json();
    return data.token || 'mock-token'; // Replace with real token retrieval
  } catch (error) {
    console.error('Failed to fetch auth token:', error);
    return 'mock-token'; // Fallback for testing
  }
}

// Render the application
function renderApp(signer, account, token) {
  const root = ReactDOM.createRoot(document.getElementById('root'));
  root.render(
    <React.StrictMode>
      <App account={account} signer={signer} token={token} />
      <ToastContainer 
        position="top-right"
        autoClose={5000}
        hideProgressBar={false}
        newestOnTop={false}
        closeOnClick
        rtl={false}
        pauseOnFocusLoss
        draggable
        pauseOnHover
        theme="light"
      />
    </React.StrictMode>
  );
}

// Main initialization function
async function main() {
  try {
    const { signer, account } = await initializeWeb3();
    const token = await fetchAuthToken(account);
    renderApp(signer, account, token);
  } catch (error) {
    console.error('Application initialization failed:', error);
    // Render with fallback values to show error state
    renderApp(null, null, null);
  }
}

// Start the application
main();

// Handle hot module replacement for development
if (module.hot) {
  module.hot.accept();
}
