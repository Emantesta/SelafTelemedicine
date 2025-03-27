import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import App from '../../App'; // Adjust path based on your project structure
import { toast } from 'react-toastify';
import axios from 'axios';
import Web3 from 'web3';
import { ethers } from 'ethers';

// Mock dependencies
jest.mock('axios');
jest.mock('react-toastify', () => ({
  toast: {
    success: jest.fn(),
    error: jest.fn(),
    info: jest.fn(),
    warn: jest.fn(),
  },
}));
jest.mock('web3', () => {
  const mockWeb3 = jest.fn(() => ({
    eth: {
      Contract: jest.fn((abi, address) => {
        if (address === process.env.REACT_APP_SUBSCRIPTION_ADDRESS) {
          return {
            methods: {
              getSubscriptionStatus: () => ({
                call: jest.fn().mockResolvedValue([false, '0', '0']), // [isActive, expiry, consultsUsed]
              }),
            },
          };
        }
        if (address === process.env.REACT_APP_MEDICAL_ADDRESS) {
          return {
            methods: {
              aiAnalysisFund: () => ({ call: jest.fn().mockResolvedValue('1000000000000000000') }), // 1 ETH
            },
          };
        }
        if (address === process.env.REACT_APP_CORE_ADDRESS) {
          return {
            methods: {
              getNonce: () => ({ call: jest.fn().mockResolvedValue('1') }),
            },
          };
        }
        if (address === process.env.REACT_APP_ACCOUNT_FACTORY_ADDRESS) {
          return {
            methods: {
              getAddress: () => ({ call: jest.fn().mockResolvedValue('0x1234567890abcdef1234567890abcdef12345678') }),
            },
          };
        }
        return {
          methods: {},
        };
      }),
      getTransactionCount: jest.fn().mockResolvedValue(1),
    },
  }));
  return mockWeb3;
});
jest.mock('ethers', () => ({
  utils: {
    parseEther: jest.fn((val) => `${val}000000000000000000`), // Mock 18 decimals for ETH
    parseUnits: jest.fn((val, decimals) => `${val}${decimals === 6 ? '000000' : '000000000000000000'}`), // Mock 6 decimals for USDC
    formatEther: jest.fn((val) => val / 1e18),
    keccak256: jest.fn(() => '0xmockhash'),
    arrayify: jest.fn((val) => val),
    defaultAbiCoder: { encode: jest.fn(() => '0xencoded') },
    Interface: jest.fn(() => ({
      encodeFunctionData: jest.fn(() => '0xcalldata'),
    })),
  },
}));

const mockSigner = {
  signMessage: jest.fn().mockResolvedValue('0xsignature'),
  sendTransaction: jest.fn().mockResolvedValue({ wait: jest.fn().mockResolvedValue() }),
};

const mockToken = 'mock-token';
const mockAccount = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';

// Setup mock environment variables
process.env.REACT_APP_API_URL = 'http://localhost:3000';
process.env.REACT_APP_SONIC_RPC_URL = 'http://localhost:8545';
process.env.REACT_APP_CORE_ADDRESS = '0xCoreAddress';
process.env.REACT_APP_PAYMENTS_ADDRESS = '0xPaymentsAddress';
process.env.REACT_APP_MEDICAL_ADDRESS = '0xMedicalAddress';
process.env.REACT_APP_PAYMASTER_ADDRESS = '0xPaymasterAddress';
process.env.REACT_APP_ACCOUNT_FACTORY_ADDRESS = '0xAccountFactoryAddress';
process.env.REACT_APP_GOVERNANCE_ADDRESS = '0xGovernanceAddress';
process.env.REACT_APP_EMERGENCY_ADDRESS = '0xEmergencyAddress';
process.env.REACT_APP_SUBSCRIPTION_ADDRESS = '0xSubscriptionAddress';

describe('App Component Unit Tests', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    axios.get.mockImplementation((url) => {
      if (url.includes('/appointments')) return Promise.resolve({ data: { appointments: [] } });
      if (url.includes('/lab-test')) return Promise.resolve({ data: { labTests: [] } });
      if (url.includes('/prescription')) return Promise.resolve({ data: { prescriptions: [] } });
      if (url.includes('/data-status')) return Promise.resolve({ data: { dataSharing: false, lastRewardTimestamp: 0 } });
      if (url.includes('/paymaster-status')) return Promise.resolve({ data: { paymaster: '0xpaymaster', isTrusted: true } });
      if (url.includes('/check-admin')) return Promise.resolve({ data: { isAdmin: false } });
      if (url.includes('/timelocks')) return Promise.resolve({ data: { timeLocks: [] } });
      return Promise.reject(new Error('Unknown endpoint'));
    });
    axios.post.mockResolvedValue({ data: { txHash: '0x123' } });
  });

  // UI Rendering Tests
  it('renders patient UI with all sections', async () => {
    render(<App account={mockAccount} signer={mockSigner} token={mockToken} />);
    
    expect(screen.getByText('Telemedicine System')).toBeInTheDocument();
    expect(screen.getByRole('combobox')).toHaveValue('patient');
    
    await waitFor(() => {
      expect(screen.getByText('System Status')).toBeInTheDocument();
      expect(screen.getByText('Book Appointment')).toBeInTheDocument();
      expect(screen.getByText('Analyze Symptoms')).toBeInTheDocument();
      expect(screen.getByText('Data Monetization')).toBeInTheDocument();
      expect(screen.getByText('Subscription')).toBeInTheDocument();
      expect(screen.getByText('Emergency')).toBeInTheDocument();
      expect(screen.getByText('Appointments')).toBeInTheDocument();
      expect(screen.getByText('Paymaster: 0xpaymaster (Trusted)')).toBeInTheDocument();
      expect(screen.getByText('AI Fund: 1 ETH')).toBeInTheDocument();
      expect(screen.getByText(/Subscription: Inactive/)).toBeInTheDocument();
      expect(screen.getByText('Consults Used: 0')).toBeInTheDocument();
    });
  });

  it('renders doctor UI when role is changed', async () => {
    render(<App account={mockAccount} signer={mockSigner} token={mockToken} />);
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'doctor' } });

    await waitFor(() => {
      expect(screen.getByText('Order Lab Test')).toBeInTheDocument();
      expect(screen.getByText('Appointments')).toBeInTheDocument();
      expect(screen.queryByText('Book Appointment')).not.toBeInTheDocument();
    });
  });

  it('renders admin UI when role is admin and user is authorized', async () => {
    axios.get.mockImplementation((url) => {
      if (url.includes('/check-admin')) return Promise.resolve({ data: { isAdmin: true } });
      if (url.includes('/appointments')) return Promise.resolve({ data: { appointments: [] } });
      if (url.includes('/data-status')) return Promise.resolve({ data: { dataSharing: false, lastRewardTimestamp: 0 } });
      if (url.includes('/paymaster-status')) return Promise.resolve({ data: { paymaster: '0xpaymaster', isTrusted: true } });
      if (url.includes('/timelocks')) return Promise.resolve({ data: { timeLocks: [] } });
      return Promise.resolve({ data: {} });
    });

    render(<App account={mockAccount} signer={mockSigner} token={mockToken} />);
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'admin' } });

    await waitFor(() => {
      expect(screen.getByText('AI Fund Management')).toBeInTheDocument();
      expect(screen.getByText('Withdraw Funds')).toBeInTheDocument();
      expect(screen.getByText('Add Admin')).toBeInTheDocument();
      expect(screen.getByText('Time-Locks')).toBeInTheDocument();
    });
  });

  // Contract Interaction Tests
  it('books an appointment and verifies contract call', async () => {
    render(<App account={mockAccount} signer={mockSigner} token={mockToken} />);

    const doctorAddressInput = screen.getByPlaceholderText('Doctor Address');
    const timestampInput = screen.getByPlaceholderText('Timestamp (Unix)');
    const amountInput = screen.getByPlaceholderText('Amount');
    const submitButton = screen.getByText('Book Appointment');

    fireEvent.change(doctorAddressInput, { target: { value: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8' } });
    fireEvent.change(timestampInput, { target: { value: Math.floor(Date.now() / 1000) + 1000 } });
    fireEvent.change(amountInput, { target: { value: '0.1' } });
    fireEvent.click(submitButton);

    await waitFor(() => {
      expect(axios.post).toHaveBeenCalledWith(
        'http://localhost:3000/book-appointment',
        expect.objectContaining({
          doctorAddress: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
          timestamp: expect.any(Number),
          paymentType: 0, // Default ETH
          isVideoCall: false,
          videoCallLink: '',
          amount: '0.1',
          userOp: expect.objectContaining({
            sender: '0x1234567890abcdef1234567890abcdef12345678',
            nonce: '1',
            callData: '0xcalldata',
          }),
        }),
        { headers: { Authorization: `Bearer ${mockToken}` } }
      );
      expect(toast.success).toHaveBeenCalledWith('Appointment booked');
    });
  });

  it('subscribes to a monthly plan and verifies contract call', async () => {
    render(<App account={mockAccount} signer={mockSigner} token={mockToken} />);

    const planSelect = screen.getByRole('combobox', { name: '' });
    const amountInput = screen.getByPlaceholderText('Amount (USDC)');
    const submitButton = screen.getByText('Subscribe');

    fireEvent.change(planSelect, { target: { value: 'false' } }); // Select Monthly
    fireEvent.change(amountInput, { target: { value: '20' } }); // $20 USDC
    fireEvent.click(submitButton);

    await waitFor(() => {
      expect(axios.post).toHaveBeenCalledWith(
        'http://localhost:3000/subscribe',
        expect.objectContaining({
          isAnnual: false,
          amount: '20000000', // 20 USDC with 6 decimals
          userOp: expect.objectContaining({
            sender: '0x1234567890abcdef1234567890abcdef12345678',
            nonce: '1',
            callData: '0xcalldata',
          }),
        }),
        { headers: { Authorization: `Bearer ${mockToken}` } }
      );
      expect(toast.success).toHaveBeenCalledWith('Subscription activated');
    });
  });

  it('subscribes to an annual plan and verifies contract call', async () => {
    render(<App account={mockAccount} signer={mockSigner} token={mockToken} />);

    const planSelect = screen.getByRole('combobox', { name: '' });
    const amountInput = screen.getByPlaceholderText('Amount (USDC)');
    const submitButton = screen.getByText('Subscribe');

    fireEvent.change(planSelect, { target: { value: 'true' } }); // Select Annual
    fireEvent.change(amountInput, { target: { value: '200' } }); // $200 USDC
    fireEvent.click(submitButton);

    await waitFor(() => {
      expect(axios.post).toHaveBeenCalledWith(
        'http://localhost:3000/subscribe',
        expect.objectContaining({
          isAnnual: true,
          amount: '200000000', // 200 USDC with 6 decimals
          userOp: expect.objectContaining({
            sender: '0x1234567890abcdef1234567890abcdef12345678',
            nonce: '1',
            callData: '0xcalldata',
          }),
        }),
        { headers: { Authorization: `Bearer ${mockToken}` } }
      );
      expect(toast.success).toHaveBeenCalledWith('Subscription activated');
    });
  });

  it('toggles data monetization and verifies contract call', async () => {
    render(<App account={mockAccount} signer={mockSigner} token={mockToken} />);

    const toggleButton = screen.getByText('Enable Data Sharing');
    fireEvent.click(toggleButton);

    await waitFor(() => {
      expect(axios.post).toHaveBeenCalledWith(
        'http://localhost:3000/toggle-data-monetization',
        expect.objectContaining({
          enable: true,
          userOp: expect.objectContaining({
            sender: '0x1234567890abcdef1234567890abcdef12345678',
            nonce: '1',
            callData: '0xcalldata',
          }),
        }),
        { headers: { Authorization: `Bearer ${mockToken}` } }
      );
      expect(toast.success).toHaveBeenCalledWith('Data monetization enabled');
    });
  });

  it('deposits to AI fund and verifies transaction', async () => {
    axios.get.mockImplementation((url) => {
      if (url.includes('/check-admin')) return Promise.resolve({ data: { isAdmin: true } });
      if (url.includes('/appointments')) return Promise.resolve({ data: { appointments: [] } });
      if (url.includes('/data-status')) return Promise.resolve({ data: { dataSharing: false, lastRewardTimestamp: 0 } });
      if (url.includes('/paymaster-status')) return Promise.resolve({ data: { paymaster: '0xpaymaster', isTrusted: true } });
      if (url.includes('/timelocks')) return Promise.resolve({ data: { timeLocks: [] } });
      return Promise.resolve({ data: {} });
    });

    render(<App account={mockAccount} signer={mockSigner} token={mockToken} />);
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'admin' } });

    await waitFor(() => {
      const amountInput = screen.getByPlaceholderText('Amount (ETH)');
      const depositButton = screen.getByText('Deposit');
      fireEvent.change(amountInput, { target: { value: '0.5' } });
      fireEvent.click(depositButton);
    });

    await waitFor(() => {
      expect(mockSigner.sendTransaction).toHaveBeenCalledWith({
        to: process.env.REACT_APP_MEDICAL_ADDRESS,
        value: '0.5000000000000000000', // 0.5 ETH with 18 decimals
        data: '0xcalldata',
      });
      expect(toast.success).toHaveBeenCalledWith('AI fund deposited');
    });
  });

  it('handles error when contract call fails', async () => {
    axios.post.mockRejectedValueOnce(new Error('Network error'));

    render(<App account={mockAccount} signer={mockSigner} token={mockToken} />);
    const submitButton = screen.getByText('Book Appointment');
    fireEvent.change(screen.getByPlaceholderText('Doctor Address'), { target: { value: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8' } });
    fireEvent.change(screen.getByPlaceholderText('Timestamp (Unix)'), { target: { value: Math.floor(Date.now() / 1000) + 1000 } });
    fireEvent.change(screen.getByPlaceholderText('Amount'), { target: { value: '0.1' } });
    fireEvent.click(submitButton);

    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith('Operation failed: Network error');
    });
  });
});
