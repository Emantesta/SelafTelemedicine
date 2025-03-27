import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import App from '../App';
import { toast } from 'react-toastify';
import axios from 'axios';
import Web3 from 'web3';
import { ethers } from 'ethers';

// Mock dependencies
jest.mock('axios');
jest.mock('react-toastify', () => ({
  toast: { success: jest.fn(), error: jest.fn(), info: jest.fn(), warn: jest.fn() },
}));
jest.mock('web3', () => {
  const mockWeb3 = jest.fn(() => ({
    eth: {
      Contract: jest.fn((abi, address) => {
        if (address === process.env.REACT_APP_SUBSCRIPTION_ADDRESS) {
          return {
            methods: {
              getSubscriptionStatus: () => ({
                call: jest.fn().mockResolvedValue([false, '0', '0']), // isActive, expiry, consultsUsed
              }),
            },
          };
        }
        return {
          methods: {
            aiAnalysisFund: () => ({ call: jest.fn().mockResolvedValue('1000000000000000000') }), // 1 ETH
            getNonce: () => ({ call: jest.fn().mockResolvedValue('1') }),
            getAddress: () => ({ call: jest.fn().mockResolvedValue('0x1234567890abcdef1234567890abcdef12345678') }),
          },
        };
      }),
      getTransactionCount: jest.fn().mockResolvedValue(1),
    },
  }));
  return mockWeb3;
});
jest.mock('ethers', () => ({
  utils: {
    parseEther: jest.fn((val) => val),
    parseUnits: jest.fn((val, decimals) => `${val}${decimals === 6 ? '000000' : '000000000000000000'}`), // Mock USDC (6 decimals) and ETH (18 decimals)
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

describe('App Component', () => {
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

  it('renders patient UI and fetches initial data', async () => {
    render(<App account={mockAccount} signer={mockSigner} token={mockToken} />);
    expect(screen.getByText('Telemedicine System')).toBeInTheDocument();
    expect(screen.getByText('Patient')).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByText('System Status')).toBeInTheDocument();
      expect(screen.getByText('Paymaster: 0xpaymaster (Trusted)')).toBeInTheDocument();
      expect(screen.getByText('AI Fund: 1 ETH')).toBeInTheDocument();
      expect(screen.getByText(/Subscription: Inactive/)).toBeInTheDocument();
      expect(screen.getByText('Consults Used: 0')).toBeInTheDocument();
    });
  });

  it('books an appointment successfully', async () => {
    render(<App account={mockAccount} signer={mockSigner} token={mockToken} />);
    fireEvent.change(screen.getByPlaceholderText('Doctor Address'), { target: { value: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8' } });
    fireEvent.change(screen.getByPlaceholderText('Timestamp (Unix)'), { target: { value: Math.floor(Date.now() / 1000) + 1000 } });
    fireEvent.change(screen.getByPlaceholderText('Amount'), { target: { value: '0.1' } }); // Updated placeholder to match UI
    fireEvent.click(screen.getByText('Book Appointment'));

    await waitFor(() => {
      expect(axios.post).toHaveBeenCalledWith(
        `${process.env.REACT_APP_API_URL}/book-appointment`,
        expect.objectContaining({
          doctorAddress: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
          timestamp: expect.any(Number),
          amount: '0.1',
          userOp: expect.objectContaining({ sender: '0x1234567890abcdef1234567890abcdef12345678' }),
        }),
        { headers: { Authorization: `Bearer ${mockToken}` } }
      );
      expect(toast.success).toHaveBeenCalledWith('Appointment booked');
    });
  });

  it('toggles data monetization', async () => {
    render(<App account={mockAccount} signer={mockSigner} token={mockToken} />);
    fireEvent.click(screen.getByText('Enable Data Sharing'));

    await waitFor(() => {
      expect(axios.post).toHaveBeenCalledWith(
        `${process.env.REACT_APP_API_URL}/toggle-data-monetization`,
        expect.objectContaining({ enable: true, userOp: expect.any(Object) }),
        { headers: { Authorization: `Bearer ${mockToken}` } }
      );
      expect(toast.success).toHaveBeenCalledWith('Data monetization enabled');
    });
  });

  it('decays points', async () => {
    render(<App account={mockAccount} signer={mockSigner} token={mockToken} />);
    fireEvent.click(screen.getByText('Decay Points'));

    await waitFor(() => {
      expect(axios.post).toHaveBeenCalledWith(
        `${process.env.REACT_APP_API_URL}/decay-points`,
        expect.objectContaining({ patient: mockAccount, userOp: expect.any(Object) }),
        { headers: { Authorization: `Bearer ${mockToken}` } }
      );
      expect(toast.success).toHaveBeenCalledWith('Points decayed');
    });
  });

  it('subscribes to a plan successfully', async () => {
    render(<App account={mockAccount} signer={mockSigner} token={mockToken} />);
    fireEvent.change(screen.getByRole('combobox', { name: '' }), { target: { value: 'true' } }); // Select Annual
    fireEvent.change(screen.getByPlaceholderText('Amount (USDC)'), { target: { value: '200' } }); // Updated placeholder
    fireEvent.click(screen.getByText('Subscribe'));

    await waitFor(() => {
      expect(axios.post).toHaveBeenCalledWith(
        `${process.env.REACT_APP_API_URL}/subscribe`,
        expect.objectContaining({
          isAnnual: true,
          amount: '200000000', // USDC with 6 decimals
          userOp: expect.objectContaining({ sender: '0x1234567890abcdef1234567890abcdef12345678' }),
        }),
        { headers: { Authorization: `Bearer ${mockToken}` } }
      );
      expect(toast.success).toHaveBeenCalledWith('Subscription activated');
    });
  });

  it('handles emergency declaration', async () => {
    render(<App account={mockAccount} signer={mockSigner} token={mockToken} />);
    fireEvent.click(screen.getByText('Declare Emergency'));

    await waitFor(() => {
      expect(axios.post).toHaveBeenCalledWith(
        `${process.env.REACT_APP_API_URL}/declare-emergency`,
        expect.objectContaining({ userOp: expect.any(Object) }),
        { headers: { Authorization: `Bearer ${mockToken}` } }
      );
      expect(toast.success).toHaveBeenCalledWith('Emergency declared');
    });
  });

  it('renders admin UI for admin role', async () => {
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
});
