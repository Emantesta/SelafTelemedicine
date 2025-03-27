import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Formik, Form, Field, ErrorMessage } from 'formik';
import * as Yup from 'yup';
import axios from 'axios';
import { toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import Web3 from 'web3';
import QRCode from 'react-qr-code';
import { ethers } from 'ethers';
import debounce from 'lodash/debounce';
import DOMPurify from 'dompurify';

// Import ABIs from Hardhat artifacts
import TelemedicineCoreABI from '../artifacts/contracts/TelemedicineCore.json';
import TelemedicinePaymentsABI from '../artifacts/contracts/TelemedicinePayments.json';
import TelemedicineMedicalABI from '../artifacts/contracts/TelemedicineMedical.json';
import SimplePaymasterABI from '../artifacts/contracts/SimplePaymaster.json';
import SimpleAccountFactoryABI from '../artifacts/contracts/SimpleAccountFactory.json';
import TelemedicineGovernanceCoreABI from '../artifacts/contracts/TelemedicineGovernanceCore.json';
import TelemedicineEmergencyABI from '../artifacts/contracts/TelemedicineEmergency.json';
import TelemedicineSubscriptionABI from '../artifacts/contracts/TelemedicineSubscription.json';

// API Service with improved error handling
const api = {
  get: async (url, token) => {
    try {
      return await axios.get(`${process.env.REACT_APP_API_URL}${url}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
    } catch (error) {
      throw new Error(`API GET failed: ${error.message}`);
    }
  },
  post: async (url, data, token) => {
    try {
      return await axios.post(`${process.env.REACT_APP_API_URL}${url}`, data, {
        headers: { Authorization: `Bearer ${token}` }
      });
    } catch (error) {
      throw new Error(`API POST failed: ${error.message}`);
    }
  }
};

// Validate contract addresses
const validateContractAddress = (address) => {
  if (!ethers.utils.isAddress(address)) {
    throw new Error(`Invalid contract address: ${address}`);
  }
  return address;
};

// Gas configuration
const GAS_CONFIG = {
  default: {
    callGasLimit: process.env.REACT_APP_CALL_GAS_LIMIT || '200000',
    verificationGasLimit: process.env.REACT_APP_VERIFICATION_GAS_LIMIT || '100000',
    preVerificationGas: process.env.REACT_APP_PRE_VERIFICATION_GAS || '21000'
  }
};

// Pack User Operation for ERC-4337 with nonce check
function packUserOp(userOp) {
  const types = [
    'address', 'uint256', 'bytes', 'bytes', 'uint256',
    'uint256', 'uint256', 'uint256', 'bytes', 'bytes'
  ];
  const values = [
    userOp.sender, userOp.nonce, userOp.initCode, userOp.callData, userOp.callGasLimit,
    userOp.verificationGasLimit, userOp.preVerificationGas, userOp.maxFeePerGas,
    userOp.maxPriorityFeePerGas, userOp.paymasterAndData
  ];
  return ethers.utils.defaultAbiCoder.encode(types, values);
}

// Input sanitization function
const sanitizeInput = (input) => {
  return typeof input === 'string' ? DOMPurify.sanitize(input.trim()) : input;
};

const App = ({ account, signer, token }) => {
  const [role, setRole] = useState('patient');
  const [appointments, setAppointments] = useState([]);
  const [labTests, setLabTests] = useState([]);
  const [prescriptions, setPrescriptions] = useState([]);
  const [aiAnalyses, setAIAnalyses] = useState([]);
  const [dataStatus, setDataStatus] = useState({ dataSharing: false, lastRewardTimestamp: 0 });
  const [paymasterStatus, setPaymasterStatus] = useState(null);
  const [aiFundBalance, setAIFundBalance] = useState('0');
  const [timeLocks, setTimeLocks] = useState([]);
  const [isAdmin, setIsAdmin] = useState(false);
  const [subscriptionStatus, setSubscriptionStatus] = useState({ isActive: false, expiry: 0 });
  const [loading, setLoading] = useState(false);
  const [nonceCache, setNonceCache] = useState({});
  const ws = useRef(null);
  const web3 = new Web3(process.env.REACT_APP_SONIC_RPC_URL);

  // Validate contract addresses from env on initialization
  const contracts = {
    core: new web3.eth.Contract(TelemedicineCoreABI.abi, validateContractAddress(process.env.REACT_APP_CORE_ADDRESS)),
    payments: new web3.eth.Contract(TelemedicinePaymentsABI.abi, validateContractAddress(process.env.REACT_APP_PAYMENTS_ADDRESS)),
    medical: new web3.eth.Contract(TelemedicineMedicalABI.abi, validateContractAddress(process.env.REACT_APP_MEDICAL_ADDRESS)),
    paymaster: new web3.eth.Contract(SimplePaymasterABI.abi, validateContractAddress(process.env.REACT_APP_PAYMASTER_ADDRESS)),
    accountFactory: new web3.eth.Contract(SimpleAccountFactoryABI.abi, validateContractAddress(process.env.REACT_APP_ACCOUNT_FACTORY_ADDRESS)),
    governance: new web3.eth.Contract(TelemedicineGovernanceCoreABI.abi, validateContractAddress(process.env.REACT_APP_GOVERNANCE_ADDRESS)),
    emergency: new web3.eth.Contract(TelemedicineEmergencyABI.abi, validateContractAddress(process.env.REACT_APP_EMERGENCY_ADDRESS)),
    subscription: new web3.eth.Contract(TelemedicineSubscriptionABI.abi, validateContractAddress(process.env.REACT_APP_SUBSCRIPTION_ADDRESS)),
  };

  // Validation Schemas with sanitization
  const schemas = {
    appointment: Yup.object({
      doctorAddress: Yup.string()
        .matches(/^0x[a-fA-F0-9]{40}$/, 'Invalid address')
        .transform(sanitizeInput)
        .required('Required'),
      timestamp: Yup.number()
        .min(Math.floor(Date.now() / 1000) + 900, 'Must be at least 15 minutes from now')
        .required('Required'),
      paymentType: Yup.number().min(0).max(2).required('Required'),
      isVideoCall: Yup.boolean(),
      videoCallLink: Yup.string()
        .when('isVideoCall', { 
          is: true, 
          then: Yup.string()
            .transform(sanitizeInput)
            .url('Invalid URL')
            .required('Required') 
        }),
      amount: Yup.string()
        .matches(/^\d+(\.\d+)?$/, 'Invalid amount')
        .transform(sanitizeInput)
        .required('Required'),
    }),
    ai: Yup.object({ 
      symptoms: Yup.string()
        .transform(sanitizeInput)
        .required('Symptoms required') 
    }),
    labTest: Yup.object({
      patientAddress: Yup.string()
        .matches(/^0x[a-fA-F0-9]{40}$/, 'Invalid address')
        .transform(sanitizeInput)
        .required('Required'),
      testType: Yup.string()
        .transform(sanitizeInput)
        .required('Required'),
    }),
    withdraw: Yup.object({
      toAddress: Yup.string()
        .matches(/^0x[a-fA-F0-9]{40}$/, 'Invalid address')
        .transform(sanitizeInput)
        .required('Required'),
      amount: Yup.number()
        .positive('Must be positive')
        .required('Required'),
    }),
    admin: Yup.object({
      adminAddress: Yup.string()
        .matches(/^0x[a-fA-F0-9]{40}$/, 'Invalid address')
        .transform(sanitizeInput)
        .required('Required'),
    }),
    sample: Yup.object({
      labTestId: Yup.number().required('Required'),
      sampleIpfsHash: Yup.string()
        .transform(sanitizeInput)
        .required('Required'),
    }),
    results: Yup.object({
      labTestId: Yup.number().required('Required'),
      resultsIpfsHash: Yup.string()
        .transform(sanitizeInput)
        .required('Required'),
    }),
    prescription: Yup.object({
      prescriptionId: Yup.number().required('Required'),
      verificationCodeHash: Yup.string()
        .transform(sanitizeInput)
        .required('Required'),
    }),
    subscription: Yup.object({
      planId: Yup.number().min(0).max(2).required('Required'),
      amount: Yup.string()
        .matches(/^\d+(\.\d+)?$/, 'Invalid amount')
        .transform(sanitizeInput)
        .required('Required'),
    }),
  };

  useEffect(() => {
    ws.current = new WebSocket('wss://localhost:8080');
    ws.current.onopen = () => toast.info('Connected to server');
    ws.current.onmessage = handleWebSocketMessage;
    ws.current.onerror = () => toast.error('WebSocket error');
    ws.current.onclose = () => toast.warn('Disconnected from server');

    fetchInitialData();
    return () => ws.current.close();
  }, [account, token]);

  const handleWebSocketMessage = (e) => {
    try {
      const data = JSON.parse(e.data);
      switch (data.type) {
        case 'appointmentUpdate':
          setAppointments(data.data);
          break;
        case 'appointmentCancelled':
        case 'appointmentRescheduled':
        case 'subscriptionUpdate':
          fetchInitialData();
          break;
        default:
          break;
      }
    } catch (error) {
      console.error('WebSocket message handling error:', error);
    }
  };

  const fetchInitialData = useCallback(debounce(async () => {
    setLoading(true);
    try {
      // Selective fetching based on role
      const fetchPromises = [];
      if (role === 'patient' || role === 'doctor') fetchPromises.push(fetchAppointments());
      if (role === 'labTech') fetchPromises.push(fetchLabTests());
      if (role === 'pharmacy') fetchPromises.push(fetchPrescriptions());
      if (role === 'patient' || role === 'admin') {
        fetchPromises.push(
          fetchDataStatus(),
          fetchPaymasterStatus(),
          fetchAIFundBalance(),
          fetchSubscriptionStatus()
        );
      }
      if (role === 'admin') {
        fetchPromises.push(checkAdminStatus(), fetchTimeLocks());
      }
      await Promise.all(fetchPromises);
    } catch (error) {
      toast.error(`Failed to load data: ${error.message}`);
      console.error(error);
    } finally {
      setLoading(false);
    }
  }, 300), [account, token, role]);

  const fetchAppointments = async () => {
    const { data } = await api.get(`/appointments/${account}`, token);
    setAppointments(data.appointments || []);
  };

  const fetchLabTests = async () => {
    const { data } = await api.get(`/lab-test/${account}`, token);
    setLabTests(data.labTests || []);
  };

  const fetchPrescriptions = async () => {
    const { data } = await api.get(`/prescription/${account}`, token);
    setPrescriptions(data.prescriptions || []);
  };

  const fetchDataStatus = async () => {
    const { data } = await api.get(`/data-status/${account}`, token);
    setDataStatus(data);
  };

  const fetchPaymasterStatus = async () => {
    const { data } = await api.get('/paymaster-status', token);
    setPaymasterStatus(data);
  };

  const fetchAIFundBalance = async () => {
    const balance = await contracts.medical.methods.aiAnalysisFund().call();
    setAIFundBalance(ethers.utils.formatEther(balance));
  };

  const checkAdminStatus = async () => {
    const { data } = await api.get(`/check-admin/${account}`, token);
    setIsAdmin(data.isAdmin);
  };

  const fetchTimeLocks = async () => {
    const { data } = await api.get('/timelocks', token);
    setTimeLocks(data.timeLocks || []);
  };

  const fetchSubscriptionStatus = async () => {
    const { data } = await api.get(`/subscription-status/${account}`, token);
    setSubscriptionStatus(data);
  };

  const createUserOp = async (callData, contractAddress, value = '0') => {
    try {
      const accountAddress = await contracts.accountFactory.methods.getAddress(account, 0).call();
      const currentNonce = await contracts.core.methods.getNonce(accountAddress).call();
      
      // Replay attack prevention
      if (nonceCache[accountAddress] && currentNonce <= nonceCache[accountAddress]) {
        throw new Error('Potential replay attack detected');
      }
      
      const userOp = {
        sender: accountAddress,
        nonce: currentNonce,
        initCode: '0x',
        callData,
        callGasLimit: GAS_CONFIG.default.callGasLimit,
        verificationGasLimit: GAS_CONFIG.default.verificationGasLimit,
        preVerificationGas: GAS_CONFIG.default.preVerificationGas,
        maxFeePerGas: ethers.utils.parseUnits('10', 'gwei'),
        maxPriorityFeePerGas: ethers.utils.parseUnits('1', 'gwei'),
        paymasterAndData: paymasterStatus?.paymaster || '0x',
      };
      
      const userOpHash = ethers.utils.keccak256(packUserOp(userOp));
      const signature = await signer.signMessage(ethers.utils.arrayify(userOpHash));
      
      setNonceCache(prev => ({ ...prev, [accountAddress]: currentNonce }));
      return { ...userOp, signature };
    } catch (error) {
      throw new Error(`UserOp creation failed: ${error.message}`);
    }
  };

  const handleContractCall = async (endpoint, data, successMessage) => {
    setLoading(true);
    try {
      const sanitizedData = Object.fromEntries(
        Object.entries(data).map(([key, value]) => [key, sanitizeInput(value)])
      );
      const { data: response } = await api.post(endpoint, sanitizedData, token);
      toast.success(successMessage);
      fetchInitialData();
      return response;
    } catch (error) {
      toast.error(`Operation failed: ${error.message}`);
      throw error;
    } finally {
      setLoading(false);
    }
  };

  // Contract Interaction Functions
  const bookAppointment = async (values) => {
    const callData = new ethers.utils.Interface(TelemedicineMedicalABI.abi).encodeFunctionData('bookAppointment', [
      values.doctorAddress, values.timestamp, values.paymentType, values.isVideoCall, values.videoCallLink || '',
    ]);
    const userOp = await createUserOp(callData, process.env.REACT_APP_MEDICAL_ADDRESS, ethers.utils.parseEther(values.amount));
    await handleContractCall('/book-appointment', { ...values, userOp }, 'Appointment booked');
  };

  const cancelAppointment = async (appointmentId) => {
    if (!window.confirm('Are you sure you want to cancel this appointment?')) return;
    const callData = new ethers.utils.Interface(TelemedicineMedicalABI.abi).encodeFunctionData('cancelAppointment', [appointmentId]);
    const userOp = await createUserOp(callData, process.env.REACT_APP_MEDICAL_ADDRESS);
    await handleContractCall('/cancel-appointment', { appointmentId, userOp }, 'Appointment cancelled');
  };

  const rescheduleAppointment = async (appointmentId, newTimestamp) => {
    if (!window.confirm('Are you sure you want to reschedule this appointment?')) return;
    const callData = new ethers.utils.Interface(TelemedicineMedicalABI.abi).encodeFunctionData('rescheduleAppointment', [appointmentId, newTimestamp]);
    const userOp = await createUserOp(callData, process.env.REACT_APP_MEDICAL_ADDRESS);
    await handleContractCall('/reschedule-appointment', { appointmentId, newTimestamp, userOp }, 'Appointment rescheduled');
  };

  const confirmAppointment = async (appointmentId, isEmergency = false) => {
    const callData = new ethers.utils.Interface(TelemedicineMedicalABI.abi).encodeFunctionData('confirmAppointment', [appointmentId, isEmergency]);
    const userOp = await createUserOp(callData, process.env.REACT_APP_MEDICAL_ADDRESS);
    await handleContractCall('/confirm-appointment', { appointmentId, isEmergency, userOp }, 'Appointment confirmed');
  };

  const analyzeSymptoms = async (values) => {
    const callData = new ethers.utils.Interface(TelemedicineMedicalABI.abi).encodeFunctionData('requestAISymptomAnalysis', [values.symptoms]);
    const userOp = await createUserOp(callData, process.env.REACT_APP_MEDICAL_ADDRESS);
    await handleContractCall('/analyze-symptoms', { ...values, userOp }, 'AI analysis requested');
  };

  const decayPoints = async () => {
    const callData = new ethers.utils.Interface(TelemedicineCoreABI.abi).encodeFunctionData('decayPoints', [account]);
    const userOp = await createUserOp(callData, process.env.REACT_APP_CORE_ADDRESS);
    await handleContractCall('/decay-points', { patient: account, userOp }, 'Points decayed');
  };

  const depositAIFund = async (values) => {
    const callData = new ethers.utils.Interface(TelemedicineMedicalABI.abi).encodeFunctionData('depositAIFund', []);
    const tx = await signer.sendTransaction({
      to: process.env.REACT_APP_MEDICAL_ADDRESS,
      value: ethers.utils.parseEther(values.amount),
      data: callData,
    });
    await tx.wait();
    toast.success('AI fund deposited');
    fetchAIFundBalance();
  };

  const queueWithdrawFunds = async (values) => {
    const callData = new ethers.utils.Interface(TelemedicineGovernanceCoreABI.abi).encodeFunctionData('queueWithdrawFunds', [
      values.toAddress, ethers.utils.parseEther(values.amount),
    ]);
    const userOp = await createUserOp(callData, process.env.REACT_APP_GOVERNANCE_ADDRESS);
    await handleContractCall('/queue-withdraw-funds', { ...values, amount: values.amount, userOp }, 'Withdrawal queued');
  };

  const queueAddAdmin = async (values) => {
    const callData = new ethers.utils.Interface(TelemedicineGovernanceCoreABI.abi).encodeFunctionData('queueAddAdmin', [values.adminAddress]);
    const userOp = await createUserOp(callData, process.env.REACT_APP_GOVERNANCE_ADDRESS);
    await handleContractCall('/queue-add-admin', { newAdmin: values.adminAddress, userOp }, 'Admin addition queued');
  };

  const approveTimeLock = async (timeLockId) => {
    const callData = new ethers.utils.Interface(TelemedicineGovernanceCoreABI.abi).encodeFunctionData('approveTimeLock', [timeLockId]);
    const userOp = await createUserOp(callData, process.env.REACT_APP_GOVERNANCE_ADDRESS);
    await handleContractCall('/approve-timelock', { timeLockId, userOp }, 'Time-lock approved');
  };

  const executeTimeLock = async (timeLockId) => {
    const callData = new ethers.utils.Interface(TelemedicineGovernanceCoreABI.abi).encodeFunctionData('executeTimeLock', [timeLockId]);
    const userOp = await createUserOp(callData, process.env.REACT_APP_GOVERNANCE_ADDRESS);
    await handleContractCall('/execute-timelock', { timeLockId, userOp }, 'Time-lock executed');
  };

  const toggleDataMonetization = async (enable) => {
    const callData = new ethers.utils.Interface(TelemedicineCoreABI.abi).encodeFunctionData('toggleDataMonetization', [enable]);
    const userOp = await createUserOp(callData, process.env.REACT_APP_CORE_ADDRESS);
    await handleContractCall('/toggle-data-monetization', { enable, userOp }, `Data monetization ${enable ? 'enabled' : 'disabled'}`);
  };

  const claimDataReward = async () => {
    const callData = new ethers.utils.Interface(TelemedicineCoreABI.abi).encodeFunctionData('claimDataReward', []);
    const userOp = await createUserOp(callData, process.env.REACT_APP_CORE_ADDRESS);
    await handleContractCall('/claim-data-reward', { userOp }, 'Data reward claimed');
  };

  const orderLabTest = async (values) => {
    const callData = new ethers.utils.Interface(TelemedicineMedicalABI.abi).encodeFunctionData('orderLabTest', [values.patientAddress, values.testType]);
    const userOp = await createUserOp(callData, process.env.REACT_APP_MEDICAL_ADDRESS);
    await handleContractCall('/order-lab-test', { ...values, userOp }, 'Lab test ordered');
  };

  const collectSample = async (values) => {
    const callData = new ethers.utils.Interface(TelemedicineMedicalABI.abi).encodeFunctionData('collectSample', [values.labTestId, values.sampleIpfsHash]);
    const userOp = await createUserOp(callData, process.env.REACT_APP_MEDICAL_ADDRESS);
    await handleContractCall('/collect-sample', { ...values, userOp }, 'Sample collected');
  };

  const uploadLabResults = async (values) => {
    const callData = new ethers.utils.Interface(TelemedicineMedicalABI.abi).encodeFunctionData('uploadLabResults', [values.labTestId, values.resultsIpfsHash]);
    const userOp = await createUserOp(callData, process.env.REACT_APP_MEDICAL_ADDRESS);
    await handleContractCall('/upload-lab-results', { ...values, userOp }, 'Results uploaded');
  };

  const verifyPrescription = async (values) => {
    const callData = new ethers.utils.Interface(TelemedicineMedicalABI.abi).encodeFunctionData('verifyPrescription', [values.prescriptionId, values.verificationCodeHash]);
    const userOp = await createUserOp(callData, process.env.REACT_APP_MEDICAL_ADDRESS);
    await handleContractCall('/verify-prescription', { ...values, userOp }, 'Prescription verified');
  };

  const fulfillPrescription = async (prescriptionId) => {
    const callData = new ethers.utils.Interface(TelemedicineMedicalABI.abi).encodeFunctionData('fulfillPrescription', [prescriptionId]);
    const userOp = await createUserOp(callData, process.env.REACT_APP_MEDICAL_ADDRESS);
    await handleContractCall('/fulfill-prescription', { prescriptionId, userOp }, 'Prescription fulfilled');
  };

  const subscribe = async (values) => {
    const callData = new ethers.utils.Interface(TelemedicineSubscriptionABI.abi).encodeFunctionData('subscribe', [values.planId]);
    const userOp = await createUserOp(callData, process.env.REACT_APP_SUBSCRIPTION_ADDRESS, ethers.utils.parseEther(values.amount));
    await handleContractCall('/subscribe', { ...values, userOp }, 'Subscription activated');
  };

  const handleEmergency = async () => {
    const callData = new ethers.utils.Interface(TelemedicineEmergencyABI.abi).encodeFunctionData('declareEmergency', [account]);
    const userOp = await createUserOp(callData, process.env.REACT_APP_EMERGENCY_ADDRESS);
    await handleContractCall('/declare-emergency', { userOp }, 'Emergency declared');
  };

  return (
    <div className="container mx-auto p-6 bg-gray-50 min-h-screen">
      <h1 className="text-3xl font-bold mb-6 text-gray-800">Telemedicine System</h1>
      {loading && <div className="text-center text-blue-600 font-semibold">Loading...</div>}
      <select
        onChange={(e) => setRole(e.target.value)}
        className="mb-6 p-3 border border-gray-300 rounded-lg shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-200"
        disabled={loading}
      >
        <option value="patient">Patient</option>
        <option value="doctor">Doctor</option>
        <option value="labTech">Lab Technician</option>
        <option value="pharmacy">Pharmacy</option>
        {isAdmin && <option value="admin">Admin</option>}
      </select>

      {role === 'patient' && (
        <div className="space-y-8">
          <div className="bg-white p-6 rounded-lg shadow-md">
            <h2 className="text-xl font-semibold mb-4 text-gray-700">System Status</h2>
            <p className="text-gray-600">Paymaster: {paymasterStatus?.paymaster || 'N/A'} ({paymasterStatus?.isTrusted ? 'Trusted' : 'Untrusted'})</p>
            <p className="text-gray-600">AI Fund: {aiFundBalance} ETH</p>
            <p className="text-gray-600">Subscription: {subscriptionStatus.isActive ? 'Active' : 'Inactive'} (Expires: {new Date(subscriptionStatus.expiry * 1000).toLocaleString()})</p>
          </div>
          <div className="bg-white p-6 rounded-lg shadow-md">
            <h2 className="text-xl font-semibold mb-4 text-gray-700">Book Appointment</h2>
            <Formik
              initialValues={{ doctorAddress: '', timestamp: '', paymentType: 0, isVideoCall: false, videoCallLink: '', amount: '' }}
              validationSchema={schemas.appointment}
              onSubmit={bookAppointment}
            >
              {({ isSubmitting, values }) => (
                <Form className="space-y-4">
                  <div>
                    <Field name="doctorAddress" placeholder="Doctor Address" className="w-full p-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-200" disabled={isSubmitting} />
                    <ErrorMessage name="doctorAddress" component="div" className="text-red-500 text-sm mt-1" />
                  </div>
                  <div>
                    <Field name="timestamp" type="number" placeholder="Timestamp (Unix)" className="w-full p-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-200" disabled={isSubmitting} />
                    <ErrorMessage name="timestamp" component="div" className="text-red-500 text-sm mt-1" />
                  </div>
                  <div>
                    <Field name="paymentType" as="select" className="w-full p-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-200" disabled={isSubmitting}>
                      <option value={0}>ETH</option>
                      <option value={1}>USDC</option>
                      <option value={2}>SONIC</option>
                    </Field>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Field name="isVideoCall" type="checkbox" className="h-5 w-5 text-blue-600" disabled={isSubmitting} />
                    <label className="text-gray-700">Video Call</label>
                  </div>
                  {values.isVideoCall && (
                    <div>
                      <Field name="videoCallLink" placeholder="Video Call Link" className="w-full p-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-200" disabled={isSubmitting} />
                      <ErrorMessage name="videoCallLink" component="div" className="text-red-500 text-sm mt-1" />
                    </div>
                  )}
                  <div>
                    <Field name="amount" placeholder="Amount (ETH)" className="w-full p-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-200" disabled={isSubmitting} />
                    <ErrorMessage name="amount" component="div" className="text-red-500 text-sm mt-1" />
                  </div>
                  <button type="submit" disabled={isSubmitting || loading} className="bg-blue-600 hover:bg-blue-700 text-white p-3 rounded-lg w-full transition duration-200 disabled:bg-gray-400">
                    Book Appointment
                  </button>
                </Form>
              )}
            </Formik>
          </div>
          <div className="bg-white p-6 rounded-lg shadow-md">
            <h2 className="text-xl font-semibold mb-4 text-gray-700">Analyze Symptoms</h2>
            <Formik initialValues={{ symptoms: '' }} validationSchema={schemas.ai} onSubmit={analyzeSymptoms}>
              {({ isSubmitting }) => (
                <Form className="space-y-4">
                  <div>
                    <Field name="symptoms" placeholder="Enter symptoms" className="w-full p-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-200" disabled={isSubmitting} />
                    <ErrorMessage name="symptoms" component="div" className="text-red-500 text-sm mt-1" />
                  </div>
                  <button type="submit" disabled={isSubmitting || loading} className="bg-green-600 hover:bg-green-700 text-white p-3 rounded-lg w-full transition duration-200 disabled:bg-gray-400">
                    Analyze Symptoms
                  </button>
                </Form>
              )}
            </Formik>
          </div>
          <div className="bg-white p-6 rounded-lg shadow-md">
            <h2 className="text-xl font-semibold mb-4 text-gray-700">Data Monetization</h2>
            <p className="text-gray-600">Status: {dataStatus.dataSharing ? 'Enabled' : 'Disabled'}</p>
            <p className="text-gray-600">Last Reward: {new Date(dataStatus.lastRewardTimestamp * 1000).toLocaleString()}</p>
            <div className="flex space-x-4 mt-4">
              <button onClick={() => toggleDataMonetization(!dataStatus.dataSharing)} disabled={loading} className="bg-yellow-600 hover:bg-yellow-700 text-white p-3 rounded-lg flex-1 transition duration-200 disabled:bg-gray-400">
                {dataStatus.dataSharing ? 'Disable' : 'Enable'} Data Sharing
              </button>
              <button onClick={claimDataReward} disabled={loading} className="bg-green-600 hover:bg-green-700 text-white p-3 rounded-lg flex-1 transition duration-200 disabled:bg-gray-400">
                Claim Reward
              </button>
              <button onClick={decayPoints} disabled={loading} className="bg-red-600 hover:bg-red-700 text-white p-3 rounded-lg flex-1 transition duration-200 disabled:bg-gray-400">
                Decay Points
              </button>
            </div>
          </div>
          <div className="bg-white p-6 rounded-lg shadow-md">
            <h2 className="text-xl font-semibold mb-4 text-gray-700">Subscription</h2>
            <Formik initialValues={{ planId: 0, amount: '' }} validationSchema={schemas.subscription} onSubmit={subscribe}>
              {({ isSubmitting }) => (
                <Form className="space-y-4">
                  <div>
                    <Field name="planId" as="select" className="w-full p-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-200" disabled={isSubmitting}>
                      <option value={0}>Basic (0.01 ETH)</option>
                      <option value={1}>Premium (0.05 ETH)</option>
                      <option value={2}>Elite (0.1 ETH)</option>
                    </Field>
                  </div>
                  <div>
                    <Field name="amount" placeholder="Amount (ETH)" className="w-full p-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-200" disabled={isSubmitting} />
                    <ErrorMessage name="amount" component="div" className="text-red-500 text-sm mt-1" />
                  </div>
                  <button type="submit" disabled={isSubmitting || loading} className="bg-purple-600 hover:bg-purple-700 text-white p-3 rounded-lg w-full transition duration-200 disabled:bg-gray-400">
                    Subscribe
                  </button>
                </Form>
              )}
            </Formik>
          </div>
          <div className="bg-white p-6 rounded-lg shadow-md">
            <h2 className="text-xl font-semibold mb-4 text-gray-700">Emergency</h2>
            <button onClick={handleEmergency} disabled={loading} className="bg-red-600 hover:bg-red-700 text-white p-3 rounded-lg w-full transition duration-200 disabled:bg-gray-400">
              Declare Emergency
            </button>
          </div>
          <div className="bg-white p-6 rounded-lg shadow-md">
            <h2 className="text-xl font-semibold mb-4 text-gray-700">Appointments</h2>
            {appointments.length === 0 ? (
              <p className="text-gray-500">No appointments found</p>
            ) : (
              appointments.map((apt) => (
                <div key={apt[0]} className="p-4 border border-gray-200 rounded-lg mb-4 shadow-sm">
                  <p className="text-gray-700"><span className="font-semibold">ID:</span> {apt[0]}</p>
                  <p className="text-gray-700"><span className="font-semibold">Doctor:</span> {apt[2]}</p>
                  <p className="text-gray-700"><span className="font-semibold">Time:</span> {new Date(apt[3] * 1000).toLocaleString()}</p>
                  <p className="text-gray-700"><span className="font-semibold">Status:</span> {['Pending', 'Confirmed', 'Completed', 'Cancelled', 'Rescheduled', 'Emergency'][apt[4]]}</p>
                  {apt[4] === 0 && (
                    <div className="mt-2 flex space-x-2">
                      <button onClick={() => cancelAppointment(apt[0])} className="bg-red-600 hover:bg-red-700 text-white p-2 rounded-lg transition duration-200">Cancel</button>
                      <button
                        onClick={() => {
                          const newTime = prompt('Enter new timestamp (Unix):');
                          if (newTime) rescheduleAppointment(apt[0], parseInt(newTime));
                        }}
                        className="bg-yellow-600 hover:bg-yellow-700 text-white p-2 rounded-lg transition duration-200"
                      >
                        Reschedule
                      </button>
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {role === 'doctor' && (
        <div className="space-y-8">
          <div className="bg-white p-6 rounded-lg shadow-md">
            <h2 className="text-xl font-semibold mb-4 text-gray-700">Order Lab Test</h2>
            <Formik initialValues={{ patientAddress: '', testType: '' }} validationSchema={schemas.labTest} onSubmit={orderLabTest}>
              {({ isSubmitting }) => (
                <Form className="space-y-4">
                  <div>
                    <Field name="patientAddress" placeholder="Patient Address" className="w-full p-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-200" disabled={isSubmitting} />
                    <ErrorMessage name="patientAddress" component="div" className="text-red-500 text-sm mt-1" />
                  </div>
                  <div>
                    <Field name="testType" placeholder="Test Type" className="w-full p-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-200" disabled={isSubmitting} />
                    <ErrorMessage name="testType" component="div" className="text-red-500 text-sm mt-1" />
                  </div>
                  <button type="submit" disabled={isSubmitting || loading} className="bg-blue-600 hover:bg-blue-700 text-white p-3 rounded-lg w-full transition duration-200 disabled:bg-gray-400">
                    Order Lab Test
                  </button>
                </Form>
              )}
            </Formik>
          </div>
          <div className="bg-white p-6 rounded-lg shadow-md">
            <h2 className="text-xl font-semibold mb-4 text-gray-700">Appointments</h2>
            {appointments.length === 0 ? (
              <p className="text-gray-500">No appointments found</p>
            ) : (
              appointments.map((apt) => (
                <div key={apt[0]} className="p-4 border border-gray-200 rounded-lg mb-4 shadow-sm">
                  <p className="text-gray-700"><span className="font-semibold">ID:</span> {apt[0]}</p>
                  <p className="text-gray-700"><span className="font-semibold">Patient:</span> {apt[1]}</p>
                  <p className="text-gray-700"><span className="font-semibold">Status:</span> {['Pending', 'Confirmed', 'Completed', 'Cancelled', 'Rescheduled', 'Emergency'][apt[4]]}</p>
                  {apt[7] && <a href={apt[7]} target="_blank" rel="noopener noreferrer" className="text-blue-500 hover:underline">Join Video Call</a>}
                  {apt[4] === 0 && (
                    <div className="mt-2 flex space-x-2">
                      <button onClick={() => confirmAppointment(apt[0], false)} className="bg-green-600 hover:bg-green-700 text-white p-2 rounded-lg transition duration-200" disabled={loading}>
                        Confirm
                      </button>
                      <button onClick={() => confirmAppointment(apt[0], true)} className="bg-red-600 hover:bg-red-700 text-white p-2 rounded-lg transition duration-200" disabled={loading}>
                        Confirm as Emergency
                      </button>
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {role === 'labTech' && (
        <div className="space-y-8">
          <div className="bg-white p-6 rounded-lg shadow-md">
            <h2 className="text-xl font-semibold mb-4 text-gray-700">Collect Sample</h2>
            <Formik initialValues={{ labTestId: '', sampleIpfsHash: '' }} validationSchema={schemas.sample} onSubmit={collectSample}>
              {({ isSubmitting }) => (
                <Form className="space-y-4">
                  <div>
                    <Field name="labTestId" type="number" placeholder="Lab Test ID" className="w-full p-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-200" disabled={isSubmitting} />
                    <ErrorMessage name="labTestId" component="div" className="text-red-500 text-sm mt-1" />
                  </div>
                  <div>
                    <Field name="sampleIpfsHash" placeholder="Sample IPFS Hash" className="w-full p-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-200" disabled={isSubmitting} />
                    <ErrorMessage name="sampleIpfsHash" component="div" className="text-red-500 text-sm mt-1" />
                  </div>
                  <button type="submit" disabled={isSubmitting || loading} className="bg-green-600 hover:bg-green-700 text-white p-3 rounded-lg w-full transition duration-200 disabled:bg-gray-400">
                    Collect Sample
                  </button>
                </Form>
              )}
            </Formik>
          </div>
          <div className="bg-white p-6 rounded-lg shadow-md">
            <h2 className="text-xl font-semibold mb-4 text-gray-700">Upload Lab Results</h2>
            <Formik initialValues={{ labTestId: '', resultsIpfsHash: '' }} validationSchema={schemas.results} onSubmit={uploadLabResults}>
              {({ isSubmitting }) => (
                <Form className="space-y-4">
                  <div>
                    <Field name="labTestId" type="number" placeholder="Lab Test ID" className="w-full p-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-200" disabled={isSubmitting} />
                    <ErrorMessage name="labTestId" component="div" className="text-red-500 text-sm mt-1" />
                  </div>
                  <div>
                    <Field name="resultsIpfsHash" placeholder="Results IPFS Hash" className="w-full p-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-200" disabled={isSubmitting} />
                    <ErrorMessage name="resultsIpfsHash" component="div" className="text-red-500 text-sm mt-1" />
                  </div>
                  <button type="submit" disabled={isSubmitting || loading} className="bg-green-600 hover:bg-green-700 text-white p-3 rounded-lg w-full transition duration-200 disabled:bg-gray-400">
                    Upload Results
                  </button>
                </Form>
              )}
            </Formik>
          </div>
          <div className="bg-white p-6 rounded-lg shadow-md">
            <h2 className="text-xl font-semibold mb-4 text-gray-700">Lab Tests</h2>
            {labTests.length === 0 ? (
              <p className="text-gray-500">No lab tests found</p>
            ) : (
              labTests.map((test) => (
                <div key={test[0]} className="p-4 border border-gray-200 rounded-lg mb-4 shadow-sm">
                  <p className="text-gray-700"><span className="font-semibold">ID:</span> {test[0]}</p>
                  <p className="text-gray-700"><span className="font-semibold">Patient:</span> {test[1]}</p>
                  <p className="text-gray-700"><span className="font-semibold">Status:</span> {['Requested', 'Collected', 'ResultsUploaded', 'Reviewed'][test[4]]}</p>
                  <p className="text-gray-700"><span className="font-semibold">Test Type:</span> {test[5]}</p>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {role === 'pharmacy' && (
        <div className="space-y-8">
          <div className="bg-white p-6 rounded-lg shadow-md">
            <h2 className="text-xl font-semibold mb-4 text-gray-700">Verify Prescription</h2>
            <Formik initialValues={{ prescriptionId: '', verificationCodeHash: '' }} validationSchema={schemas.prescription} onSubmit={verifyPrescription}>
              {({ isSubmitting }) => (
                <Form className="space-y-4">
                  <div>
                    <Field name="prescriptionId" type="number" placeholder="Prescription ID" className="w-full p-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-200" disabled={isSubmitting} />
                    <ErrorMessage name="prescriptionId" component="div" className="text-red-500 text-sm mt-1" />
                  </div>
                  <div>
                    <Field name="verificationCodeHash" placeholder="Verification Code Hash" className="w-full p-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-200" disabled={isSubmitting} />
                    <ErrorMessage name="verificationCodeHash" component="div" className="text-red-500 text-sm mt-1" />
                  </div>
                  <button type="submit" disabled={isSubmitting || loading} className="bg-yellow-600 hover:bg-yellow-700 text-white p-3 rounded-lg w-full transition duration-200 disabled:bg-gray-400">
                    Verify Prescription
                  </button>
                </Form>
              )}
            </Formik>
          </div>
          <div className="bg-white p-6 rounded-lg shadow-md">
            <h2 className="text-xl font-semibold mb-4 text-gray-700">Prescriptions</h2>
            {prescriptions.length === 0 ? (
              <p className="text-gray-500">No prescriptions found</p>
            ) : (
              prescriptions.map((pres) => (
                <div key={pres[0]} className="p-4 border border-gray-200 rounded-lg mb-4 shadow-sm">
                  <p className="text-gray-700"><span className="font-semibold">ID:</span> {pres[0]}</p>
                  <p className="text-gray-700"><span className="font-semibold">Patient:</span> {pres[1]}</p>
                  <p className="text-gray-700"><span className="font-semibold">Status:</span> {['Generated', 'Verified', 'Fulfilled'][pres[6]]}</p>
                  {pres[6] === 0 && (
                    <div className="mt-2">
                      <QRCode value={JSON.stringify({ id: pres[0].toString(), verificationCodeHash: ethers.utils.hexlify(pres[3]) })} size={128} className="mb-2" />
                    </div>
                  )}
                  {pres[6] === 1 && (
                    <button onClick={() => fulfillPrescription(pres[0])} className="bg-green-600 hover:bg-green-700 text-white p-2 rounded-lg transition duration-200" disabled={loading}>
                      Fulfill
                    </button>
                  )}
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {role === 'admin' && isAdmin && (
        <div className="space-y-8">
          <div className="bg-white p-6 rounded-lg shadow-md">
            <h2 className="text-xl font-semibold mb-4 text-gray-700">AI Fund Management</h2>
            <p className="text-gray-600">Balance: {aiFundBalance} ETH</p>
            <Formik initialValues={{ amount: '' }} validationSchema={schemas.withdraw.pick(['amount'])} onSubmit={depositAIFund}>
              {({ isSubmitting }) => (
                <Form className="space-y-4 mt-4">
                  <Field name="amount" type="number" placeholder="Amount (ETH)" className="w-full p-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-200" disabled={isSubmitting} />
                  <ErrorMessage name="amount" component="div" className="text-red-500 text-sm mt-1" />
                  <button type="submit" disabled={isSubmitting || loading} className="bg-blue-600 hover:bg-blue-700 text-white p-3 rounded-lg w-full transition duration-200 disabled:bg-gray-400">
                    Deposit
                  </button>
                </Form>
              )}
            </Formik>
          </div>
          <div className="bg-white p-6 rounded-lg shadow-md">
            <h2 className="text-xl font-semibold mb-4 text-gray-700">Withdraw Funds</h2>
            <Formik initialValues={{ toAddress: '', amount: '' }} validationSchema={schemas.withdraw} onSubmit={queueWithdrawFunds}>
              {({ isSubmitting }) => (
                <Form className="space-y-4">
                  <Field name="toAddress" placeholder="To Address" className="w-full p-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-200" disabled={isSubmitting} />
                  <ErrorMessage name="toAddress" component="div" className="text-red-500 text-sm mt-1" />
                  <Field name="amount" type="number" placeholder="Amount (ETH)" className="w-full p-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-200" disabled={isSubmitting} />
                  <ErrorMessage name="amount" component="div" className="text-red-500 text-sm mt-1" />
                  <button type="submit" disabled={isSubmitting || loading} className="bg-red-600 hover:bg-red-700 text-white p-3 rounded-lg w-full transition duration-200 disabled:bg-gray-400">
                    Queue Withdrawal
                  </button>
                </Form>
              )}
            </Formik>
          </div>
          <div className="bg-white p-6 rounded-lg shadow-md">
            <h2 className="text-xl font-semibold mb-4 text-gray-700">Add Admin</h2>
            <Formik initialValues={{ adminAddress: '' }} validationSchema={schemas.admin} onSubmit={queueAddAdmin}>
              {({ isSubmitting }) => (
                <Form className="space-y-4">
                  <Field name="adminAddress" placeholder="New Admin Address" className="w-full p-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:bg-gray-200" disabled={isSubmitting} />
                  <ErrorMessage name="adminAddress" component="div" className="text-red-500 text-sm mt-1" />
                  <button type="submit" disabled={isSubmitting || loading} className="bg-green-600 hover:bg-green-700 text-white p-3 rounded-lg w-full transition duration-200 disabled:bg-gray-400">
                    Queue Add Admin
                  </button>
                </Form>
              )}
            </Formik>
          </div>
          <div className="bg-white p-6 rounded-lg shadow-md">
            <h2 className="text-xl font-semibold mb-4 text-gray-700">Time-Locks</h2>
            {timeLocks.length === 0 ? (
              <p className="text-gray-500">No time-locks found</p>
            ) : (
              timeLocks.map((tl) => (
                <div key={tl.id} className="p-4 border border-gray-200 rounded-lg mb-4 shadow-sm">
                  <p className="text-gray-700"><span className="font-semibold">ID:</span> {tl.id}</p>
                  <p className="text-gray-700"><span className="font-semibold">Action:</span> {['Withdraw', 'Add Admin', 'Remove Admin'][tl.action]}</p>
                  <p className="text-gray-700"><span className="font-semibold">Target:</span> {tl.target}</p>
                  <p className="text-gray-700"><span className="font-semibold">Amount:</span> {ethers.utils.formatEther(tl.value)} ETH</p>
                  <p className="text-gray-700"><span className="font-semibold">Approvals:</span> {tl.approvalCount}/2</p>
                  <div className="mt-2 flex space-x-2">
                    {!tl.approvals.includes(account) && !tl.executed && (
                      <button onClick={() => approveTimeLock(tl.id)} className="bg-yellow-600 hover:bg-yellow-700 text-white p-2 rounded-lg transition duration-200" disabled={loading}>
                        Approve
                      </button>
                    )}
                    {tl.approvalCount >= 2 && !tl.executed && Date.now() / 1000 >= tl.timestamp + 86400 && (
                      <button onClick={() => executeTimeLock(tl.id)} className="bg-green-600 hover:bg-green-700 text-white p-2 rounded-lg transition duration-200" disabled={loading}>
                        Execute
                      </button>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default App;
