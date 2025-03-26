require('dotenv').config();
const express = require('express');
const https = require('https');
const fs = require('fs');
const WebSocket = require('ws');
const { ethers } = require('ethers');
const jwt = require('jsonwebtoken');
const winston = require('winston');
const cors = require('cors');
const { create } = require('ipfs-http-client');
const QRCode = require('qrcode');
const tf = require('@tensorflow/tfjs-node');
const { packUserOp } = require('@account-abstraction/utils');
const { EntryPoint__factory } = require('@account-abstraction/contracts');
const mongoose = require('mongoose');
const axios = require('axios');
const rateLimit = require('express-rate-limit');
const { body, param, validationResult } = require('express-validator');
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');
const NodeCache = require('node-cache');
// Setup
const app = express();
const server = https.createServer({
    cert: fs.readFileSync(process.env.SSL_CERT_PATH || './cert.pem'),
    key: fs.readFileSync(process.env.SSL_KEY_PATH || './key.pem'),
});
const wss = new WebSocket.Server({ server });
const ipfs = create({ host: 'ipfs.infura.io', port: 5001, protocol: 'https' });
const provider = new ethers.providers.JsonRpcProvider(process.env.SONIC_RPC_URL || 'https://rpc.sonic.example.com');
const wallet = new ethers.Wallet(process.env.PRIVATE_KEY, provider);
const cache = new NodeCache({ stdTTL: 300, checkperiod: 320 }); // 5-minute cache
// Rate Limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.'
});
// Contract Instances
const coreContract = new ethers.Contract(
    process.env.CORE_ADDRESS || '0x...',
    [
        'function registerPatient(string) external',
        'function verifyDoctor(address,string,uint256) external',
        'function verifyLabTechnician(address,string) external',
        'function registerPharmacy(address,string) external',
        'function toggleDataMonetization(bool) external',
        'function claimDataReward() external',
        'function decayPoints(address) external',
        'function getPatientLevel(address) view returns (uint8)',
        'function getPatientPoints(address) view returns (uint96)',
        'function getDoctorFee(address) view returns (uint256)',
        'function hasRole(bytes32,address) view returns (bool)',
        'function aiAnalysisFund() view returns (uint256)',
        'function reserveFund() view returns (uint256)',
        'function nonces(address) view returns (uint256)',
    ],
    wallet
);
const paymentsContract = new ethers.Contract(
    process.env.PAYMENTS_ADDRESS || '0x...',
    [
        'function usdcToken() view returns (address)',
        'function sonicToken() view returns (address)',
        'function deposit(address,uint256) external payable',
    ],
    wallet
);
const medicalContract = new ethers.Contract(
    process.env.MEDICAL_ADDRESS || '0x...',
    [
        'function bookAppointment(address,uint48,uint8,bool,string) external payable',
        'function confirmAppointment(uint256,bool) external',
        'function batchConfirmAppointments(uint256[]) external',
        'function completeAppointment(uint256,string) external',
        'function cancelAppointment(uint256) external',
        'function rescheduleAppointment(uint256,uint48) external',
        'function requestAISymptomAnalysis(string) external',
        'function reviewAISymptomAnalysis(uint256,string) external',
        'function orderLabTest(address,string) external',
        'function collectSample(uint256,string) external',
        'function uploadLabResults(uint256,string) external',
        'function reviewLabResults(uint256,string,string) external',
        'function verifyPrescription(uint256,bytes32) external',
        'function fulfillPrescription(uint256) external',
        'function appointments(uint256) view returns (tuple(uint256,address,address,uint48,uint8,uint96,uint8,bool,bool,string))',
        'function labTestOrders(uint256) view returns (tuple(uint256,address,address,address,uint8,uint48,uint48,string,string,string))',
        'function prescriptions(uint256) view returns (tuple(uint256,address,address,bytes32,uint8,address,uint48,uint48,string,string))',
        'function aiAnalyses(uint256) view returns (tuple(uint256,address,bool,string,string))',
    ],
    wallet
);
const paymasterContract = new ethers.Contract(
    process.env.PAYMASTER_ADDRESS || '0x...',
    [
        'function deposit(uint8,uint256) external payable',
        'function validatePaymasterUserOp(tuple(address,uint256,bytes,bytes,uint256,uint256,uint256,uint256,uint256,bytes),bytes32,uint256) external returns (uint256,bytes)',
        'function getBalance(uint8) external view returns (uint256)',
    ],
    wallet
);
const accountFactoryContract = new ethers.Contract(
    process.env.ACCOUNT_FACTORY_ADDRESS || '0x...',
    [
        'function createAccount(address,uint256) external returns (address)',
        'function getAddress(address,uint256) external view returns (address)',
    ],
    wallet
);
const governanceContract = new ethers.Contract(
    process.env.GOVERNANCE_ADDRESS || '0x...',
    [
        'function queueWithdrawFunds(address,uint256) external',
        'function queueAddAdmin(address) external',
        'function queueRemoveAdmin(address) external',
        'function approveTimeLock(uint256) external',
        'function executeTimeLock(uint256) external',
        'function cancelTimeLock(uint256) external',
        'function timeLocks(uint256) view returns (tuple(uint256,uint8,address,uint256,bytes,uint256,address[],uint256,bool,bool))',
    ],
    wallet
);
const emergencyContract = new ethers.Contract(
    process.env.EMERGENCY_ADDRESS || '0x...',
    [
        'function emergencyPause() external',
        'function requestEmergencyUnpause() external',
        'function approveEmergencyUnpause(uint256) external',
        'function requestEmergencyFundWithdrawal(uint256) external',
        'function approveEmergencyFundWithdrawal(uint256,uint256) external',
    ],
    wallet
);
const subscriptionContract = new ethers.Contract(
    process.env.SUBSCRIPTION_ADDRESS || '0x...',
    [
        'function subscribe(uint8) external payable',
        'function getSubscriptionStatus(address) view returns (bool,uint256,uint256)',
    ],
    wallet
);
const entryPoint = EntryPoint__factory.connect(process.env.ENTRYPOINT_ADDRESS || '0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789', wallet);
app.use(cors({ origin: process.env.FRONTEND_URL || 'http://localhost:3000' }));
app.use(express.json());
app.use(limiter);
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
    transports: [
        new winston.transports.File({ filename: 'error.log', level: 'error' }),
        new winston.transports.Console(),
    ],
});
// MongoDB Setup
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/telemedicine', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => logger.info('Connected to MongoDB'))
  .catch(err => logger.error('MongoDB connection error:', err));
// Schemas
const UserSchema = new mongoose.Schema({
    address: { type: String, required: true, unique: true },
    role: { type: String, enum: ['patient', 'doctor', 'labTech', 'pharmacy', 'admin'], default: 'patient' },
    createdAt: { type: Date, default: Date.now },
});
const User = mongoose.model('User', UserSchema);
const UserOpSchema = new mongoose.Schema({
    sender: { type: String, required: true },
    nonce: { type: Number, required: true },
    initCode: { type: String, required: true },
    callData: { type: String, required: true },
    callGasLimit: Number,
    verificationGasLimit: Number,
    preVerificationGas: Number,
    maxFeePerGas: String,
    maxPriorityFeePerGas: String,
    paymasterAndData: String,
    signature: { type: String, required: true },
    txHash: String,
    status: { type: String, enum: ['pending', 'validated', 'submitted', 'failed'], default: 'pending' },
    createdAt: { type: Date, default: Date.now },
});
const UserOp = mongoose.model('UserOp', UserOpSchema);
const TimeLockSchema = new mongoose.Schema({
    id: { type: Number, required: true },
    action: { type: Number, required: true },
    target: { type: String, required: true },
    value: { type: String, required: true },
    data: { type: String, required: true },
    timestamp: { type: Number, required: true },
    approvalCount: { type: Number, default: 0 },
    executed: { type: Boolean, default: false },
    cancelled: { type: Boolean, default: false },
    approvals: [{ type: String }],
});
const TimeLock = mongoose.model('TimeLock', TimeLockSchema);
const DisputeSchema = new mongoose.Schema({
    id: { type: Number, required: true },
    initiator: { type: String, required: true },
    relatedId: { type: Number, required: true },
    status: { type: Number, enum: [0, 1, 2], default: 0 },
    reason: { type: String, required: true },
    resolutionTimestamp: { type: Number, default: 0 },
});
const Dispute = mongoose.model('Dispute', DisputeSchema);
// Swagger Setup
const swaggerOptions = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'Telemedicine API',
            version: '1.0.0',
            description: 'API for blockchain-based telemedicine platform'
        },
        servers: [{ url: 'https://localhost:8080' }],
    },
    apis: ['backend.js'],
};
const swaggerSpec = swaggerJsdoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));
// Error Handling Middleware
const errorHandler = (err, req, res, next) => {
    logger.error(${req.method} ${req.url} - Error: ${err.message}, { stack: err.stack });
    res.status(500).json({ error: 'Internal server error', message: err.message });
};
// Validation Middleware
const validate = (validations) => {
    return async (req, res, next) => {
        await Promise.all(validations.map(validation => validation.run(req)));
        const errors = validationResult(req);
        if (errors.isEmpty()) return next();
        return res.status(400).json({ errors: errors.array() });
    };
};
// Auth Middleware
const authMiddleware = async (req, res, next) => {
    try {
        const token = req.headers['authorization']?.split(' ')[1];
        if (!token) throw new Error('Token required');
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
        req.user = decoded;
        next();
    } catch (error) {
        logger.error('Auth error:', error);
        res.status(401).json({ error: 'Authentication failed', message: error.message });
    }
};
// User Operation Handling
async function createUserOperation(sender, callData, gasParams = {}) {
    try {
        const nonce = await coreContract.nonces(sender);
        const userOp = {
            sender,
            nonce: nonce.toNumber(),
            initCode: gasParams.initCode || '0x',
            callData,
            callGasLimit: gasParams.callGasLimit || 200000,
            verificationGasLimit: gasParams.verificationGasLimit || 100000,
            preVerificationGas: gasParams.preVerificationGas || 21000,
            maxFeePerGas: gasParams.maxFeePerGas || ethers.utils.parseUnits('10', 'gwei'),
            maxPriorityFeePerGas: gasParams.maxPriorityFeePerGas || ethers.utils.parseUnits('1', 'gwei'),
            paymasterAndData: '0x',
            signature: '0x',
        };

    if (gasParams.value) userOp.value = gasParams.value;

    const user = await User.findOne({ address: sender });
    if (user && user.role === 'patient') {
        const [isActive] = await subscriptionContract.getSubscriptionStatus(sender);
        if (isActive) {
            const sponsorType = gasParams.sponsorType || 0;
            const paymasterData = await generatePaymasterData(userOp, sponsorType);
            userOp.paymasterAndData = ethers.utils.hexConcat([
                paymasterContract.address,
                ethers.utils.hexZeroPad(ethers.utils.hexlify(sponsorType), 1),
                paymasterData,
            ]);
        }
    }

    const userOpHash = ethers.utils.keccak256(packUserOp(userOp));
    const signature = await wallet.signMessage(ethers.utils.arrayify(userOpHash));
    userOp.signature = signature;

    return userOp;
} catch (error) {
    logger.error('Create user operation error:', error);
    throw error;
}

}
async function generatePaymasterData(userOp, sponsorType) {
    try {
        const deadline = Math.floor(Date.now() / 1000) + 3600;
        return ethers.utils.defaultAbiCoder.encode(['uint256'], [deadline]);
    } catch (error) {
        logger.error('Generate paymaster data error:', error);
        throw error;
    }
}
async function validateUserOp(userOp) {
    try {
        const userOpHash = ethers.utils.keccak256(packUserOp(userOp));
        const recoveredAddress = ethers.utils.verifyMessage(ethers.utils.arrayify(userOpHash), userOp.signature);
        if (recoveredAddress.toLowerCase() !== userOp.sender.toLowerCase()) {
            throw new Error('Invalid signature');
        }

    const onChainNonce = await coreContract.nonces(userOp.sender);
    if (userOp.nonce < onChainNonce.toNumber()) {
        throw new Error('Nonce too low');
    }

    if (userOp.paymasterAndData !== '0x') {
        const paymasterAddress = userOp.paymasterAndData.slice(0, 42);
        const sponsorType = parseInt(userOp.paymasterAndData.slice(42, 44), 16);
        const totalGasCost = ethers.BigNumber.from(userOp.maxFeePerGas)
            .mul(userOp.callGasLimit + userOp.verificationGasLimit + userOp.preVerificationGas);
        const balance = await paymasterContract.getBalance(sponsorType);
        if (balance.lt(totalGasCost)) {
            throw new Error('Insufficient paymaster funding');
        }

        const [validationResult] = await paymasterContract.validatePaymasterUserOp(userOp, userOpHash, totalGasCost);
        if (validationResult.toNumber() !== 0) {
            throw new Error('Paymaster validation failed');
        }
    }

    return true;
} catch (error) {
    logger.error('UserOp validation error:', error);
    return false;
}

}
async function submitUserOperation(userOp) {
    try {
        const dbUserOp = new UserOp({ ...userOp, status: 'pending' });
        await dbUserOp.save();

    const isValid = await validateUserOp(userOp);
    if (!isValid) {
        dbUserOp.status = 'failed';
        await dbUserOp.save();
        throw new Error('UserOp validation failed');
    }

    dbUserOp.status = 'validated';
    await dbUserOp.save();

    const tx = await entryPoint.handleOps([userOp], wallet.address, {
        gasLimit: ethers.BigNumber.from(userOp.callGasLimit)
            .add(userOp.verificationGasLimit)
            .add(userOp.preVerificationGas)
            .mul(2),
    });
    await tx.wait();
    dbUserOp.txHash = tx.hash;
    dbUserOp.status = 'submitted';
    await dbUserOp.save();
    return tx.hash;
} catch (error) {
    dbUserOp.status = 'failed';
    await dbUserOp.save();
    logger.error('UserOp submission error:', error);
    throw error;
}

}
// AI Symptom Analysis
async function analyzeSymptoms(symptoms) {
    try {
        const tensor = tf.tensor([symptoms.split(' ').length]);
        const prediction = tensor.add(0.5);
        return { diagnosis: "Possible condition based on: " + symptoms, confidence: prediction.dataSync()[0] };
    } catch (error) {
        logger.error('Symptom analysis error:', error);
        throw error;
    }
}
// OnRamp/OffRamp Providers
async function initiateYellowCardOnRamp(fiatAmount, targetToken, userAddress) {
    try {
        const response = await axios.post('https://api.yellowcard.io/v1/onramp', {
            amount: fiatAmount,
            currency: 'USD',
            destination: targetToken === 0 ? 'ETH' : targetToken === 1 ? 'USDC' : 'SONIC',
            walletAddress: userAddress,
            apiKey: process.env.YELLOWCARD_API_KEY,
        });
        return response.data.transactionId;
    } catch (error) {
        logger.error('Yellow Card on-ramp error:', error);
        throw new Error('Yellow Card on-ramp initiation failed');
    }
}
async function initiateMoonPayOnRamp(fiatAmount, targetToken, userAddress) {
    try {
        const response = await axios.get('https://api.moonpay.com/v3/buy/quote', {
            params: {
                apiKey: process.env.MOONPAY_API_KEY,
                currencyCode: targetToken === 0 ? 'eth' : targetToken === 1 ? 'usdc' : 'sonic',
                baseCurrencyCode: 'usd',
                baseCurrencyAmount: fiatAmount,
                walletAddress: userAddress,
            },
        });
        return response.data.transactionId;
    } catch (error) {
        logger.error('MoonPay on-ramp error:', error);
        throw new Error('MoonPay on-ramp initiation failed');
    }
}
async function initiateYellowCardOffRamp(cryptoAmount, sourceToken, bankDetails, userAddress) {
    try {
        const response = await axios.post('https://api.yellowcard.io/v1/offramp', {
            amount: cryptoAmount,
            currency: sourceToken === 0 ? 'ETH' : sourceToken === 1 ? 'USDC' : 'SONIC',
            bankDetails,
            walletAddress: userAddress,
            apiKey: process.env.YELLOWCARD_API_KEY,
        });
        return response.data.transactionId;
    } catch (error) {
        logger.error('Yellow Card off-ramp error:', error);
        throw new Error('Yellow Card off-ramp initiation failed');
    }
}
async function initiateMoonPayOffRamp(cryptoAmount, sourceToken, bankDetails, userAddress) {
    try {
        const response = await axios.post('https://api.moonpay.com/v3/sell/quote', {
            apiKey: process.env.MOONPAY_API_KEY,
            currencyCode: sourceToken === 0 ? 'eth' : sourceToken === 1 ? 'usdc' : 'sonic',
            baseCurrencyAmount: cryptoAmount,
            bankDetails,
            walletAddress: userAddress,
        });
        return response.data.transactionId;
    } catch (error) {
        logger.error('MoonPay off-ramp error:', error);
        throw new Error('MoonPay off-ramp initiation failed');
    }
}
// Authentication Routes
/**
@swagger

/login:

post:

summary: User login

tags: [Auth]

requestBody:

  required: true

  content:

    application/json:

      schema:

        type: object

        properties:

          address: { type: string }

          signature: { type: string }

          message: { type: string }

responses:

  200: { description: Successful login }

  401: { description: Invalid signature }

 */
app.post('/login', validate([
    body('address').isEthereumAddress(),
    body('signature').notEmpty(),
    body('message').notEmpty()
]), async (req, res) => {
    const { address, signature, message } = req.body;
    try {
        const recoveredAddress = ethers.utils.verifyMessage(message, signature);
        if (recoveredAddress.toLowerCase() !== address.toLowerCase()) {
            return res.status(401).json({ error: 'Invalid signature' });
        }
        let user = await User.findOne({ address });
        if (!user) {
            user = new User({ address });
            await user.save();
        }
        const token = jwt.sign({ address, role: user.role }, process.env.JWT_SECRET || 'your-secret-key', { expiresIn: '1h' });
        res.json({ token, role: user.role });
    } catch (error) {
        logger.error('Login error:', error);
        throw error;
    }
});
/**
@swagger

/register:

post:

summary: Register new user

tags: [Auth]

requestBody:

  required: true

  content:

    application/json:

      schema:

        type: object

        properties:

          address: { type: string }

          role: { type: string, enum: ['patient', 'doctor', 'labTech', 'pharmacy', 'admin'] }

          signature: { type: string }

          message: { type: string }

responses:

  200: { description: Successful registration }

  400: { description: User already exists }

 */
app.post('/register', validate([
    body('address').isEthereumAddress(),
    body('role').isIn(['patient', 'doctor', 'labTech', 'pharmacy', 'admin']),
    body('signature').notEmpty(),
    body('message').notEmpty()
]), async (req, res) => {
    const { address, role, signature, message } = req.body;
    try {
        const recoveredAddress = ethers.utils.verifyMessage(message, signature);
        if (recoveredAddress.toLowerCase() !== address.toLowerCase()) {
            return res.status(401).json({ error: 'Invalid signature' });
        }
        let user = await User.findOne({ address });
        if (user) {
            return res.status(400).json({ error: 'User already exists' });
        }
        user = new User({ address, role });
        await user.save();
        const token = jwt.sign({ address, role }, process.env.JWT_SECRET || 'your-secret-key', { expiresIn: '1h' });

    if (role === 'patient') {
        const callData = coreContract.interface.encodeFunctionData('registerPatient', ['encryptedSymmetricKey']);
        const salt = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(address + Date.now().toString()));
        const accountAddr = await accountFactoryContract.getAddress(address, salt);
        const userOp = await createUserOperation(accountAddr, callData);
        await submitUserOperation(userOp);
    }

    res.json({ token, role });
} catch (error) {
    logger.error('Register error:', error);
    throw error;
}

});
app.post('/validate-token', authMiddleware, async (req, res) => {
    try {
        const user = await User.findOne({ address: req.user.address });
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json({ address: user.address, role: user.role });
    } catch (error) {
        logger.error('Token validation error:', error);
        throw error;
    }
});
// Protected Routes
app.post('/register-patient', authMiddleware, validate([
    body('encryptedSymmetricKey').notEmpty()
]), async (req, res) => {
    try {
        const callData = coreContract.interface.encodeFunctionData('registerPatient', [req.body.encryptedSymmetricKey]);
        const salt = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(req.user.address + Date.now().toString()));
        const accountAddr = await accountFactoryContract.getAddress(req.user.address, salt);
        const userOp = await createUserOperation(accountAddr, callData);
        const txHash = await submitUserOperation(userOp);
        res.json({ txHash });
    } catch (error) {
        logger.error('Patient registration error:', error);
        throw error;
    }
});
app.post('/verify-doctor', authMiddleware, validate([
    body('doctorAddress').isEthereumAddress(),
    body('licenseNumber').notEmpty(),
    body('fee').isNumeric()
]), async (req, res) => {
    const { doctorAddress, licenseNumber, fee } = req.body;
    try {
        const callData = coreContract.interface.encodeFunctionData('verifyDoctor', [doctorAddress, licenseNumber, ethers.utils.parseEther(fee)]);
        const userOp = await createUserOperation(req.user.address, callData);
        const txHash = await submitUserOperation(userOp);
        await User.findOneAndUpdate({ address: doctorAddress }, { role: 'doctor' }, { upsert: true });
        res.json({ txHash });
    } catch (error) {
        logger.error('Doctor verification error:', error);
        throw error;
    }
});
app.post('/verify-lab-technician', authMiddleware, validate([
    body('labTechAddress').isEthereumAddress(),
    body('licenseNumber').notEmpty()
]), async (req, res) => {
    const { labTechAddress, licenseNumber } = req.body;
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
        const callData = coreContract.interface.encodeFunctionData('verifyLabTechnician', [labTechAddress, licenseNumber]);
        const userOp = await createUserOperation(req.user.address, callData);
        const txHash = await submitUserOperation(userOp);
        await User.findOneAndUpdate({ address: labTechAddress }, { role: 'labTech' }, { upsert: true });
        res.json({ txHash });
    } catch (error) {
        logger.error('Lab technician verification error:', error);
        throw error;
    }
});
app.post('/register-pharmacy', authMiddleware, validate([
    body('pharmacyAddress').isEthereumAddress(),
    body('registrationNumber').notEmpty()
]), async (req, res) => {
    const { pharmacyAddress, registrationNumber } = req.body;
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
        const callData = coreContract.interface.encodeFunctionData('registerPharmacy', [pharmacyAddress, registrationNumber]);
        const userOp = await createUserOperation(req.user.address, callData);
        const txHash = await submitUserOperation(userOp);
        await User.findOneAndUpdate({ address: pharmacyAddress }, { role: 'pharmacy' }, { upsert: true });
        res.json({ txHash });
    } catch (error) {
        logger.error('Pharmacy registration error:', error);
        throw error;
    }
});
/**
@swagger

/book-appointment:

post:

summary: Book an appointment

tags: [Medical]

security:

  - bearerAuth: []

requestBody:

  required: true

  content:

    application/json:

      schema:

        type: object

        properties:

          doctorAddress: { type: string }

          timestamp: { type: integer }

          paymentType: { type: integer, enum: [0, 1, 2] }

          isVideoCall: { type: boolean }

          videoCallLink: { type: string }

responses:

  200: { description: Appointment booked }

  401: { description: Unauthorized }

 */
app.post('/book-appointment', authMiddleware, validate([
    body('doctorAddress').isEthereumAddress(),
    body('timestamp').isInt({ min: Math.floor(Date.now() / 1000) }),
    body('paymentType').isInt({ min: 0, max: 2 }),
    body('isVideoCall').isBoolean(),
    body('videoCallLink').optional().isURL()
]), async (req, res) => {
    const { doctorAddress, timestamp, paymentType, isVideoCall, videoCallLink } = req.body;
    try {
        const callData = medicalContract.interface.encodeFunctionData('bookAppointment', [
            doctorAddress,
            timestamp,
            paymentType,
            isVideoCall,
            videoCallLink || '',
        ]);
        const userOp = await createUserOperation(req.user.address, callData, {
            callGasLimit: 250000,
            value: paymentType === 0 ? ethers.utils.parseEther(req.body.amount || '0') : 0,
            sponsorType: paymentType,
        });
        const txHash = await submitUserOperation(userOp);
        wss.clients.forEach(client => client.send(JSON.stringify({ type: 'appointment', id: txHash })));
        res.json({ txHash });
    } catch (error) {
        logger.error('Booking error:', error);
        throw error;
    }
});
app.post('/confirm-appointment', authMiddleware, validate([
    body('appointmentId').isInt({ min: 1 }),
    body('overridePriority').optional().isBoolean()
]), async (req, res) => {
    const { appointmentId, overridePriority } = req.body;
    try {
        const callData = medicalContract.interface.encodeFunctionData('confirmAppointment', [appointmentId, overridePriority || false]);
        const userOp = await createUserOperation(req.user.address, callData);
        const txHash = await submitUserOperation(userOp);
        wss.clients.forEach(client => client.send(JSON.stringify({ type: 'appointmentConfirmed', id: appointmentId })));
        res.json({ txHash });
    } catch (error) {
        logger.error('Confirmation error:', error);
        throw error;
    }
});
app.post('/batch-confirm-appointments', authMiddleware, validate([
    body('appointmentIds').isArray().notEmpty()
]), async (req, res) => {
    const { appointmentIds } = req.body;
    try {
        const callData = medicalContract.interface.encodeFunctionData('batchConfirmAppointments', [appointmentIds]);
        const userOp = await createUserOperation(req.user.address, callData);
        const txHash = await submitUserOperation(userOp);
        wss.clients.forEach(client => client.send(JSON.stringify({ type: 'batchAppointmentsConfirmed', ids: appointmentIds })));
        res.json({ txHash });
    } catch (error) {
        logger.error('Batch confirmation error:', error);
        throw error;
    }
});
app.post('/complete-appointment', authMiddleware, validate([
    body('appointmentId').isInt({ min: 1 }),
    body('ipfsSummary').notEmpty()
]), async (req, res) => {
    const { appointmentId, ipfsSummary } = req.body;
    try {
        const callData = medicalContract.interface.encodeFunctionData('completeAppointment', [appointmentId, ipfsSummary]);
        const userOp = await createUserOperation(req.user.address, callData);
        const txHash = await submitUserOperation(userOp);
        wss.clients.forEach(client => client.send(JSON.stringify({ type: 'appointmentCompleted', id: appointmentId })));
        res.json({ txHash });
    } catch (error) {
        logger.error('Completion error:', error);
        throw error;
    }
});
app.post('/cancel-appointment', authMiddleware, validate([
    body('appointmentId').isInt({ min: 1 })
]), async (req, res) => {
    const { appointmentId } = req.body;
    try {
        const callData = medicalContract.interface.encodeFunctionData('cancelAppointment', [appointmentId]);
        const userOp = await createUserOperation(req.user.address, callData, { callGasLimit: 200000 });
        const txHash = await submitUserOperation(userOp);
        wss.clients.forEach(client => client.send(JSON.stringify({ type: 'appointmentCancelled', id: appointmentId })));
        res.json({ txHash });
    } catch (error) {
        logger.error('Cancellation error:', error);
        throw error;
    }
});
app.post('/reschedule-appointment', authMiddleware, validate([
    body('appointmentId').isInt({ min: 1 }),
    body('newTimestamp').isInt({ min: Math.floor(Date.now() / 1000) })
]), async (req, res) => {
    const { appointmentId, newTimestamp } = req.body;
    try {
        const callData = medicalContract.interface.encodeFunctionData('rescheduleAppointment', [appointmentId, newTimestamp]);
        const userOp = await createUserOperation(req.user.address, callData);
        const txHash = await submitUserOperation(userOp);
        wss.clients.forEach(client => client.send(JSON.stringify({ type: 'appointmentRescheduled', id: appointmentId, newTimestamp })));
        res.json({ txHash });
    } catch (error) {
        logger.error('Reschedule error:', error);
        throw error;
    }
});
app.post('/analyze-symptoms', authMiddleware, validate([
    body('symptoms').notEmpty()
]), async (req, res) => {
    const { symptoms } = req.body;
    try {
        const analysis = await analyzeSymptoms(symptoms);
        const ipfsResult = await ipfs.add(JSON.stringify(analysis));
        const callData = medicalContract.interface.encodeFunctionData('requestAISymptomAnalysis', [symptoms]);
        const userOp = await createUserOperation(req.user.address, callData);
        const txHash = await submitUserOperation(userOp);
        res.json({ txHash, ipfsHash: ipfsResult.path });
    } catch (error) {
        logger.error('Symptom analysis error:', error);
        throw error;
    }
});
app.post('/review-ai-analysis', authMiddleware, validate([
    body('aiAnalysisId').isInt({ min: 1 }),
    body('analysisIpfsHash').notEmpty()
]), async (req, res) => {
    const { aiAnalysisId, analysisIpfsHash } = req.body;
    try {
        const callData = medicalContract.interface.encodeFunctionData('reviewAISymptomAnalysis', [aiAnalysisId, analysisIpfsHash]);
        const userOp = await createUserOperation(req.user.address, callData);
        const txHash = await submitUserOperation(userOp);
        res.json({ txHash });
    } catch (error) {
        logger.error('AI review error:', error);
        throw error;
    }
});
app.post('/order-lab-test', authMiddleware, validate([
    body('patientAddress').isEthereumAddress(),
    body('testType').notEmpty()
]), async (req, res) => {
    const { patientAddress, testType } = req.body;
    try {
        const callData = medicalContract.interface.encodeFunctionData('orderLabTest', [patientAddress, testType]);
        const userOp = await createUserOperation(req.user.address, callData);
        const txHash = await submitUserOperation(userOp);
        res.json({ txHash });
    } catch (error) {
        logger.error('Lab test order error:', error);
        throw error;
    }
});
app.post('/collect-sample', authMiddleware, validate([
    body('labTestId').isInt({ min: 1 }),
    body('sampleIpfsHash').notEmpty()
]), async (req, res) => {
    const { labTestId, sampleIpfsHash } = req.body;
    try {
        const callData = medicalContract.interface.encodeFunctionData('collectSample', [labTestId, sampleIpfsHash]);
        const userOp = await createUserOperation(req.user.address, callData);
        const txHash = await submitUserOperation(userOp);
        res.json({ txHash });
    } catch (error) {
        logger.error('Sample collection error:', error);
        throw error;
    }
});
app.post('/upload-lab-results', authMiddleware, validate([
    body('labTestId').isInt({ min: 1 }),
    body('resultsIpfsHash').notEmpty()
]), async (req, res) => {
    const { labTestId, resultsIpfsHash } = req.body;
    try {
        const callData = medicalContract.interface.encodeFunctionData('uploadLabResults', [labTestId, resultsIpfsHash]);
        const userOp = await createUserOperation(req.user.address, callData);
        const txHash = await submitUserOperation(userOp);
        res.json({ txHash });
    } catch (error) {
        logger.error('Results upload error:', error);
        throw error;
    }
});
app.post('/review-lab-results', authMiddleware, validate([
    body('labTestId').isInt({ min: 1 }),
    body('medicationDetails').notEmpty(),
    body('prescriptionIpfsHash').notEmpty()
]), async (req, res) => {
    const { labTestId, medicationDetails, prescriptionIpfsHash } = req.body;
    try {
        const callData = medicalContract.interface.encodeFunctionData('reviewLabResults', [labTestId, medicationDetails, prescriptionIpfsHash]);
        const userOp = await createUserOperation(req.user.address, callData);
        const txHash = await submitUserOperation(userOp);
        res.json({ txHash });
    } catch (error) {
        logger.error('Lab results review error:', error);
        throw error;
    }
});
app.post('/verify-prescription', authMiddleware, validate([
    body('prescriptionId').isInt({ min: 1 }),
    body('verificationCodeHash').notEmpty()
]), async (req, res) => {
    const { prescriptionId, verificationCodeHash } = req.body;
    try {
        const callData = medicalContract.interface.encodeFunctionData('verifyPrescription', [prescriptionId, ethers.utils.hexlify(verificationCodeHash)]);
        const userOp = await createUserOperation(req.user.address, callData);
        const txHash = await submitUserOperation(userOp);
        res.json({ txHash });
    } catch (error) {
        logger.error('Prescription verification error:', error);
        throw error;
    }
});
app.post('/fulfill-prescription', authMiddleware, validate([
    body('prescriptionId').isInt({ min: 1 })
]), async (req, res) => {
    const { prescriptionId } = req.body;
    try {
        const callData = medicalContract.interface.encodeFunctionData('fulfillPrescription', [prescriptionId]);
        const userOp = await createUserOperation(req.user.address, callData);
        const txHash = await submitUserOperation(userOp);
        res.json({ txHash });
    } catch (error) {
        logger.error('Prescription fulfillment error:', error);
        throw error;
    }
});
app.post('/toggle-data-monetization', authMiddleware, validate([
    body('enable').isBoolean()
]), async (req, res) => {
    const { enable } = req.body;
    try {
        const callData = coreContract.interface.encodeFunctionData('toggleDataMonetization', [enable]);
        const userOp = await createUserOperation(req.user.address, callData);
        const txHash = await submitUserOperation(userOp);
        res.json({ txHash });
    } catch (error) {
        logger.error('Data monetization toggle error:', error);
        throw error;
    }
});
app.post('/claim-data-reward', authMiddleware, async (req, res) => {
    try {
        const callData = coreContract.interface.encodeFunctionData('claimDataReward');
        const userOp = await createUserOperation(req.user.address, callData);
        const txHash = await submitUserOperation(userOp);
        res.json({ txHash });
    } catch (error) {
        logger.error('Reward claim error:', error);
        throw error;
    }
});
app.post('/deposit-ai-fund', authMiddleware, validate([
    body('amount').isNumeric({ min: 0 })
]), async (req, res) => {
    const { amount } = req.body;
    try {
        const callData = paymentsContract.interface.encodeFunctionData('deposit', [coreContract.address, ethers.utils.parseEther(amount)]);
        const userOp = await createUserOperation(req.user.address, callData, {
            callGasLimit: 150000,
            value: ethers.utils.parseEther(amount),
        });
        const txHash = await submitUserOperation(userOp);
        res.json({ txHash });
    } catch (error) {
        logger.error('AI fund deposit error:', error);
        throw error;
    }
});
app.post('/deposit-reserve-fund', authMiddleware, validate([
    body('amount').isNumeric({ min: 0 })
]), async (req, res) => {
    const { amount } = req.body;
    try {
        const callData = paymentsContract.interface.encodeFunctionData('deposit', [coreContract.address, ethers.utils.parseEther(amount)]);
        const userOp = await createUserOperation(req.user.address, callData, {
            callGasLimit: 150000,
            value: ethers.utils.parseEther(amount),
        });
        const txHash = await submitUserOperation(userOp);
        res.json({ txHash });
    } catch (error) {
        logger.error('Reserve fund deposit error:', error);
        throw error;
    }
});
app.post('/paymaster-deposit', authMiddleware, validate([
    body('amount').isNumeric({ min: 0 }),
    body('sponsorType').isInt({ min: 0, max: 2 })
]), async (req, res) => {
    const { amount, sponsorType } = req.body;
    try {
        const callData = paymasterContract.interface.encodeFunctionData('deposit', [sponsorType, ethers.utils.parseEther(amount)]);
        const userOp = await createUserOperation(req.user.address, callData, {
            value: sponsorType === 0 ? ethers.utils.parseEther(amount) : 0,
        });
        const txHash = await submitUserOperation(userOp);
        res.json({ txHash });
    } catch (error) {
        logger.error('Paymaster deposit error:', error);
        throw error;
    }
});
app.post('/subscribe', authMiddleware, validate([
    body('plan').isInt({ min: 0, max: 1 })
]), async (req, res) => {
    const { plan } = req.body;
    try {
        const callData = subscriptionContract.interface.encodeFunctionData('subscribe', [plan]);
        const userOp = await createUserOperation(req.user.address, callData, {
            value: ethers.utils.parseEther(plan === 0 ? '0.01' : '0.05'),
        });
        const txHash = await submitUserOperation(userOp);
        res.json({ txHash });
    } catch (error) {
        logger.error('Subscription error:', error);
        throw error;
    }
});
app.post('/queue-withdraw-funds', authMiddleware, validate([
    body('to').isEthereumAddress(),
    body('amount').isNumeric({ min: 0 })
]), async (req, res) => {
    const { to, amount } = req.body;
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
        const callData = governanceContract.interface.encodeFunctionData('queueWithdrawFunds', [to, ethers.utils.parseEther(amount)]);
        const userOp = await createUserOperation(req.user.address, callData);
        const txHash = await submitUserOperation(userOp);

    const timeLockId = (await TimeLock.countDocuments()) + 1;
    await TimeLock.create({
        id: timeLockId,
        action: 0,
        target: to,
        value: ethers.utils.parseEther(amount).toString(),
        data: callData,
        timestamp: Math.floor(Date.now() / 1000),
        approvals: [req.user.address],
    });

    res.json({ txHash, timeLockId });
} catch (error) {
    logger.error('Withdraw funds queue error:', error);
    throw error;
}

});
app.post('/queue-add-admin', authMiddleware, validate([
    body('newAdmin').isEthereumAddress()
]), async (req, res) => {
    const { newAdmin } = req.body;
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
        const callData = governanceContract.interface.encodeFunctionData('queueAddAdmin', [newAdmin]);
        const userOp = await createUserOperation(req.user.address, callData);
        const txHash = await submitUserOperation(userOp);

    const timeLockId = (await TimeLock.countDocuments()) + 1;
    await TimeLock.create({
        id: timeLockId,
        action: 1,
        target: newAdmin,
        value: '0',
        data: callData,
        timestamp: Math.floor(Date.now() / 1000),
        approvals: [req.user.address],
    });

    res.json({ txHash, timeLockId });
} catch (error) {
    logger.error('Add admin queue error:', error);
    throw error;
}

});
app.post('/approve-timelock', authMiddleware, validate([
    body('timeLockId').isInt({ min: 1 })
]), async (req, res) => {
    const { timeLockId } = req.body;
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
        const callData = governanceContract.interface.encodeFunctionData('approveTimeLock', [timeLockId]);
        const userOp = await createUserOperation(req.user.address, callData);
        const txHash = await submitUserOperation(userOp);

    const timeLock = await TimeLock.findOne({ id: timeLockId });
    if (!timeLock.approvals.includes(req.user.address)) {
        timeLock.approvals.push(req.user.address);
        timeLock.approvalCount += 1;
        await timeLock.save();
    }

    res.json({ txHash });
} catch (error) {
    logger.error('Time-lock approval error:', error);
    throw error;
}

});
app.post('/execute-timelock', authMiddleware, validate([
    body('timeLockId').isInt({ min: 1 })
]), async (req, res) => {
    const { timeLockId } = req.body;
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
        const callData = governanceContract.interface.encodeFunctionData('executeTimeLock', [timeLockId]);
        const userOp = await createUserOperation(req.user.address, callData);
        const txHash = await submitUserOperation(userOp);

    const timeLock = await TimeLock.findOne({ id: timeLockId });
    timeLock.executed = true;
    await timeLock.save();

    res.json({ txHash });
} catch (error) {
    logger.error('Time-lock execution error:', error);
    throw error;
}

});
app.post('/emergency-pause', authMiddleware, async (req, res) => {
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
        const callData = emergencyContract.interface.encodeFunctionData('emergencyPause');
        const userOp = await createUserOperation(req.user.address, callData);
        const txHash = await submitUserOperation(userOp);
        res.json({ txHash });
    } catch (error) {
        logger.error('Emergency pause error:', error);
        throw error;
    }
});
app.post('/request-emergency-unpause', authMiddleware, async (req, res) => {
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
        const callData = emergencyContract.interface.encodeFunctionData('requestEmergencyUnpause');
        const userOp = await createUserOperation(req.user.address, callData);
        const txHash = await submitUserOperation(userOp);
        res.json({ txHash });
    } catch (error) {
        logger.error('Emergency unpause request error:', error);
        throw error;
    }
});
app.post('/request-onramp', authMiddleware, validate([
    body('fiatAmount').isNumeric({ min: 0 }),
    body('targetToken').isInt({ min: 0, max: 2 }),
    body('provider').isIn(['yellowcard', 'moonpay'])
]), async (req, res) => {
    const { fiatAmount, targetToken, provider } = req.body;
    try {
        let providerReference;
        if (provider === 'yellowcard') {
            providerReference = await initiateYellowCardOnRamp(fiatAmount, targetToken, req.user.address);
        } else if (provider === 'moonpay') {
            providerReference = await initiateMoonPayOnRamp(fiatAmount, targetToken, req.user.address);
        } else {
            throw new Error('Unsupported provider');
        }

    const callData = paymentsContract.interface.encodeFunctionData('deposit', [
        coreContract.address,
        ethers.utils.parseEther(fiatAmount.toString())
    ]);
    const userOp = await createUserOperation(req.user.address, callData, {
        value: ethers.utils.parseEther('0.001'),
    });
    const txHash = await submitUserOperation(userOp);
    res.json({ txHash, providerReference });
} catch (error) {
    logger.error('OnRamp request error:', error);
    throw error;
}

});
app.post('/request-offramp', authMiddleware, validate([
    body('sourceToken').isInt({ min: 0, max: 2 }),
    body('cryptoAmount').isNumeric({ min: 0 }),
    body('bankDetails').notEmpty(),
    body('provider').isIn(['yellowcard', 'moonpay'])
]), async (req, res) => {
    const { sourceToken, cryptoAmount, bankDetails, provider } = req.body;
    try {
        let providerReference;
        if (provider === 'yellowcard') {
            providerReference = await initiateYellowCardOffRamp(cryptoAmount, sourceToken, bankDetails, req.user.address);
        } else if (provider === 'moonpay') {
            providerReference = await initiateMoonPayOffRamp(cryptoAmount, sourceToken, bankDetails, req.user.address);
        } else {
            throw new Error('Unsupported provider');
        }

    const callData = paymentsContract.interface.encodeFunctionData('deposit', [
        coreContract.address,
        ethers.utils.parseEther(cryptoAmount.toString())
    ]);
    const userOp = await createUserOperation(req.user.address, callData, {
        value: sourceToken === 0 ? ethers.utils.parseEther(cryptoAmount.toString()).add(ethers.utils.parseEther('0.002')) : ethers.utils.parseEther('0.002'),
    });
    const txHash = await submitUserOperation(userOp);
    res.json({ txHash, providerReference });
} catch (error) {
    logger.error('OffRamp request error:', error);
    throw error;
}

});
app.post('/raise-dispute', authMiddleware, validate([
    body('relatedId').isInt({ min: 1 }),
    body('reason').notEmpty()
]), async (req, res) => {
    const { relatedId, reason } = req.body;
    try {
        const callData = governanceContract.interface.encodeFunctionData('queueWithdrawFunds', [req.user.address, 0]);
        const userOp = await createUserOperation(req.user.address, callData);
        const txHash = await submitUserOperation(userOp);

    const disputeId = (await Dispute.countDocuments()) + 1;
    await Dispute.create({
        id: disputeId,
        initiator: req.user.address,
        relatedId,
        status: 0,
        reason,
    });

    res.json({ txHash, disputeId });
} catch (error) {
    logger.error('Dispute raise error:', error);
    throw error;
}

});
// View Routes
app.get('/paymaster-status', authMiddleware, async (req, res) => {
    try {
        const cacheKey = 'paymaster_status';
        const cached = cache.get(cacheKey);
        if (cached) return res.json(cached);

    const ethBalance = await paymasterContract.getBalance(0);
    const usdcBalance = await paymasterContract.getBalance(1);
    const sonicBalance = await paymasterContract.getBalance(2);
    const result = {
        ethBalance: ethers.utils.formatEther(ethBalance),
        usdcBalance: ethers.utils.formatUnits(usdcBalance, 6),
        sonicBalance: ethers.utils.formatUnits(sonicBalance, 18),
    };
    cache.set(cacheKey, result);
    res.json(result);
} catch (error) {
    logger.error('Paymaster status error:', error);
    throw error;
}

});
app.get('/ai-fund-balance', authMiddleware, async (req, res) => {
    try {
        const cacheKey = 'ai_fund_balance';
        const cached = cache.get(cacheKey);
        if (cached) return res.json(cached);

    const balance = await coreContract.aiAnalysisFund();
    const result = { balance: ethers.utils.formatEther(balance) };
    cache.set(cacheKey, result);
    res.json(result);
} catch (error) {
    logger.error('AI fund balance error:', error);
    throw error;
}

});
app.get('/reserve-fund-balance', authMiddleware, async (req, res) => {
    try {
        const cacheKey = 'reserve_fund_balance';
        const cached = cache.get(cacheKey);
        if (cached) return res.json(cached);

    const balance = await coreContract.reserveFund();
    const result = { balance: ethers.utils.formatEther(balance) };
    cache.set(cacheKey, result);
    res.json(result);
} catch (error) {
    logger.error('Reserve fund balance error:', error);
    throw error;
}

});
app.get('/check-role/:role/:address', authMiddleware, validate([
    param('role').isIn(['patient', 'doctor', 'labTech', 'pharmacy', 'admin']),
    param('address').isEthereumAddress()
]), async (req, res) => {
    try {
        const cacheKey = role_${req.params.role}_${req.params.address};
        const cached = cache.get(cacheKey);
        if (cached) return res.json(cached);

    const role = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(req.params.role.toUpperCase() + '_ROLE'));
    const hasRole = await coreContract.hasRole(role, req.params.address);
    const result = { hasRole };
    cache.set(cacheKey, result);
    res.json(result);
} catch (error) {
    logger.error('Role check error:', error);
    throw error;
}

});
app.get('/timelocks', authMiddleware, async (req, res) => {
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
        const cacheKey = 'timelocks';
        const cached = cache.get(cacheKey);
        if (cached) return res.json(cached);

    const timeLocks = await TimeLock.find({ executed: false, cancelled: false });
    const result = { timeLocks };
    cache.set(cacheKey, result);
    res.json(result);
} catch (error) {
    logger.error('Time-locks fetch error:', error);
    throw error;
}

});
app.get('/disputes', authMiddleware, async (req, res) => {
    try {
        const cacheKey = 'disputes';
        const cached = cache.get(cacheKey);
        if (cached) return res.json(cached);

    const disputes = await Dispute.find({ status: 0 });
    const result = { disputes };
    cache.set(cacheKey, result);
    res.json(result);
} catch (error) {
    logger.error('Disputes fetch error:', error);
    throw error;
}

});
app.get('/userop-status/:txHash', authMiddleware, validate([
    param('txHash').isHash('sha256')
]), async (req, res) => {
    try {
        const userOp = await UserOp.findOne({ txHash: req.params.txHash });
        if (!userOp) return res.status(404).json({ error: 'UserOp not found' });
        res.json({ status: userOp.status, userOp });
    } catch (error) {
        logger.error('UserOp status error:', error);
        throw error;
    }
});
app.get('/generate-qr/:prescriptionId', authMiddleware, validate([
    param('prescriptionId').isInt({ min: 1 })
]), async (req, res) => {
    try {
        const prescription = await medicalContract.prescriptions(req.params.prescriptionId);
        const qrData = JSON.stringify({
            id: prescription.id.toString(),
            verificationCodeHash: ethers.utils.hexlify(prescription.verificationCodeHash),
        });
        const qrCode = await QRCode.toDataURL(qrData);
        res.json({ qrCode });
    } catch (error) {
        logger.error('QR generation error:', error);
        throw error;
    }
});
app.get('/appointments/:id', authMiddleware, validate([
    param('id').isInt({ min: 1 })
]), async (req, res) => {
    try {
        const cacheKey = appointment_${req.params.id};
        const cached = cache.get(cacheKey);
        if (cached) return res.json(cached);

    const appointment = await medicalContract.appointments(req.params.id);
    const result = { appointment };
    cache.set(cacheKey, result);
    res.json(result);
} catch (error) {
    logger.error('Appointment fetch error:', error);
    throw error;
}

});
app.get('/lab-test/:id', authMiddleware, validate([
    param('id').isInt({ min: 1 })
]), async (req, res) => {
    try {
        const cacheKey = labtest_${req.params.id};
        const cached = cache.get(cacheKey);
        if (cached) return res.json(cached);

    const labTest = await medicalContract.labTestOrders(req.params.id);
    const result = { labTest };
    cache.set(cacheKey, result);
    res.json(result);
} catch (error) {
    logger.error('Lab test fetch error:', error);
    throw error;
}

});
app.get('/prescription/:id', authMiddleware, validate([
    param('id').isInt({ min: 1 })
]), async (req, res) => {
    try {
        const cacheKey = prescription_${req.params.id};
        const cached = cache.get(cacheKey);
        if (cached) return res.json(cached);

    const prescription = await medicalContract.prescriptions(req.params.id);
    const result = { prescription };
    cache.set(cacheKey, result);
    res.json(result);
} catch (error) {
    logger.error('Prescription fetch error:', error);
    throw error;
}

});
app.get('/ai-analysis/:id', authMiddleware, validate([
    param('id').isInt({ min: 1 })
]), async (req, res) => {
    try {
        const cacheKey = aianalysis_${req.params.id};
        const cached = cache.get(cacheKey);
        if (cached) return res.json(cached);

    const analysis = await medicalContract.aiAnalyses(req.params.id);
    const result = { analysis };
    cache.set(cacheKey, result);
    res.json(result);
} catch (error) {
    logger.error('AI analysis fetch error:', error);
    throw error;
}

});
/**
@swagger

/patient-level/{address}:

get:

summary: Get patient level

tags: [Patient]

security:

  - bearerAuth: []

parameters:

  - in: path

    name: address

    required: true

    schema:

      type: string

responses:

  200: { description: Patient level }

  401: { description: Unauthorized }

 */
app.get('/patient-level/:address', authMiddleware, validate([
    param('address').isEthereumAddress()
]), async (req, res) => {
    try {
        const cacheKey = patient_level_${req.params.address};
        const cached = cache.get(cacheKey);
        if (cached) return res.json(cached);

    const level = await coreContract.getPatientLevel(req.params.address);
    const result = { level: level.toString() };
    cache.set(cacheKey, result);
    res.json(result);
} catch (error) {
    logger.error('Patient level fetch error:', error);
    throw error;
}

});
app.get('/patient-points/:address', authMiddleware, validate([
    param('address').isEthereumAddress()
]), async (req, res) => {
    try {
        const cacheKey = patient_points_${req.params.address};
        const cached = cache.get(cacheKey);
        if (cached) return res.json(cached);

    const points = await coreContract.getPatientPoints(req.params.address);
    const result = { points: points.toString() };
    cache.set(cacheKey, result);
    res.json(result);
} catch (error) {
    logger.error('Patient points fetch error:', error);
    throw error;
}

});
app.get('/subscription-status/:address', authMiddleware, validate([
    param('address').isEthereumAddress()
]), async (req, res) => {
    try {
        const cacheKey = subscription_${req.params.address};
        const cached = cache.get(cacheKey);
        if (cached) return res.json(cached);

    const [isActive, expiry, consultsUsed] = await subscriptionContract.getSubscriptionStatus(req.params.address);
    const result = { isActive, expiry: expiry.toString(), consultsUsed: consultsUsed.toString() };
    cache.set(cacheKey, result);
    res.json(result);
} catch (error) {
    logger.error('Subscription status fetch error:', error);
    throw error;
}

});
// WebSocket Handling
wss.on('connection', (ws) => {
    logger.info('WebSocket client connected');
    ws.on('message', async (message) => {
        try {
            const data = JSON.parse(message);
            if (data.type === 'appointment') {
                const appointment = await medicalContract.appointments(data.id);
                ws.send(JSON.stringify({ type: 'appointmentUpdate', data: appointment }));
            }
        } catch (error) {
            logger.error('WebSocket error:', error);
        }
    });
});
// Error Handler (must be last middleware)
app.use(errorHandler);
// Start Server
server.listen(8080, () => logger.info('Server running on port 8080'));

