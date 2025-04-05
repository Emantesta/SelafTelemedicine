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
const axiosRetry = require('axios-retry');
const rateLimit = require('express-rate-limit');
const { body, param, validationResult } = require('express-validator');
const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');
const NodeCache = require('node-cache');
const { cleanEnv, str, url, num } = require('envalid');
const Queue = require('bull');

// Config Validation
const env = cleanEnv(process.env, {
    SSL_CERT_PATH: str({ default: './cert.pem' }),
    SSL_KEY_PATH: str({ default: './key.pem' }),
    SONIC_RPC_URL: url({ default: 'https://rpc.sonic.example.com' }),
    PRIVATE_KEY: str(),
    JWT_SECRET: str({ default: 'your-secret-key' }),
    CORE_ADDRESS: str(),
    PAYMENTS_ADDRESS: str(),
    MEDICAL_ADDRESS: str(),
    PAYMASTER_ADDRESS: str(),
    ACCOUNT_FACTORY_ADDRESS: str(),
    GOVERNANCE_ADDRESS: str(),
    EMERGENCY_ADDRESS: str(),
    SUBSCRIPTION_ADDRESS: str(),
    ENTRYPOINT_ADDRESS: str({ default: '0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789' }),
    FRONTEND_URL: url({ default: 'http://localhost:3000' }),
    MONGO_URI: url({ default: 'mongodb://localhost:27017/telemedicine' }),
    YELLOWCARD_API_KEY: str(),
    MOONPAY_API_KEY: str(),
    RATE_LIMIT_MAX: num({ default: 200 }),
    RATE_LIMIT_WINDOW_MS: num({ default: 10 * 60 * 1000 }), // 10 minutes
});

// Setup
const app = express();
const server = https.createServer({
    cert: fs.readFileSync(env.SSL_CERT_PATH),
    key: fs.readFileSync(env.SSL_KEY_PATH),
});
const wss = new WebSocket.Server({ server });
const ipfs = create({ host: 'ipfs.infura.io', port: 5001, protocol: 'https' });
const provider = new ethers.providers.JsonRpcProvider(env.SONIC_RPC_URL);
const wallet = new ethers.Wallet(env.PRIVATE_KEY, provider);
const cache = new NodeCache({ stdTTL: 300, checkperiod: 320 }); // 5-minute cache

// Rate Limiting
const limiter = rateLimit({
    windowMs: env.RATE_LIMIT_WINDOW_MS,
    max: env.RATE_LIMIT_MAX,
    message: 'Too many requests from this IP, please try again later.',
});

// Async Queue
const userOpQueue = new Queue('userOpQueue', {
    redis: { host: 'localhost', port: 6379 }, // Adjust Redis config as needed
});
const aiQueue = new Queue('aiQueue', {
    redis: { host: 'localhost', port: 6379 },
});

// Contract Instances
const coreContract = new ethers.Contract(env.CORE_ADDRESS, [
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
], wallet);

const paymentsContract = new ethers.Contract(env.PAYMENTS_ADDRESS, [
    'function usdcToken() view returns (address)',
    'function sonicToken() view returns (address)',
    'function deposit(address,uint256) external payable',
], wallet);

const medicalContract = new ethers.Contract(env.MEDICAL_ADDRESS, [
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
], wallet);

const paymasterContract = new ethers.Contract(env.PAYMASTER_ADDRESS, [
    'function deposit(uint8,uint256) external payable',
    'function validatePaymasterUserOp(tuple(address,uint256,bytes,bytes,uint256,uint256,uint256,uint256,uint256,bytes),bytes32,uint256) external returns (uint256,bytes)',
    'function getBalance(uint8) external view returns (uint256)',
], wallet);

const accountFactoryContract = new ethers.Contract(env.ACCOUNT_FACTORY_ADDRESS, [
    'function createAccount(address,uint256) external returns (address)',
    'function getAddress(address,uint256) external view returns (address)',
], wallet);

const governanceContract = new ethers.Contract(env.GOVERNANCE_ADDRESS, [
    'function queueWithdrawFunds(address,uint256) external',
    'function queueAddAdmin(address) external',
    'function queueRemoveAdmin(address) external',
    'function approveTimeLock(uint256) external',
    'function executeTimeLock(uint256) external',
    'function cancelTimeLock(uint256) external',
    'function timeLocks(uint256) view returns (tuple(uint256,uint8,address,uint256,bytes,uint256,address[],uint256,bool,bool))',
], wallet);

const emergencyContract = new ethers.Contract(env.EMERGENCY_ADDRESS, [
    'function emergencyPause() external',
    'function requestEmergencyUnpause() external',
    'function approveEmergencyUnpause(uint256) external',
    'function requestEmergencyFundWithdrawal(uint256) external',
    'function approveEmergencyFundWithdrawal(uint256,uint256) external',
], wallet);

const subscriptionContract = new ethers.Contract(env.SUBSCRIPTION_ADDRESS, [
    'function subscribe(uint8) external payable',
    'function getSubscriptionStatus(address) view returns (bool,uint256,uint256)',
], wallet);

const entryPoint = EntryPoint__factory.connect(env.ENTRYPOINT_ADDRESS, wallet);

app.use(cors({ origin: env.FRONTEND_URL }));
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
mongoose.connect(env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => logger.info('Connected to MongoDB'))
  .catch(err => logger.error('MongoDB connection error:', err));

// Schemas with Indexes
const UserSchema = new mongoose.Schema({
    address: { type: String, required: true, unique: true, index: true },
    role: { type: String, enum: ['patient', 'doctor', 'labTech', 'pharmacy', 'admin'], default: 'patient' },
    createdAt: { type: Date, default: Date.now },
});

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
    txHash: { type: String, index: true },
    status: { type: String, enum: ['pending', 'validated', 'submitted', 'failed'], default: 'pending' },
    createdAt: { type: Date, default: Date.now },
});

const TimeLockSchema = new mongoose.Schema({
    id: { type: Number, required: true, unique: true },
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

const DisputeSchema = new mongoose.Schema({
    id: { type: Number, required: true, unique: true },
    initiator: { type: String, required: true, index: true },
    relatedId: { type: Number, required: true },
    status: { type: Number, enum: [0, 1, 2], default: 0 },
    reason: { type: String, required: true },
    resolutionTimestamp: { type: Number, default: 0 },
});

const User = mongoose.model('User', UserSchema);
const UserOp = mongoose.model('UserOp', UserOpSchema);
const TimeLock = mongoose.model('TimeLock', TimeLockSchema);
const Dispute = mongoose.model('Dispute', DisputeSchema);

// Swagger Setup
const swaggerOptions = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'Telemedicine API',
            version: '1.0.0',
            description: 'API for blockchain-based telemedicine platform',
        },
        servers: [{ url: 'https://localhost:8080' }],
    },
    apis: ['backend.js'],
};
const swaggerSpec = swaggerJsdoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// Axios Retry Configuration
axiosRetry(axios, { retries: 3, retryDelay: axiosRetry.exponentialDelay });

// Error Handling Middleware
const errorHandler = (err, req, res, next) => {
    const status = err.status || 500;
    logger.error(`${req.method} ${req.url} - Error: ${err.message}`, { stack: err.stack });
    res.status(status).json({ error: err.message || 'Internal server error', details: err.details || null });
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
        if (!token) return res.status(401).json({ error: 'Authentication required', details: 'No token provided' });
        const decoded = jwt.verify(token, env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        logger.error('Auth error:', error);
        res.status(401).json({ error: 'Authentication failed', details: error.message });
    }
};

// User Operation Handling
async function createUserOperation(sender, callData, gasParams = {}) {
    try {
        const nonce = await coreContract.nonces(sender);
        const gasEstimate = await provider.estimateGas({
            to: gasParams.to || medicalContract.address,
            data: callData,
            value: gasParams.value || 0,
            from: sender,
        });

        const userOp = {
            sender,
            nonce: nonce.toNumber(),
            initCode: gasParams.initCode || '0x',
            callData,
            callGasLimit: gasParams.callGasLimit || gasEstimate.toNumber(),
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
        throw { status: 500, message: 'Failed to create UserOperation', details: error.message };
    }
}

async function generatePaymasterData(userOp, sponsorType) {
    try {
        const deadline = Math.floor(Date.now() / 1000) + 3600;
        return ethers.utils.defaultAbiCoder.encode(['uint256'], [deadline]);
    } catch (error) {
        logger.error('Generate paymaster data error:', error);
        throw { status: 500, message: 'Failed to generate paymaster data', details: error.message };
    }
}

async function validateUserOp(userOp) {
    try {
        const userOpHash = ethers.utils.keccak256(packUserOp(userOp));
        const recoveredAddress = ethers.utils.verifyMessage(ethers.utils.arrayify(userOpHash), userOp.signature);
        if (recoveredAddress.toLowerCase() !== userOp.sender.toLowerCase()) {
            throw { status: 401, message: 'Invalid signature' };
        }

        const onChainNonce = await coreContract.nonces(userOp.sender);
        if (userOp.nonce < onChainNonce.toNumber()) {
            throw { status: 400, message: 'Nonce too low' };
        }

        if (userOp.paymasterAndData !== '0x') {
            const paymasterAddress = userOp.paymasterAndData.slice(0, 42);
            const sponsorType = parseInt(userOp.paymasterAndData.slice(42, 44), 16);
            const totalGasCost = ethers.BigNumber.from(userOp.maxFeePerGas)
                .mul(userOp.callGasLimit + userOp.verificationGasLimit + userOp.preVerificationGas);
            const balance = await paymasterContract.getBalance(sponsorType);
            if (balance.lt(totalGasCost)) {
                throw { status: 402, message: 'Insufficient paymaster funding' };
            }

            const [validationResult] = await paymasterContract.validatePaymasterUserOp(userOp, userOpHash, totalGasCost);
            if (validationResult.toNumber() !== 0) {
                throw { status: 400, message: 'Paymaster validation failed' };
            }
        }

        return true;
    } catch (error) {
        logger.error('UserOp validation error:', error);
        throw error.status ? error : { status: 500, message: 'UserOp validation failed', details: error.message };
    }
}

async function submitUserOperation(userOp) {
    const dbUserOp = new UserOp({ ...userOp, status: 'pending' });
    try {
        await dbUserOp.save();

        const isValid = await validateUserOp(userOp);
        if (!isValid) throw { status: 400, message: 'UserOp validation failed' };

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
        throw error.status ? error : { status: 500, message: 'UserOp submission failed', details: error.message };
    }
}

// Queue Processor for User Operations
userOpQueue.process(async (job) => {
    const { userOp } = job.data;
    return await submitUserOperation(userOp);
});

// AI Symptom Analysis
async function analyzeSymptoms(symptoms) {
    try {
        const tensor = tf.tensor([symptoms.split(' ').length]);
        const prediction = tensor.add(0.5);
        return { diagnosis: "Possible condition based on: " + symptoms, confidence: prediction.dataSync()[0] };
    } catch (error) {
        logger.error('Symptom analysis error:', error);
        throw { status: 500, message: 'Symptom analysis failed', details: error.message };
    }
}

// Queue Processor for AI Analysis
aiQueue.process(async (job) => {
    const { symptoms } = job.data;
    return await analyzeSymptoms(symptoms);
});

// OnRamp/OffRamp Providers with Retry
async function initiateYellowCardOnRamp(fiatAmount, targetToken, userAddress) {
    try {
        const response = await axios.post('https://api.yellowcard.io/v1/onramp', {
            amount: fiatAmount,
            currency: 'USD',
            destination: targetToken === 0 ? 'ETH' : targetToken === 1 ? 'USDC' : 'SONIC',
            walletAddress: userAddress,
            apiKey: env.YELLOWCARD_API_KEY,
        });
        return response.data.transactionId;
    } catch (error) {
        logger.error('Yellow Card on-ramp error:', error);
        throw { status: 502, message: 'Yellow Card on-ramp initiation failed', details: error.message };
    }
}

async function initiateMoonPayOnRamp(fiatAmount, targetToken, userAddress) {
    try {
        const response = await axios.get('https://api.moonpay.com/v3/buy/quote', {
            params: {
                apiKey: env.MOONPAY_API_KEY,
                currencyCode: targetToken === 0 ? 'eth' : targetToken === 1 ? 'usdc' : 'sonic',
                baseCurrencyCode: 'usd',
                baseCurrencyAmount: fiatAmount,
                walletAddress: userAddress,
            },
        });
        return response.data.transactionId;
    } catch (error) {
        logger.error('MoonPay on-ramp error:', error);
        throw { status: 502, message: 'MoonPay on-ramp initiation failed', details: error.message };
    }
}

async function initiateYellowCardOffRamp(cryptoAmount, sourceToken, bankDetails, userAddress) {
    try {
        const response = await axios.post('https://api.yellowcard.io/v1/offramp', {
            amount: cryptoAmount,
            currency: sourceToken === 0 ? 'ETH' : sourceToken === 1 ? 'USDC' : 'SONIC',
            bankDetails,
            walletAddress: userAddress,
            apiKey: env.YELLOWCARD_API_KEY,
        });
        return response.data.transactionId;
    } catch (error) {
        logger.error('Yellow Card off-ramp error:', error);
        throw { status: 502, message: 'Yellow Card off-ramp initiation failed', details: error.message };
    }
}

async function initiateMoonPayOffRamp(cryptoAmount, sourceToken, bankDetails, userAddress) {
    try {
        const response = await axios.post('https://api.moonpay.com/v3/sell/quote', {
            apiKey: env.MOONPAY_API_KEY,
            currencyCode: sourceToken === 0 ? 'eth' : sourceToken === 1 ? 'usdc' : 'sonic',
            baseCurrencyAmount: cryptoAmount,
            bankDetails,
            walletAddress: userAddress,
        });
        return response.data.transactionId;
    } catch (error) {
        logger.error('MoonPay off-ramp error:', error);
        throw { status: 502, message: 'MoonPay off-ramp initiation failed', details: error.message };
    }
}

// Authentication Routes
/**
 * @swagger
 * /login:
 *   post:
 *     summary: User login
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               address: { type: string }
 *               signature: { type: string }
 *               message: { type: string }
 *     responses:
 *       200: { description: Successful login }
 *       401: { description: Invalid signature }
 */
app.post('/login', validate([
    body('address').isEthereumAddress(),
    body('signature').notEmpty(),
    body('message').notEmpty(),
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
        const token = jwt.sign({ address, role: user.role }, env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token, role: user.role });
    } catch (error) {
        logger.error('Login error:', error);
        throw { status: 500, message: 'Login failed', details: error.message };
    }
});

/**
 * @swagger
 * /register:
 *   post:
 *     summary: Register new user
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               address: { type: string }
 *               role: { type: string, enum: ['patient', 'doctor', 'labTech', 'pharmacy', 'admin'] }
 *               signature: { type: string }
 *               message: { type: string }
 *     responses:
 *       200: { description: Successful registration }
 *       400: { description: User already exists }
 */
app.post('/register', validate([
    body('address').isEthereumAddress(),
    body('role').isIn(['patient', 'doctor', 'labTech', 'pharmacy', 'admin']),
    body('signature').notEmpty(),
    body('message').notEmpty(),
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
        const token = jwt.sign({ address, role }, env.JWT_SECRET, { expiresIn: '1h' });

        if (role === 'patient') {
            const callData = coreContract.interface.encodeFunctionData('registerPatient', ['encryptedSymmetricKey']);
            const salt = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(address + Date.now().toString()));
            const accountAddr = await accountFactoryContract.getAddress(address, salt);
            const userOp = await createUserOperation(accountAddr, callData);
            await userOpQueue.add({ userOp });
        }

        res.json({ token, role });
    } catch (error) {
        logger.error('Register error:', error);
        throw { status: 500, message: 'Registration failed', details: error.message };
    }
});

app.post('/validate-token', authMiddleware, async (req, res) => {
    try {
        const user = await User.findOne({ address: req.user.address });
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json({ address: user.address, role: user.role });
    } catch (error) {
        logger.error('Token validation error:', error);
        throw { status: 500, message: 'Token validation failed', details: error.message };
    }
});

// Protected Routes
app.post('/register-patient', authMiddleware, validate([
    body('encryptedSymmetricKey').notEmpty(),
]), async (req, res) => {
    try {
        if (req.user.role !== 'patient') return res.status(403).json({ error: 'Patient role required' });
        const callData = coreContract.interface.encodeFunctionData('registerPatient', [req.body.encryptedSymmetricKey]);
        const salt = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(req.user.address + Date.now().toString()));
        const accountAddr = await accountFactoryContract.getAddress(req.user.address, salt);
        const userOp = await createUserOperation(accountAddr, callData);
        const job = await userOpQueue.add({ userOp });
        res.json({ jobId: job.id });
    } catch (error) {
        logger.error('Patient registration error:', error);
        throw { status: 500, message: 'Patient registration failed', details: error.message };
    }
});

app.post('/verify-doctor', authMiddleware, validate([
    body('doctorAddress').isEthereumAddress(),
    body('licenseNumber').notEmpty(),
    body('fee').isNumeric(),
]), async (req, res) => {
    const { doctorAddress, licenseNumber, fee } = req.body;
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
        const callData = coreContract.interface.encodeFunctionData('verifyDoctor', [doctorAddress, licenseNumber, ethers.utils.parseEther(fee)]);
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });
        await User.findOneAndUpdate({ address: doctorAddress }, { role: 'doctor' }, { upsert: true });
        res.json({ jobId: job.id });
    } catch (error) {
        logger.error('Doctor verification error:', error);
        throw { status: 500, message: 'Doctor verification failed', details: error.message };
    }
});

app.post('/verify-lab-technician', authMiddleware, validate([
    body('labTechAddress').isEthereumAddress(),
    body('licenseNumber').notEmpty(),
]), async (req, res) => {
    const { labTechAddress, licenseNumber } = req.body;
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
        const callData = coreContract.interface.encodeFunctionData('verifyLabTechnician', [labTechAddress, licenseNumber]);
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });
        await User.findOneAndUpdate({ address: labTechAddress }, { role: 'labTech' }, { upsert: true });
        res.json({ jobId: job.id });
    } catch (error) {
        logger.error('Lab technician verification error:', error);
        throw { status: 500, message: 'Lab technician verification failed', details: error.message };
    }
});

app.post('/register-pharmacy', authMiddleware, validate([
    body('pharmacyAddress').isEthereumAddress(),
    body('registrationNumber').notEmpty(),
]), async (req, res) => {
    const { pharmacyAddress, registrationNumber } = req.body;
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
        const callData = coreContract.interface.encodeFunctionData('registerPharmacy', [pharmacyAddress, registrationNumber]);
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });
        await User.findOneAndUpdate({ address: pharmacyAddress }, { role: 'pharmacy' }, { upsert: true });
        res.json({ jobId: job.id });
    } catch (error) {
        logger.error('Pharmacy registration error:', error);
        throw { status: 500, message: 'Pharmacy registration failed', details: error.message };
    }
});

/**
 * @swagger
 * /book-appointment:
 *   post:
 *     summary: Book an appointment
 *     tags: [Medical]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               doctorAddress: { type: string }
 *               timestamp: { type: integer }
 *               paymentType: { type: integer, enum: [0, 1, 2] }
 *               isVideoCall: { type: boolean }
 *               videoCallLink: { type: string }
 *     responses:
 *       200: { description: Appointment booked }
 *       403: { description: Unauthorized }
 */
app.post('/book-appointment', authMiddleware, validate([
    body('doctorAddress').isEthereumAddress(),
    body('timestamp').isInt({ min: Math.floor(Date.now() / 1000) }),
    body('paymentType').isInt({ min: 0, max: 2 }),
    body('isVideoCall').isBoolean(),
    body('videoCallLink').optional().isURL(),
]), async (req, res) => {
    const { doctorAddress, timestamp, paymentType, isVideoCall, videoCallLink } = req.body;
    try {
        if (req.user.role !== 'patient') return res.status(403).json({ error: 'Patient role required' });
        const callData = medicalContract.interface.encodeFunctionData('bookAppointment', [
            doctorAddress,
            timestamp,
            paymentType,
            isVideoCall,
            videoCallLink || '',
        ]);
        const userOp = await createUserOperation(req.user.address, callData, {
            to: medicalContract.address,
            value: paymentType === 0 ? ethers.utils.parseEther(req.body.amount || '0') : 0,
            sponsorType: paymentType,
        });
        const job = await userOpQueue.add({ userOp });
        wss.clients.forEach(client => {
            if (client.user.address === req.user.address) {
                client.send(JSON.stringify({ type: 'appointment', jobId: job.id }));
            }
        });
        res.json({ jobId: job.id });
    } catch (error) {
        logger.error('Booking error:', error);
        throw { status: 500, message: 'Appointment booking failed', details: error.message };
    }
});

app.post('/confirm-appointment', authMiddleware, validate([
    body('appointmentId').isInt({ min: 1 }),
    body('overridePriority').optional().isBoolean(),
]), async (req, res) => {
    const { appointmentId, overridePriority } = req.body;
    try {
        if (req.user.role !== 'doctor') return res.status(403).json({ error: 'Doctor role required' });
        const callData = medicalContract.interface.encodeFunctionData('confirmAppointment', [appointmentId, overridePriority || false]);
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });
        wss.clients.forEach(client => {
            if (client.user.role === 'patient' || client.user.role === 'doctor') {
                client.send(JSON.stringify({ type: 'appointmentConfirmed', id: appointmentId, jobId: job.id }));
            }
        });
        res.json({ jobId: job.id });
    } catch (error) {
        logger.error('Confirmation error:', error);
        throw { status: 500, message: 'Appointment confirmation failed', details: error.message };
    }
});

app.post('/batch-confirm-appointments', authMiddleware, validate([
    body('appointmentIds').isArray().notEmpty(),
]), async (req, res) => {
    const { appointmentIds } = req.body;
    try {
        if (req.user.role !== 'doctor') return res.status(403).json({ error: 'Doctor role required' });
        const callData = medicalContract.interface.encodeFunctionData('batchConfirmAppointments', [appointmentIds]);
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });
        wss.clients.forEach(client => {
            if (client.user.role === 'patient' || client.user.role === 'doctor') {
                client.send(JSON.stringify({ type: 'batchAppointmentsConfirmed', ids: appointmentIds, jobId: job.id }));
            }
        });
        res.json({ jobId: job.id });
    } catch (error) {
        logger.error('Batch confirmation error:', error);
        throw { status: 500, message: 'Batch confirmation failed', details: error.message };
    }
});

app.post('/complete-appointment', authMiddleware, validate([
    body('appointmentId').isInt({ min: 1 }),
    body('ipfsSummary').notEmpty(),
]), async (req, res) => {
    const { appointmentId, ipfsSummary } = req.body;
    try {
        if (req.user.role !== 'doctor') return res.status(403).json({ error: 'Doctor role required' });
        const callData = medicalContract.interface.encodeFunctionData('completeAppointment', [appointmentId, ipfsSummary]);
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });
        wss.clients.forEach(client => {
            if (client.user.role === 'patient' || client.user.role === 'doctor') {
                client.send(JSON.stringify({ type: 'appointmentCompleted', id: appointmentId, jobId: job.id }));
            }
        });
        res.json({ jobId: job.id });
    } catch (error) {
        logger.error('Completion error:', error);
        throw { status: 500, message: 'Appointment completion failed', details: error.message };
    }
});

app.post('/cancel-appointment', authMiddleware, validate([
    body('appointmentId').isInt({ min: 1 }),
]), async (req, res) => {
    const { appointmentId } = req.body;
    try {
        if (req.user.role !== 'patient') return res.status(403).json({ error: 'Patient role required' });
        const callData = medicalContract.interface.encodeFunctionData('cancelAppointment', [appointmentId]);
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });
        wss.clients.forEach(client => {
            if (client.user.address === req.user.address) {
                client.send(JSON.stringify({ type: 'appointmentCancelled', id: appointmentId, jobId: job.id }));
            }
        });
        res.json({ jobId: job.id });
    } catch (error) {
        logger.error('Cancellation error:', error);
        throw { status: 500, message: 'Appointment cancellation failed', details: error.message };
    }
});

app.post('/reschedule-appointment', authMiddleware, validate([
    body('appointmentId').isInt({ min: 1 }),
    body('newTimestamp').isInt({ min: Math.floor(Date.now() / 1000) }),
]), async (req, res) => {
    const { appointmentId, newTimestamp } = req.body;
    try {
        if (req.user.role !== 'patient') return res.status(403).json({ error: 'Patient role required' });
        const callData = medicalContract.interface.encodeFunctionData('rescheduleAppointment', [appointmentId, newTimestamp]);
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });
        wss.clients.forEach(client => {
            if (client.user.address === req.user.address) {
                client.send(JSON.stringify({ type: 'appointmentRescheduled', id: appointmentId, newTimestamp, jobId: job.id }));
            }
        });
        res.json({ jobId: job.id });
    } catch (error) {
        logger.error('Reschedule error:', error);
        throw { status: 500, message: 'Appointment rescheduling failed', details: error.message };
    }
});

app.post('/analyze-symptoms', authMiddleware, validate([
    body('symptoms').notEmpty(),
]), async (req, res) => {
    const { symptoms } = req.body;
    try {
        if (req.user.role !== 'patient') return res.status(403).json({ error: 'Patient role required' });
        const job = await aiQueue.add({ symptoms });
        const analysis = await job.finished();
        const ipfsResult = await ipfs.add(JSON.stringify(analysis));
        const callData = medicalContract.interface.encodeFunctionData('requestAISymptomAnalysis', [symptoms]);
        const userOp = await createUserOperation(req.user.address, callData);
        const userOpJob = await userOpQueue.add({ userOp });
        res.json({ jobId: userOpJob.id, ipfsHash: ipfsResult.path });
    } catch (error) {
        logger.error('Symptom analysis error:', error);
        throw { status: 500, message: 'Symptom analysis failed', details: error.message };
    }
});

app.post('/review-ai-analysis', authMiddleware, validate([
    body('aiAnalysisId').isInt({ min: 1 }),
    body('analysisIpfsHash').notEmpty(),
]), async (req, res) => {
    const { aiAnalysisId, analysisIpfsHash } = req.body;
    try {
        if (req.user.role !== 'doctor') return res.status(403).json({ error: 'Doctor role required' });
        const callData = medicalContract.interface.encodeFunctionData('reviewAISymptomAnalysis', [aiAnalysisId, analysisIpfsHash]);
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });
        res.json({ jobId: job.id });
    } catch (error) {
        logger.error('AI review error:', error);
        throw { status: 500, message: 'AI analysis review failed', details: error.message };
    }
});

app.post('/order-lab-test', authMiddleware, validate([
    body('patientAddress').isEthereumAddress(),
    body('testType').notEmpty(),
]), async (req, res) => {
    const { patientAddress, testType } = req.body;
    try {
        if (req.user.role !== 'doctor') return res.status(403).json({ error: 'Doctor role required' });
        const callData = medicalContract.interface.encodeFunctionData('orderLabTest', [patientAddress, testType]);
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });
        res.json({ jobId: job.id });
    } catch (error) {
        logger.error('Lab test order error:', error);
        throw { status: 500, message: 'Lab test order failed', details: error.message };
    }
});

app.post('/collect-sample', authMiddleware, validate([
    body('labTestId').isInt({ min: 1 }),
    body('sampleIpfsHash').notEmpty(),
]), async (req, res) => {
    const { labTestId, sampleIpfsHash } = req.body;
    try {
        if (req.user.role !== 'labTech') return res.status(403).json({ error: 'LabTech role required' });
        const callData = medicalContract.interface.encodeFunctionData('collectSample', [labTestId, sampleIpfsHash]);
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });
        res.json({ jobId: job.id });
    } catch (error) {
        logger.error('Sample collection error:', error);
        throw { status: 500, message: 'Sample collection failed', details: error.message };
    }
});

app.post('/upload-lab-results', authMiddleware, validate([
    body('labTestId').isInt({ min: 1 }),
    body('resultsIpfsHash').notEmpty(),
]), async (req, res) => {
    const { labTestId, resultsIpfsHash } = req.body;
    try {
        if (req.user.role !== 'labTech') return res.status(403).json({ error: 'LabTech role required' });
        const callData = medicalContract.interface.encodeFunctionData('uploadLabResults', [labTestId, resultsIpfsHash]);
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });
        res.json({ jobId: job.id });
    } catch (error) {
        logger.error('Results upload error:', error);
        throw { status: 500, message: 'Lab results upload failed', details: error.message };
    }
});

app.post('/review-lab-results', authMiddleware, validate([
    body('labTestId').isInt({ min: 1 }),
    body('medicationDetails').notEmpty(),
    body('prescriptionIpfsHash').notEmpty(),
]), async (req, res) => {
    const { labTestId, medicationDetails, prescriptionIpfsHash } = req.body;
    try {
        if (req.user.role !== 'doctor') return res.status(403).json({ error: 'Doctor role required' });
        const callData = medicalContract.interface.encodeFunctionData('reviewLabResults', [labTestId, medicationDetails, prescriptionIpfsHash]);
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });
        res.json({ jobId: job.id });
    } catch (error) {
        logger.error('Lab results review error:', error);
        throw { status: 500, message: 'Lab results review failed', details: error.message };
    }
});

app.post('/verify-prescription', authMiddleware, validate([
    body('prescriptionId').isInt({ min: 1 }),
    body('verificationCodeHash').notEmpty(),
]), async (req, res) => {
    const { prescriptionId, verificationCodeHash } = req.body;
    try {
        if (req.user.role !== 'pharmacy') return res.status(403).json({ error: 'Pharmacy role required' });
        const callData = medicalContract.interface.encodeFunctionData('verifyPrescription', [prescriptionId, ethers.utils.hexlify(verificationCodeHash)]);
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });
        res.json({ jobId: job.id });
    } catch (error) {
        logger.error('Prescription verification error:', error);
        throw { status: 500, message: 'Prescription verification failed', details: error.message };
    }
});

app.post('/fulfill-prescription', authMiddleware, validate([
    body('prescriptionId').isInt({ min: 1 }),
]), async (req, res) => {
    const { prescriptionId } = req.body;
    try {
        if (req.user.role !== 'pharmacy') return res.status(403).json({ error: 'Pharmacy role required' });
        const callData = medicalContract.interface.encodeFunctionData('fulfillPrescription', [prescriptionId]);
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });
        res.json({ jobId: job.id });
    } catch (error) {
        logger.error('Prescription fulfillment error:', error);
        throw { status: 500, message: 'Prescription fulfillment failed', details: error.message };
    }
});

app.post('/toggle-data-monetization', authMiddleware, validate([
    body('enable').isBoolean(),
]), async (req, res) => {
    const { enable } = req.body;
    try {
        const callData = coreContract.interface.encodeFunctionData('toggleDataMonetization', [enable]);
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });
        res.json({ jobId: job.id });
    } catch (error) {
        logger.error('Data monetization toggle error:', error);
        throw { status: 500, message: 'Data monetization toggle failed', details: error.message };
    }
});

app.post('/claim-data-reward', authMiddleware, async (req, res) => {
    try {
        const callData = coreContract.interface.encodeFunctionData('claimDataReward');
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });
        res.json({ jobId: job.id });
    } catch (error) {
        logger.error('Reward claim error:', error);
        throw { status: 500, message: 'Data reward claim failed', details: error.message };
    }
});

app.post('/deposit-ai-fund', authMiddleware, validate([
    body('amount').isNumeric({ min: 0 }),
]), async (req, res) => {
    const { amount } = req.body;
    try {
        const callData = paymentsContract.interface.encodeFunctionData('deposit', [coreContract.address, ethers.utils.parseEther(amount)]);
        const userOp = await createUserOperation(req.user.address, callData, {
            to: paymentsContract.address,
            value: ethers.utils.parseEther(amount),
        });
        const job = await userOpQueue.add({ userOp });
        res.json({ jobId: job.id });
    } catch (error) {
        logger.error('AI fund deposit error:', error);
        throw { status: 500, message: 'AI fund deposit failed', details: error.message };
    }
});

app.post('/deposit-reserve-fund', authMiddleware, validate([
    body('amount').isNumeric({ min: 0 }),
]), async (req, res) => {
    const { amount } = req.body;
    try {
        const callData = paymentsContract.interface.encodeFunctionData('deposit', [coreContract.address, ethers.utils.parseEther(amount)]);
        const userOp = await createUserOperation(req.user.address, callData, {
            to: paymentsContract.address,
            value: ethers.utils.parseEther(amount),
        });
        const job = await userOpQueue.add({ userOp });
        res.json({ jobId: job.id });
    } catch (error) {
        logger.error('Reserve fund deposit error:', error);
        throw { status: 500, message: 'Reserve fund deposit failed', details: error.message };
    }
});

app.post('/paymaster-deposit', authMiddleware, validate([
    body('amount').isNumeric({ min: 0 }),
    body('sponsorType').isInt({ min: 0, max: 2 }),
]), async (req, res) => {
    const { amount, sponsorType } = req.body;
    try {
        const callData = paymasterContract.interface.encodeFunctionData('deposit', [sponsorType, ethers.utils.parseEther(amount)]);
        const userOp = await createUserOperation(req.user.address, callData, {
            to: paymasterContract.address,
            value: sponsorType === 0 ? ethers.utils.parseEther(amount) : 0,
        });
        const job = await userOpQueue.add({ userOp });
        res.json({ jobId: job.id });
    } catch (error) {
        logger.error('Paymaster deposit error:', error);
        throw { status: 500, message: 'Paymaster deposit failed', details: error.message };
    }
});

app.post('/subscribe', authMiddleware, validate([
    body('plan').isInt({ min: 0, max: 1 }),
]), async (req, res) => {
    const { plan } = req.body;
    try {
        const callData = subscriptionContract.interface.encodeFunctionData('subscribe', [plan]);
        const userOp = await createUserOperation(req.user.address, callData, {
            to: subscriptionContract.address,
            value: ethers.utils.parseEther(plan === 0 ? '0.01' : '0.05'),
        });
        const job = await userOpQueue.add({ userOp });
        res.json({ jobId: job.id });
    } catch (error) {
        logger.error('Subscription error:', error);
        throw { status: 500, message: 'Subscription failed', details: error.message };
    }
});

app.post('/queue-withdraw-funds', authMiddleware, validate([
    body('to').isEthereumAddress(),
    body('amount').isNumeric({ min: 0 }),
]), async (req, res) => {
    const { to, amount } = req.body;
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
        const callData = governanceContract.interface.encodeFunctionData('queueWithdrawFunds', [to, ethers.utils.parseEther(amount)]);
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });

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

        res.json({ jobId: job.id, timeLockId });
    } catch (error) {
        logger.error('Withdraw funds queue error:', error);
        throw { status: 500, message: 'Withdraw funds queue failed', details: error.message };
    }
});

app.post('/queue-add-admin', authMiddleware, validate([
    body('newAdmin').isEthereumAddress(),
]), async (req, res) => {
    const { newAdmin } = req.body;
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
        const callData = governanceContract.interface.encodeFunctionData('queueAddAdmin', [newAdmin]);
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });

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

        res.json({ jobId: job.id, timeLockId });
    } catch (error) {
        logger.error('Add admin queue error:', error);
        throw { status: 500, message: 'Add admin queue failed', details: error.message };
    }
});

app.post('/approve-timelock', authMiddleware, validate([
    body('timeLockId').isInt({ min: 1 }),
]), async (req, res) => {
    const { timeLockId } = req.body;
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
        const callData = governanceContract.interface.encodeFunctionData('approveTimeLock', [timeLockId]);
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });

        const timeLock = await TimeLock.findOne({ id: timeLockId });
        if (!timeLock) throw { status: 404, message: 'TimeLock not found' };
        if (!timeLock.approvals.includes(req.user.address)) {
            timeLock.approvals.push(req.user.address);
            timeLock.approvalCount += 1;
            await timeLock.save();
        }

        res.json({ jobId: job.id });
    } catch (error) {
        logger.error('Time-lock approval error:', error);
        throw error.status ? error : { status: 500, message: 'Time-lock approval failed', details: error.message };
    }
});

app.post('/execute-timelock', authMiddleware, validate([
    body('timeLockId').isInt({ min: 1 }),
]), async (req, res) => {
    const { timeLockId } = req.body;
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
        const callData = governanceContract.interface.encodeFunctionData('executeTimeLock', [timeLockId]);
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });

        const timeLock = await TimeLock.findOne({ id: timeLockId });
        if (!timeLock) throw { status: 404, message: 'TimeLock not found' };
        timeLock.executed = true;
        await timeLock.save();

        res.json({ jobId: job.id });
    } catch (error) {
        logger.error('Time-lock execution error:', error);
        throw error.status ? error : { status: 500, message: 'Time-lock execution failed', details: error.message };
    }
});

app.post('/emergency-pause', authMiddleware, async (req, res) => {
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
        const callData = emergencyContract.interface.encodeFunctionData('emergencyPause');
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });
        res.json({ jobId: job.id });
    } catch (error) {
        logger.error('Emergency pause error:', error);
        throw { status: 500, message: 'Emergency pause failed', details: error.message };
    }
});

app.post('/request-emergency-unpause', authMiddleware, async (req, res) => {
    try {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
        const callData = emergencyContract.interface.encodeFunctionData('requestEmergencyUnpause');
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });
        res.json({ jobId: job.id });
    } catch (error) {
        logger.error('Emergency unpause request error:', error);
        throw { status: 500, message: 'Emergency unpause request failed', details: error.message };
    }
});

app.post('/request-onramp', authMiddleware, validate([
    body('fiatAmount').isNumeric({ min: 0 }),
    body('targetToken').isInt({ min: 0, max: 2 }),
    body('provider').isIn(['yellowcard', 'moonpay']),
]), async (req, res) => {
    const { fiatAmount, targetToken, provider } = req.body;
    try {
        let providerReference;
        if (provider === 'yellowcard') {
            providerReference = await initiateYellowCardOnRamp(fiatAmount, targetToken, req.user.address);
        } else if (provider === 'moonpay') {
            providerReference = await initiateMoonPayOnRamp(fiatAmount, targetToken, req.user.address);
        } else {
            throw { status: 400, message: 'Unsupported provider' };
        }

        const callData = paymentsContract.interface.encodeFunctionData('deposit', [
            coreContract.address,
            ethers.utils.parseEther(fiatAmount.toString()),
        ]);
        const userOp = await createUserOperation(req.user.address, callData, {
            to: paymentsContract.address,
            value: ethers.utils.parseEther('0.001'),
        });
        const job = await userOpQueue.add({ userOp });
        res.json({ jobId: job.id, providerReference });
    } catch (error) {
        logger.error('OnRamp request error:', error);
        throw error.status ? error : { status: 500, message: 'OnRamp request failed', details: error.message };
    }
});

app.post('/request-offramp', authMiddleware, validate([
    body('sourceToken').isInt({ min: 0, max: 2 }),
    body('cryptoAmount').isNumeric({ min: 0 }),
    body('bankDetails').notEmpty(),
    body('provider').isIn(['yellowcard', 'moonpay']),
]), async (req, res) => {
    const { sourceToken, cryptoAmount, bankDetails, provider } = req.body;
    try {
        let providerReference;
        if (provider === 'yellowcard') {
            providerReference = await initiateYellowCardOffRamp(cryptoAmount, sourceToken, bankDetails, req.user.address);
        } else if (provider === 'moonpay') {
            providerReference = await initiateMoonPayOffRamp(cryptoAmount, sourceToken, bankDetails, req.user.address);
        } else {
            throw { status: 400, message: 'Unsupported provider' };
        }

        const callData = paymentsContract.interface.encodeFunctionData('deposit', [
            coreContract.address,
            ethers.utils.parseEther(cryptoAmount.toString()),
        ]);
        const userOp = await createUserOperation(req.user.address, callData, {
            to: paymentsContract.address,
            value: sourceToken === 0 ? ethers.utils.parseEther(cryptoAmount.toString()).add(ethers.utils.parseEther('0.002')) : ethers.utils.parseEther('0.002'),
        });
        const job = await userOpQueue.add({ userOp });
        res.json({ jobId: job.id, providerReference });
    } catch (error) {
        logger.error('OffRamp request error:', error);
        throw error.status ? error : { status: 500, message: 'OffRamp request failed', details: error.message };
    }
});

app.post('/raise-dispute', authMiddleware, validate([
    body('relatedId').isInt({ min: 1 }),
    body('reason').notEmpty(),
]), async (req, res) => {
    const { relatedId, reason } = req.body;
    try {
        const callData = governanceContract.interface.encodeFunctionData('queueWithdrawFunds', [req.user.address, 0]);
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });

        const disputeId = (await Dispute.countDocuments()) + 1;
        await Dispute.create({
            id: disputeId,
            initiator: req.user.address,
            relatedId,
            status: 0,
            reason,
        });

        res.json({ jobId: job.id, disputeId });
    } catch (error) {
        logger.error('Dispute raise error:', error);
        throw { status: 500, message: 'Dispute raise failed', details: error.message };
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
        throw { status: 500, message: 'Paymaster status fetch failed', details: error.message };
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
        throw { status: 500, message: 'AI fund balance fetch failed', details: error.message };
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
        throw { status: 500, message: 'Reserve fund balance fetch failed', details: error.message };
    }
});

app.get('/check-role/:role/:address', authMiddleware, validate([
    param('role').isIn(['patient', 'doctor', 'labTech', 'pharmacy', 'admin']),
    param('address').isEthereumAddress(),
]), async (req, res) => {
    try {
        const cacheKey = `role_${req.params.role}_${req.params.address}`;
        const cached = cache.get(cacheKey);
        if (cached) return res.json(cached);

        const role = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(req.params.role.toUpperCase() + '_ROLE'));
        const hasRole = await coreContract.hasRole(role, req.params.address);
        const result = { hasRole };
        cache.set(cacheKey, result);
        res.json(result);
    } catch (error) {
        logger.error('Role check error:', error);
        throw { status: 500, message: 'Role check failed', details: error.message };
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
        throw { status: 500, message: 'Time-locks fetch failed', details: error.message };
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
        throw { status: 500, message: 'Disputes fetch failed', details: error.message };
    }
});

app.get('/userop-status/:jobId', authMiddleware, validate([
    param('jobId').isString(),
]), async (req, res) => {
    try {
        const job = await userOpQueue.getJob(req.params.jobId);
        if (!job) return res.status(404).json({ error: 'Job not found' });
        const userOp = await UserOp.findOne({ txHash: job.data.userOp.txHash });
        res.json({ status: userOp ? userOp.status : job.data.userOp.status, job });
    } catch (error) {
        logger.error('UserOp status error:', error);
        throw { status: 500, message: 'UserOp status fetch failed', details: error.message };
    }
});

app.get('/generate-qr/:prescriptionId', authMiddleware, validate([
    param('prescriptionId').isInt({ min: 1 }),
]), async (req, res) => {
    try {
        if (req.user.role !== 'pharmacy') return res.status(403).json({ error: 'Pharmacy role required' });
        const prescription = await medicalContract.prescriptions(req.params.prescriptionId);
        const qrData = JSON.stringify({
            id: prescription.id.toString(),
            verificationCodeHash: ethers.utils.hexlify(prescription.verificationCodeHash),
        });
        const qrCode = await QRCode.toDataURL(qrData);
        res.json({ qrCode });
    } catch (error) {
        logger.error('QR generation error:', error);
        throw { status: 500, message: 'QR code generation failed', details: error.message };
    }
});

app.get('/appointments/:id', authMiddleware, validate([
    param('id').isInt({ min: 1 }),
]), async (req, res) => {
    try {
        const cacheKey = `appointment_${req.params.id}`;
        const cached = cache.get(cacheKey);
        if (cached) return res.json(cached);

        const appointment = await medicalContract.appointments(req.params.id);
        const result = { appointment };
        cache.set(cacheKey, result);
        res.json(result);
    } catch (error) {
        logger.error('Appointment fetch error:', error);
        throw { status: 500, message: 'Appointment fetch failed', details: error.message };
    }
});

app.get('/lab-test/:id', authMiddleware, validate([
    param('id').isInt({ min: 1 }),
]), async (req, res) => {
    try {
        const cacheKey = `labtest_${req.params.id}`;
        const cached = cache.get(cacheKey);
        if (cached) return res.json(cached);

        const labTest = await medicalContract.labTestOrders(req.params.id);
        const result = { labTest };
        cache.set(cacheKey, result);
        res.json(result);
    } catch (error) {
        logger.error('Lab test fetch error:', error);
        throw { status: 500, message: 'Lab test fetch failed', details: error.message };
    }
});

app.get('/prescription/:id', authMiddleware, validate([
    param('id').isInt({ min: 1 }),
]), async (req, res) => {
    try {
        const cacheKey = `prescription_${req.params.id}`;
        const cached = cache.get(cacheKey);
        if (cached) return res.json(cached);

        const prescription = await medicalContract.prescriptions(req.params.id);
        const result = { prescription };
        cache.set(cacheKey, result);
        res.json(result);
    } catch (error) {
        logger.error('Prescription fetch error:', error);
        throw { status: 500, message: 'Prescription fetch failed', details: error.message };
    }
});

app.get('/ai-analysis/:id', authMiddleware, validate([
    param('id').isInt({ min: 1 }),
]), async (req, res) => {
    try {
        const cacheKey = `aianalysis_${req.params.id}`;
        const cached = cache.get(cacheKey);
        if (cached) return res.json(cached);

        const analysis = await medicalContract.aiAnalyses(req.params.id);
        const result = { analysis };
        cache.set(cacheKey, result);
        res.json(result);
    } catch (error) {
        logger.error('AI analysis fetch error:', error);
        throw { status: 500, message: 'AI analysis fetch failed', details: error.message };
    }
});

/**
 * @swagger
 * /patient-level/{address}:
 *   get:
 *     summary: Get patient level
 *     tags: [Patient]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: address
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200: { description: Patient level }
 *       403: { description: Unauthorized }
 */
app.get('/patient-level/:address', authMiddleware, validate([
    param('address').isEthereumAddress(),
]), async (req, res) => {
    try {
        const cacheKey = `patient_level_${req.params.address}`;
        const cached = cache.get(cacheKey);
        if (cached) return res.json(cached);

        const level = await coreContract.getPatientLevel(req.params.address);
        const result = { level: level.toString() };
        cache.set(cacheKey, result);
        res.json(result);
    } catch (error) {
        logger.error('Patient level fetch error:', error);
        throw { status: 500, message: 'Patient level fetch failed', details: error.message };
    }
});

app.get('/patient-points/:address', authMiddleware, validate([
    param('address').isEthereumAddress(),
]), async (req, res) => {
    try {
        const cacheKey = `patient_points_${req.params.address}`;
        const cached = cache.get(cacheKey);
        if (cached) return res.json(cached);

        const points = await coreContract.getPatientPoints(req.params.address);
        const result = { points: points.toString() };
        cache.set(cacheKey, result);
        res.json(result);
    } catch (error) {
        logger.error('Patient points fetch error:', error);
        throw { status: 500, message: 'Patient points fetch failed', details: error.message };
    }
});

app.get('/subscription-status/:address', authMiddleware, validate([
    param('address').isEthereumAddress(),
]), async (req, res) => {
    try {
        const cacheKey = `subscription_${req.params.address}`;
        const cached = cache.get(cacheKey);
        if (cached) return res.json(cached);

        const [isActive, expiry, consultsUsed] = await subscriptionContract.getSubscriptionStatus(req.params.address);
        const result = { isActive, expiry: expiry.toString(), consultsUsed: consultsUsed.toString() };
        cache.set(cacheKey, result);
        res.json(result);
    } catch (error) {
        logger.error('Subscription status fetch error:', error);
        throw { status: 500, message: 'Subscription status fetch failed', details: error.message };
    }
});

// WebSocket Handling with Authentication
wss.on('connection', (ws, req) => {
    const token = req.url.split('token=')[1];
    try {
        const decoded = jwt.verify(token, env.JWT_SECRET);
        ws.user = decoded;
        logger.info(`WebSocket client connected: ${ws.user.address}`);
    } catch (error) {
        ws.close(1008, 'Authentication required');
        logger.error('WebSocket auth error:', error);
        return;
    }

    ws.on('message', async (message) => {
        try {
            const data = JSON.parse(message);
            if (data.type === 'appointment') {
                const appointment = await medicalContract.appointments(data.id);
                ws.send(JSON.stringify({ type: 'appointmentUpdate', data: appointment }));
            }
        } catch (error) {
            logger.error('WebSocket message error:', error);
            ws.send(JSON.stringify({ error: 'WebSocket error', details: error.message }));
        }
    });

    ws.on('close', () => logger.info(`WebSocket client disconnected: ${ws.user.address}`));
});

// Error Handler (must be last middleware)
app.use(errorHandler);

// Start Server
server.listen(8080, () => logger.info('Server running on port 8080'));
