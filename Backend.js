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
const { cleanEnv, str, url, num, makeValidator } = require('envalid');
const Queue = require('bull');
const csurf = require('csurf');
const prom = require('prom-client');
const timeout = require('connect-timeout');
const helmet = require('helmet');
const sanitize = require('sanitize-html');
const redis = require('redis');
const circuitBreaker = require('opossum');
const slowDown = require('express-slow-down');
const sanitizeMongo = require('mongo-sanitize');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

// Custom envalid validator for Ethereum addresses
const ethAddress = makeValidator((x) => {
    if (!ethers.utils.isAddress(x)) throw new Error('Invalid Ethereum address');
    return x;
});

// Enhanced Environment Validation
const env = cleanEnv(process.env, {
    NODE_ENV: str({ choices: ['development', 'production', 'test'], default: 'development' }),
    SSL_CERT_PATH: str({ desc: 'Path to SSL certificate' }),
    SSL_KEY_PATH: str({ desc: 'Path to SSL key' }),
    SONIC_RPC_URL: url({ desc: 'Sonic RPC URL' }),
    PRIVATE_KEY: str({ desc: 'Wallet private key' }),
    JWT_SECRET: str({ default: crypto.randomBytes(32).toString('hex'), desc: 'JWT secret key' }),
    CORE_ADDRESS: ethAddress({ desc: 'Core contract address' }),
    PAYMENTS_ADDRESS: ethAddress({ desc: 'Payments contract address' }),
    MEDICAL_ADDRESS: ethAddress({ desc: 'Medical contract address' }),
    PAYMASTER_ADDRESS: ethAddress({ desc: 'Paymaster contract address' }),
    ACCOUNT_FACTORY_ADDRESS: ethAddress({ desc: 'Account Factory contract address' }),
    GOVERNANCE_ADDRESS: ethAddress({ desc: 'Governance contract address' }),
    EMERGENCY_ADDRESS: ethAddress({ desc: 'Emergency contract address' }),
    SUBSCRIPTION_ADDRESS: ethAddress({ desc: 'Subscription contract address' }),
    ENTRYPOINT_ADDRESS: ethAddress({ default: '0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789', desc: 'EntryPoint contract address' }),
    FRONTEND_URL: url({ desc: 'Frontend URL' }),
    MONGO_URI: url({ desc: 'MongoDB connection URI (required in production)', devDefault: 'mongodb://localhost:27017/telemedicine' }),
    REDIS_URL: url({ desc: 'Redis connection URL (required in production)', devDefault: 'redis://localhost:6379' }),
    YELLOWCARD_API_KEY: str({ desc: 'YellowCard API key' }),
    MOONPAY_API_KEY: str({ desc: 'MoonPay API key' }),
    RATE_LIMIT_MAX: num({ default: 200, desc: 'Max requests per window' }),
    RATE_LIMIT_WINDOW_MS: num({ default: 10 * 60 * 1000, desc: 'Rate limit window in ms' }),
    REQUEST_TIMEOUT_MS: num({ default: 30000, desc: 'Request timeout in ms' }),
    API_KEY_ROTATION_INTERVAL: num({ default: 24 * 60 * 60 * 1000, desc: 'API key rotation interval in ms' }),
    REDIS_TTL_NONCE: num({ default: 300, desc: 'Nonce TTL in seconds' }),
    REDIS_TTL_STATUS: num({ default: 3600, desc: 'Status TTL in seconds' }),
    EMAIL_USER: str({ desc: 'Email user for alerts', devDefault: 'user@example.com' }),
    EMAIL_PASS: str({ desc: 'Email password for alerts', devDefault: 'password' }),
    GOOGLE_API_KEY: str({ desc: 'Google Healthcare API key', devDefault: 'mock-google-key' })
}, {
    strict: process.env.NODE_ENV === 'production' // Enforce all vars in production
});

// Redis Clients
const redisClient = redis.createClient({
    url: env.REDIS_URL,
    socket: { reconnectStrategy: (retries) => Math.min(retries * 100, 1000) }
});
const redisPub = redis.createClient({ url: env.REDIS_URL });
const redisSub = redis.createClient({ url: env.REDIS_URL });
redisClient.connect().catch(err => console.error('Redis connection error:', err));
redisPub.connect();
redisSub.connect();

// DDoS Protection
const speedLimiter = slowDown({
    windowMs: 15 * 60 * 1000,
    delayAfter: 100,
    delayMs: (hits) => hits * 100
});

// Prometheus Metrics
const register = new prom.Registry();
const httpRequestDuration = new prom.Histogram({
    name: 'http_request_duration_seconds',
    help: 'Duration of HTTP requests in seconds',
    labelNames: ['method', 'route', 'status'],
    buckets: [0.1, 0.3, 0.5, 0.7, 1, 3, 5, 10],
});
const queueLengthGauge = new prom.Gauge({
    name: 'queue_length',
    help: 'Number of jobs in queue',
    labelNames: ['queue'],
});
const wsConnectionsGauge = new prom.Gauge({
    name: 'websocket_connections',
    help: 'Number of active WebSocket connections',
});
const circuitBreakerState = new prom.Gauge({
    name: 'circuit_breaker_state',
    help: 'State of circuit breakers (0: closed, 1: open, 2: half-open)',
    labelNames: ['breaker'],
});
register.registerMetric(httpRequestDuration);
register.registerMetric(queueLengthGauge);
register.registerMetric(wsConnectionsGauge);
register.registerMetric(circuitBreakerState);

// Setup
const app = express();
const server = https.createServer({
    cert: fs.readFileSync(env.SSL_CERT_PATH),
    key: fs.readFileSync(env.SSL_KEY_PATH),
});
const wss = new WebSocket.Server({ server, maxPayload: 1024 * 1024 });
const ipfs = create({ host: 'ipfs.infura.io', port: 5001, protocol: 'https' });
const provider = new ethers.providers.JsonRpcProvider(env.SONIC_RPC_URL);
const wallet = new ethers.Wallet(env.PRIVATE_KEY, provider);
const cache = new NodeCache({ stdTTL: env.REDIS_TTL_NONCE, checkperiod: 320 });

// Rate Limiting
const limiter = rateLimit({
    windowMs: env.RATE_LIMIT_WINDOW_MS,
    max: env.RATE_LIMIT_MAX,
    message: 'Too many requests from this IP, please try again later.',
    keyGenerator: (req) => req.ip + '-' + req.path
});

// CSRF Protection
const csrfProtection = csurf({ cookie: { secure: true, httpOnly: true } });

// Email Transport
const emailTransporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: env.EMAIL_USER, pass: env.EMAIL_PASS }
});

// Queues
const userOpQueue = new Queue('userOpQueue', {
    redis: { url: env.REDIS_URL },
    defaultJobOptions: { attempts: 3, backoff: { type: 'exponential', delay: 1000 } }
});
const aiQueue = new Queue('aiQueue', {
    redis: { url: env.REDIS_URL },
    defaultJobOptions: { attempts: 3, backoff: { type: 'exponential', delay: 1000 } }
});
const deadLetterQueue = new Queue('deadLetterQueue', {
    redis: { url: env.REDIS_URL }
});

// Contract Instances with Circuit Breakers
const createCircuitBreaker = (fn, options = {}) => {
    const breaker = circuitBreaker(fn, {
        timeout: 5000,
        errorThresholdPercentage: 50,
        resetTimeout: 30000,
        ...options
    });
    breaker.on('open', () => circuitBreakerState.set({ breaker: options.name || 'unknown' }, 1));
    breaker.on('close', () => circuitBreakerState.set({ breaker: options.name || 'unknown' }, 0));
    breaker.on('halfOpen', () => circuitBreakerState.set({ breaker: options.name || 'unknown' }, 2));
    return breaker;
};

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

const coreContractBreaker = createCircuitBreaker(async (...args) => await coreContract.call(...args), {
    name: 'core',
    fallback: () => ({ error: 'Core contract unavailable', mock: true })
});
const paymentsContractBreaker = createCircuitBreaker(async (...args) => await paymentsContract.call(...args), {
    name: 'payments',
    fallback: () => ({ error: 'Payments contract unavailable', mock: true })
});
const medicalContractBreaker = createCircuitBreaker(async (...args) => await medicalContract.call(...args), {
    name: 'medical',
    fallback: () => ({ error: 'Medical contract unavailable', mock: true })
});
const paymasterContractBreaker = createCircuitBreaker(async (...args) => await paymasterContract.call(...args), {
    name: 'paymaster',
    fallback: () => ({ error: 'Paymaster contract unavailable', mock: true })
});

// Middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            objectSrc: ["'none'"],
            upgradeInsecureRequests: []
        }
    }
}));
app.use(cors({ origin: env.FRONTEND_URL, credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(limiter);
app.use(speedLimiter);
app.use(timeout(env.REQUEST_TIMEOUT_MS));
app.use(csrfProtection);

// Logger
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json(),
        winston.format.metadata()
    ),
    transports: [
        new winston.transports.File({ filename: 'error.log', level: 'error' }),
        new winston.transports.Console()
    ],
});

// MongoDB Setup
mongoose.connect(env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    poolSize: 50,
    bufferCommands: false,
    autoIndex: true,
    serverSelectionTimeoutMS: 5000,
}).then(() => logger.info('Connected to MongoDB'))
  .catch(err => logger.error('MongoDB connection error:', { message: err.message, stack: err.stack }));

// Schemas
const UserSchema = new mongoose.Schema({
    address: { type: String, required: true, unique: true, index: true },
    role: { type: String, enum: ['patient', 'doctor', 'labTech', 'pharmacy', 'admin'], default: 'patient' },
    createdAt: { type: Date, default: Date.now },
});

const UserOpSchema = new mongoose.Schema({
    sender: { type: String, required: true, index: true },
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
    createdAt: { type: Date, default: Date.now, index: { expires: '30d' } },
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

// Swagger Setup with Detailed Docs
const swaggerOptions = {
    definition: {
        openapi: '3.0.0',
        info: { title: 'Telemedicine API', version: '1.0.0', description: 'Blockchain-based telemedicine platform' },
        servers: [{ url: 'https://localhost:8080' }],
        components: {
            securitySchemes: { bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' } },
            schemas: {
                LoginRequest: {
                    type: 'object',
                    properties: {
                        address: { type: 'string', description: 'Ethereum address' },
                        signature: { type: 'string', description: 'Signed message' },
                        message: { type: 'string', description: 'Message to sign' }
                    },
                    required: ['address', 'signature', 'message']
                },
                LoginResponse: {
                    type: 'object',
                    properties: {
                        token: { type: 'string', description: 'JWT token' },
                        role: { type: 'string', description: 'User role' },
                        csrfToken: { type: 'string', description: 'CSRF token' }
                    }
                }
            }
        },
        security: [{ bearerAuth: [] }]
    },
    apis: ['backend.js'],
};
const swaggerSpec = swaggerJsdoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// Axios Retry
axiosRetry(axios, {
    retries: 3,
    retryDelay: axiosRetry.exponentialDelay,
    retryCondition: (error) => axiosRetry.isNetworkOrIdempotentRequestError(error) || error.response?.status === 429,
    shouldResetTimeout: true
});

// API Key Rotation
let currentApiKeys = {
    yellowcard: env.YELLOWCARD_API_KEY,
    moonpay: env.MOONPAY_API_KEY,
};

async function rotateApiKeys() {
    logger.info('Rotating API keys');
    currentApiKeys.yellowcard = crypto.randomBytes(32).toString('hex');
    currentApiKeys.moonpay = crypto.randomBytes(32).toString('hex');
    await redisClient.set('api_keys', JSON.stringify(currentApiKeys), 'EX', env.API_KEY_ROTATION_INTERVAL / 1000);
}

setInterval(rotateApiKeys, env.API_KEY_ROTATION_INTERVAL);
(async () => {
    const storedKeys = await redisClient.get('api_keys');
    if (storedKeys) currentApiKeys = JSON.parse(storedKeys);
})();

// Error Classes
class ValidationError extends Error {
    constructor(message, details) { super(message); this.name = 'ValidationError'; this.status = 400; this.details = details; }
}
class AuthenticationError extends Error {
    constructor(message, details) { super(message); this.name = 'AuthenticationError'; this.status = 401; this.details = details; }
}
class AuthorizationError extends Error {
    constructor(message, details) { super(message); this.name = 'AuthorizationError'; this.status = 403; this.details = details; }
}
class NotFoundError extends Error {
    constructor(message, details) { super(message); this.name = 'NotFoundError'; this.status = 404; this.details = details; }
}
class ServiceError extends Error {
    constructor(message, details) { super(message); this.name = 'ServiceError'; this.status = 500; this.details = details; }
}

// Error Handler
const errorHandler = (err, req, res, next) => {
    const status = err.status || 500;
    const end = httpRequestDuration.startTimer({ method: req.method, route: req.path });
    logger.error(`${req.method} ${req.url} - Error: ${err.message}`, {
        stack: err.stack,
        metadata: { user: req.user?.address, ip: req.ip }
    });
    res.status(status).json({
        error: { message: err.message || 'Internal server error', code: err.name || 'UNKNOWN_ERROR', details: err.details || null, timestamp: new Date().toISOString() },
    });
    end({ status: status.toString() });
};

// Validation Middleware
const validate = (validations) => {
    return async (req, res, next) => {
        try {
            for (const key in req.body) {
                if (typeof req.body[key] === 'string') {
                    req.body[key] = sanitize(req.body[key], { allowedTags: [], allowedAttributes: {} });
                }
            }
            await Promise.all(validations.map(validation => validation.run(req)));
            const errors = validationResult(req);
            if (!errors.isEmpty()) throw new ValidationError('Validation failed', errors.array());
            next();
        } catch (error) {
            next(error);
        }
    };
};

// Auth Middleware
const authMiddleware = async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        if (!authHeader) throw new AuthenticationError('Authentication required', 'No token provided');
        const token = authHeader.split(' ')[1];
        if (!token) throw new AuthenticationError('Authentication required', 'Invalid token format');

        const tokenKey = `token:${token}`;
        const tokenUsage = await redisClient.get(tokenKey);
        if (tokenUsage && parseInt(tokenUsage) > 5000) throw new AuthenticationError('Token rate limit exceeded');
        await redisClient.incr(tokenKey);
        await redisClient.expire(tokenKey, 3600);

        const decoded = jwt.verify(token, env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        next(error instanceof jwt.JsonWebTokenError ? new AuthenticationError('Authentication failed', error.message) : error);
    }
};

// User Operation Handling
async function createUserOperation(sender, callData, gasParams = {}) {
    try {
        const nonceCacheKey = `nonce:${sender}`;
        let nonce = await redisClient.get(nonceCacheKey);
        if (!nonce) {
            const nonceResult = await coreContractBreaker.fire('nonces', sender);
            nonce = nonceResult.error ? 0 : nonceResult.toNumber();
            await redisClient.setEx(nonceCacheKey, env.REDIS_TTL_NONCE, nonce.toString());
        }

        let gasEstimate;
        try {
            gasEstimate = await provider.estimateGas({
                to: gasParams.to || medicalContract.address,
                data: callData,
                value: gasParams.value || 0,
                from: sender,
            });
        } catch (error) {
            logger.warn('Gas estimation failed, using default', { error: error.message });
            gasEstimate = ethers.BigNumber.from('100000'); // Reduced default for optimization
        }

        const userOp = {
            sender,
            nonce: parseInt(nonce),
            initCode: gasParams.initCode || '0x',
            callData,
            callGasLimit: gasParams.callGasLimit || gasEstimate.mul(12).div(10).toNumber(),
            verificationGasLimit: gasParams.verificationGasLimit || 150000,
            preVerificationGas: gasParams.preVerificationGas || 25000,
            maxFeePerGas: gasParams.maxFeePerGas || ethers.utils.parseUnits('15', 'gwei'),
            maxPriorityFeePerGas: gasParams.maxPriorityFeePerGas || ethers.utils.parseUnits('2', 'gwei'),
            paymasterAndData: '0x',
            signature: '0x',
        };

        if (gasParams.value) userOp.value = gasParams.value;

        const user = await User.findOne({ address: sanitizeMongo(sender) });
        if (user && user.role === 'patient') {
            const [isActive] = await subscriptionContract.getSubscriptionStatus(sender);
            const sponsorType = isActive ? (gasParams.sponsorType || 0) : 2;
            const paymasterData = await generatePaymasterData(userOp, sponsorType);
            userOp.paymasterAndData = ethers.utils.hexConcat([
                paymasterContract.address,
                ethers.utils.hexZeroPad(ethers.utils.hexlify(sponsorType), 1),
                paymasterData,
            ]);
        }

        const userOpHash = ethers.utils.keccak256(packUserOp(userOp));
        const signature = await wallet.signMessage(ethers.utils.arrayify(userOpHash));
        userOp.signature = signature;

        return userOp;
    } catch (error) {
        throw new ServiceError('Failed to create UserOperation', error.message);
    }
}

async function generatePaymasterData(userOp, sponsorType) {
    try {
        const deadline = Math.floor(Date.now() / 1000) + 3600;
        return ethers.utils.defaultAbiCoder.encode(['uint256'], [deadline]);
    } catch (error) {
        throw new ServiceError('Failed to generate paymaster data', error.message);
    }
}

async function validateUserOp(userOp) {
    try {
        const userOpHash = ethers.utils.keccak256(packUserOp(userOp));
        const recoveredAddress = ethers.utils.verifyMessage(ethers.utils.arrayify(userOpHash), userOp.signature);
        if (recoveredAddress.toLowerCase() !== userOp.sender.toLowerCase()) throw new AuthenticationError('Invalid signature');

        const nonceCacheKey = `nonce:${userOp.sender}`;
        const onChainNonce = await coreContractBreaker.fire('nonces', userOp.sender);
        if (userOp.nonce < (onChainNonce.error ? 0 : onChainNonce.toNumber())) throw new ValidationError('Nonce too low');
        await redisClient.setEx(nonceCacheKey, env.REDIS_TTL_NONCE, onChainNonce.error ? '0' : onChainNonce.toString());

        if (userOp.paymasterAndData !== '0x') {
            const paymasterAddress = userOp.paymasterAndData.slice(0, 42);
            const sponsorType = parseInt(userOp.paymasterAndData.slice(42, 44), 16);
            const totalGasCost = ethers.BigNumber.from(userOp.maxFeePerGas)
                .mul(userOp.callGasLimit + userOp.verificationGasLimit + userOp.preVerificationGas);
            const balance = await paymasterContractBreaker.fire('getBalance', sponsorType);
            if (balance.error || balance.lt(totalGasCost)) throw new ValidationError('Insufficient paymaster funding');

            const [validationResult] = await paymasterContractBreaker.fire('validatePaymasterUserOp', userOp, userOpHash, totalGasCost);
            if (validationResult.error || validationResult.toNumber() !== 0) throw new ValidationError('Paymaster validation failed');
        }

        return true;
    } catch (error) {
        throw error.status ? error : new ServiceError('UserOp validation failed', error.message);
    }
}

async function submitUserOperation(userOp) {
    const dbUserOp = new UserOp({ ...userOp, status: 'pending' });
    try {
        await dbUserOp.save();
        const isValid = await validateUserOp(userOp);
        if (!isValid) throw new ValidationError('UserOp validation failed');

        dbUserOp.status = 'validated';
        await dbUserOp.save();

        const tx = await entryPoint.handleOps([userOp], wallet.address, {
            gasLimit: ethers.BigNumber.from(userOp.callGasLimit).add(userOp.verificationGasLimit).add(userOp.preVerificationGas).mul(15).div(10),
            maxFeePerGas: userOp.maxFeePerGas,
            maxPriorityFeePerGas: userOp.maxPriorityFeePerGas
        });
        const receipt = await tx.wait();

        dbUserOp.txHash = tx.hash;
        dbUserOp.status = 'submitted';
        await dbUserOp.save();
        await redisClient.del(`nonce:${userOp.sender}`);
        return tx.hash;
    } catch (error) {
        dbUserOp.status = 'failed';
        await dbUserOp.save();
        await deadLetterQueue.add({ userOp, error: error.message });
        throw error.status ? error : new ServiceError('UserOp submission failed', error.message);
    }
}

// Queue Processor
userOpQueue.process(async (job) => {
    queueLengthGauge.set({ queue: 'userOpQueue' }, await userOpQueue.getJobCounts().then(counts => counts.waiting));
    try {
        return await submitUserOperation(job.data.userOp);
    } catch (error) {
        await deadLetterQueue.add({ userOp: job.data.userOp, error: error.message });
        throw error;
    }
});

userOpQueue.on('failed', async (job, err) => {
    logger.error('UserOp job failed:', { jobId: job.id, error: err.message });
});

// Enhanced AI Symptom Analysis
let symptomModel;
async function initSymptomModel() {
    if (!symptomModel) {
        symptomModel = tf.sequential();
        symptomModel.add(tf.layers.dense({ units: 16, activation: 'relu', inputShape: [5] })); // 5 symptom features
        symptomModel.add(tf.layers.dense({ units: 8, activation: 'relu' }));
        symptomModel.add(tf.layers.dense({ units: 1, activation: 'sigmoid' }));
        symptomModel.compile({ optimizer: 'adam', loss: 'binaryCrossentropy', metrics: ['accuracy'] });

        // Simulated training data (in practice, load from a dataset)
        const xs = tf.tensor2d([
            [1, 0, 1, 0, 1], // fever, cough, fatigue
            [0, 1, 0, 1, 0], // cough, headache
            [1, 1, 1, 0, 0], // fever, cough, fatigue
            [0, 0, 0, 1, 1]  // headache, nausea
        ]);
        const ys = tf.tensor2d([[1], [0], [1], [0]]); // 1 = flu, 0 = other
        await symptomModel.fit(xs, ys, { epochs: 50, verbose: 0 });
    }
    return symptomModel;
}

async function analyzeSymptoms(symptoms) {
    try {
        const cacheKey = `symptom_analysis:${ethers.utils.keccak256(ethers.utils.toUtf8Bytes(symptoms))}`;
        const cached = await redisClient.get(cacheKey);
        if (cached) return JSON.parse(cached);

        const response = await axios.post('https://healthcare.googleapis.com/v1/analyze', { symptoms }, {
            timeout: 10000,
            headers: { 'Authorization': `Bearer ${env.GOOGLE_API_KEY}` }
        });
        const result = response.data;
        await redisClient.setEx(cacheKey, 86400, JSON.stringify(result));
        return result;
    } catch (error) {
        logger.warn('AI service failed, using local model', { error: error.message });
        const fallbackResult = await localSymptomAnalysis(symptoms);
        if (fallbackResult) return fallbackResult;
        throw new ServiceError('Symptom analysis failed', error.message);
    }
}

async function localSymptomAnalysis(symptoms) {
    try {
        const model = await initSymptomModel();
        const symptomArray = symptoms.split(',').map(s => s.trim().toLowerCase());
        const features = [
            symptomArray.includes('fever') ? 1 : 0,
            symptomArray.includes('cough') ? 1 : 0,
            symptomArray.includes('fatigue') ? 1 : 0,
            symptomArray.includes('headache') ? 1 : 0,
            symptomArray.includes('nausea') ? 1 : 0
        ];
        const symptomVector = tf.tensor2d([features]);
        const prediction = model.predict(symptomVector);
        const confidence = prediction.dataSync()[0];
        const diagnosis = confidence > 0.5 ? 'Possible Flu' : 'Unknown Condition';
        return { diagnosis, confidence };
    } catch (error) {
        logger.error('Local AI analysis failed', { error: error.message });
        return null;
    }
}

aiQueue.process(async (job) => {
    queueLengthGauge.set({ queue: 'aiQueue' }, await aiQueue.getJobCounts().then(counts => counts.waiting));
    try {
        return await analyzeSymptoms(job.data.symptoms);
    } catch (error) {
        await deadLetterQueue.add({ symptoms: job.data.symptoms, error: error.message });
        throw error;
    }
});

// Dead Letter Queue Reprocessing
async function reprocessDeadLetterQueue() {
    const jobs = await deadLetterQueue.getJobs(['waiting'], 0, 10);
    for (const job of jobs) {
        logger.warn('Reprocessing dead letter job:', { jobId: job.id });
        try {
            if (job.data.userOp) await userOpQueue.add(job.data);
            else if (job.data.symptoms) await aiQueue.add(job.data);
            await job.remove();
        } catch (error) {
            await emailTransporter.sendMail({
                from: env.EMAIL_USER,
                to: 'admin@example.com',
                subject: `Dead Letter Queue Failure: Job ${job.id}`,
                text: `Failed to reprocess job ${job.id}: ${error.message}`
            });
            await job.moveToFailed({ message: 'Manual intervention required' });
        }
    }
}

setInterval(reprocessDeadLetterQueue, 60 * 60 * 1000);

// External Services
const yellowCardBreaker = createCircuitBreaker(initiateYellowCardOnRamp, { name: 'yellowcard', fallback: () => ({ transactionId: 'mock-yellowcard-txid', status: 'pending' }) });
const moonPayBreaker = createCircuitBreaker(initiateMoonPayOnRamp, { name: 'moonpay', fallback: () => ({ transactionId: 'mock-moonpay-txid', status: 'pending' }) });

async function initiateYellowCardOnRamp(fiatAmount, targetToken, userAddress) {
    const response = await axios.post('https://api.yellowcard.io/v1/onramp', {
        amount: fiatAmount,
        currency: 'USD',
        destination: targetToken === 0 ? 'ETH' : targetToken === 1 ? 'USDC' : 'SONIC',
        walletAddress: userAddress,
        apiKey: currentApiKeys.yellowcard,
    }, { timeout: 10000 });
    return response.data;
}

async function initiateMoonPayOnRamp(fiatAmount, targetToken, userAddress) {
    const response = await axios.get('https://api.moonpay.com/v3/buy/quote', {
        params: {
            apiKey: currentApiKeys.moonpay,
            currencyCode: targetToken === 0 ? 'eth' : targetToken === 1 ? 'usdc' : 'sonic',
            baseCurrencyCode: 'usd',
            baseCurrencyAmount: fiatAmount,
            walletAddress: userAddress,
        },
        timeout: 10000
    });
    return response.data;
}

async function initiateYellowCardOffRamp(cryptoAmount, sourceToken, bankDetails, userAddress) {
    const response = await axios.post('https://api.yellowcard.io/v1/offramp', {
        amount: cryptoAmount,
        currency: sourceToken === 0 ? 'ETH' : sourceToken === 1 ? 'USDC' : 'SONIC',
        bankDetails,
        walletAddress: userAddress,
        apiKey: currentApiKeys.yellowcard,
    }, { timeout: 10000 });
    return response.data;
}

async function initiateMoonPayOffRamp(cryptoAmount, sourceToken, bankDetails, userAddress) {
    const response = await axios.post('https://api.moonpay.com/v3/sell/quote', {
        apiKey: currentApiKeys.moonpay,
        currencyCode: sourceToken === 0 ? 'eth' : sourceToken === 1 ? 'usdc' : 'sonic',
        baseCurrencyAmount: cryptoAmount,
        bankDetails,
        walletAddress: userAddress,
    }, { timeout: 10000 });
    return response.data;
}

// Health Check
app.get('/health', async (req, res) => {
    const end = httpRequestDuration.startTimer({ method: 'GET', route: '/health' });
    try {
        const redisStatus = await redisClient.ping();
        res.json({
            status: 'healthy',
            uptime: process.uptime(),
            timestamp: new Date().toISOString(),
            mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
            redis: redisStatus === 'PONG' ? 'connected' : 'disconnected'
        });
    } catch (error) {
        res.status(503).json({ status: 'unhealthy', error: error.message });
    }
    end({ status: '200' });
});

// Metrics
app.get('/metrics', async (req, res) => {
    res.set('Content-Type', register.contentType);
    res.end(await register.metrics());
});

// API Routes with Swagger Docs
/**
 * @swagger
 * /login:
 *   post:
 *     summary: Authenticate a user
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LoginRequest'
 *     responses:
 *       200:
 *         description: Successful login
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/LoginResponse'
 *       400:
 *         description: Validation error
 *       401:
 *         description: Authentication failed
 */
app.post('/login', validate([
    body('address').isEthereumAddress(),
    body('signature').notEmpty(),
    body('message').notEmpty(),
]), async (req, res, next) => {
    const end = httpRequestDuration.startTimer({ method: 'POST', route: '/login' });
    const { address, signature, message } = req.body;
    try {
        const recoveredAddress = ethers.utils.verifyMessage(message, signature);
        if (recoveredAddress.toLowerCase() !== address.toLowerCase()) throw new AuthenticationError('Invalid signature');
        let user = await User.findOne({ address: sanitizeMongo(address) });
        if (!user) {
            user = new User({ address });
            await user.save();
        }
        const token = jwt.sign({ address, role: user.role }, env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token, role: user.role, csrfToken: req.csrfToken() });
        end({ status: '200' });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /book-appointment:
 *   post:
 *     summary: Book a doctor appointment
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
 *               doctorAddress: { type: 'string', description: 'Doctor Ethereum address' }
 *               timestamp: { type: 'integer', description: 'Unix timestamp' }
 *               paymentType: { type: 'integer', enum: [0, 1, 2], description: '0: ETH, 1: USDC, 2: SONIC' }
 *               isVideoCall: { type: 'boolean', description: 'Video call flag' }
 *               videoCallLink: { type: 'string', description: 'Video call URL (optional)' }
 *             required: ['doctorAddress', 'timestamp', 'paymentType', 'isVideoCall']
 *     responses:
 *       200:
 *         description: Appointment booked
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 jobId: { type: 'string', description: 'Queue job ID' }
 *       403:
 *         description: Patient role required
 */
app.post('/book-appointment', authMiddleware, validate([
    body('doctorAddress').isEthereumAddress(),
    body('timestamp').isInt({ min: Math.floor(Date.now() / 1000) }),
    body('paymentType').isInt({ min: 0, max: 2 }),
    body('isVideoCall').isBoolean(),
    body('videoCallLink').optional().isURL(),
]), async (req, res, next) => {
    const end = httpRequestDuration.startTimer({ method: 'POST', route: '/book-appointment' });
    const { doctorAddress, timestamp, paymentType, isVideoCall, videoCallLink } = req.body;
    try {
        if (req.user.role !== 'patient') throw new AuthorizationError('Patient role required');
        const callData = medicalContract.interface.encodeFunctionData('bookAppointment', [
            doctorAddress, timestamp, paymentType, isVideoCall, videoCallLink || ''
        ]);
        const userOp = await createUserOperation(req.user.address, callData, {
            to: medicalContract.address,
            value: paymentType === 0 ? ethers.utils.parseEther(req.body.amount || '0') : 0,
            sponsorType: paymentType,
        });
        const job = await userOpQueue.add({ userOp });
        await redisPub.publish('appointment', JSON.stringify({ address: req.user.address, jobId: job.id }));
        res.json({ jobId: job.id });
        end({ status: '200' });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /register:
 *   post:
 *     summary: Register a new user with a specific role
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               address: { type: 'string', description: 'Ethereum address' }
 *               role: { type: 'string', enum: ['patient', 'doctor', 'labTech', 'pharmacy', 'admin'], description: 'User role' }
 *               signature: { type: 'string', description: 'Signed message' }
 *               message: { type: 'string', description: 'Message to sign' }
 *             required: ['address', 'role', 'signature', 'message']
 *     responses:
 *       200:
 *         description: User registered successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token: { type: 'string', description: 'JWT token' }
 *                 role: { type: 'string', description: 'User role' }
 *                 csrfToken: { type: 'string', description: 'CSRF token' }
 *       400:
 *         description: Validation error or user already exists
 *       401:
 *         description: Authentication failed
 */
app.post('/register', validate([
    body('address').isEthereumAddress(),
    body('role').isIn(['patient', 'doctor', 'labTech', 'pharmacy', 'admin']),
    body('signature').notEmpty(),
    body('message').notEmpty(),
]), async (req, res, next) => {
    const end = httpRequestDuration.startTimer({ method: 'POST', route: '/register' });
    const { address, role, signature, message } = req.body;
    try {
        const recoveredAddress = ethers.utils.verifyMessage(message, signature);
        if (recoveredAddress.toLowerCase() !== address.toLowerCase()) throw new AuthenticationError('Invalid signature');
        let user = await User.findOne({ address: sanitizeMongo(address) });
        if (user) throw new ValidationError('User already exists');
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

        res.json({ token, role, csrfToken: req.csrfToken() });
        end({ status: '200' });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /validate-token:
 *   post:
 *     summary: Validate a JWT token and return user info
 *     tags: [Authentication]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Token validated
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 address: { type: 'string', description: 'User Ethereum address' }
 *                 role: { type: 'string', description: 'User role' }
 *       401:
 *         description: Authentication failed
 *       404:
 *         description: User not found
 */
app.post('/validate-token', authMiddleware, async (req, res, next) => {
    const end = httpRequestDuration.startTimer({ method: 'POST', route: '/validate-token' });
    try {
        const user = await User.findOne({ address: sanitizeMongo(req.user.address) });
        if (!user) throw new NotFoundError('User not found');
        res.json({ address: user.address, role: user.role });
        end({ status: '200' });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /register-patient:
 *   post:
 *     summary: Register a patient on the blockchain
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
 *               encryptedSymmetricKey: { type: 'string', description: 'Encrypted symmetric key for patient data' }
 *             required: ['encryptedSymmetricKey']
 *     responses:
 *       200:
 *         description: Patient registration queued
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 jobId: { type: 'string', description: 'Queue job ID' }
 *       403:
 *         description: Patient role required
 */
app.post('/register-patient', authMiddleware, validate([
    body('encryptedSymmetricKey').notEmpty().isString(),
]), async (req, res, next) => {
    const end = httpRequestDuration.startTimer({ method: 'POST', route: '/register-patient' });
    try {
        if (req.user.role !== 'patient') throw new AuthorizationError('Patient role required');
        const callData = coreContract.interface.encodeFunctionData('registerPatient', [req.body.encryptedSymmetricKey]);
        const salt = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(req.user.address + Date.now().toString()));
        const accountAddr = await accountFactoryContract.getAddress(req.user.address, salt);
        const userOp = await createUserOperation(accountAddr, callData);
        const job = await userOpQueue.add({ userOp });
        res.json({ jobId: job.id });
        end({ status: '200' });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /verify-doctor:
 *   post:
 *     summary: Verify a doctor with license and fee
 *     tags: [Admin]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               doctorAddress: { type: 'string', description: 'Doctor Ethereum address' }
 *               licenseNumber: { type: 'string', description: 'Doctor license number' }
 *               fee: { type: 'number', description: 'Consultation fee in ETH' }
 *             required: ['doctorAddress', 'licenseNumber', 'fee']
 *     responses:
 *       200:
 *         description: Doctor verification queued
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 jobId: { type: 'string', description: 'Queue job ID' }
 *       403:
 *         description: Admin access required
 */
app.post('/verify-doctor', authMiddleware, validate([
    body('doctorAddress').isEthereumAddress(),
    body('licenseNumber').notEmpty().isString(),
    body('fee').isNumeric(),
]), async (req, res, next) => {
    const end = httpRequestDuration.startTimer({ method: 'POST', route: '/verify-doctor' });
    const { doctorAddress, licenseNumber, fee } = req.body;
    try {
        if (req.user.role !== 'admin') throw new AuthorizationError('Admin access required');
        const callData = coreContract.interface.encodeFunctionData('verifyDoctor', [doctorAddress, licenseNumber, ethers.utils.parseEther(fee)]);
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });
        await User.findOneAndUpdate({ address: sanitizeMongo(doctorAddress) }, { role: 'doctor' }, { upsert: true });
        res.json({ jobId: job.id });
        end({ status: '200' });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /verify-lab-technician:
 *   post:
 *     summary: Verify a lab technician with license
 *     tags: [Admin]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               labTechAddress: { type: 'string', description: 'Lab technician Ethereum address' }
 *               licenseNumber: { type: 'string', description: 'Lab technician license number' }
 *             required: ['labTechAddress', 'licenseNumber']
 *     responses:
 *       200:
 *         description: Lab technician verification queued
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 jobId: { type: 'string', description: 'Queue job ID' }
 *       403:
 *         description: Admin access required
 */
app.post('/verify-lab-technician', authMiddleware, validate([
    body('labTechAddress').isEthereumAddress(),
    body('licenseNumber').notEmpty().isString(),
]), async (req, res, next) => {
    const end = httpRequestDuration.startTimer({ method: 'POST', route: '/verify-lab-technician' });
    const { labTechAddress, licenseNumber } = req.body;
    try {
        if (req.user.role !== 'admin') throw new AuthorizationError('Admin access required');
        const callData = coreContract.interface.encodeFunctionData('verifyLabTechnician', [labTechAddress, licenseNumber]);
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });
        await User.findOneAndUpdate({ address: sanitizeMongo(labTechAddress) }, { role: 'labTech' }, { upsert: true });
        res.json({ jobId: job.id });
        end({ status: '200' });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /register-pharmacy:
 *   post:
 *     summary: Register a pharmacy with registration number
 *     tags: [Admin]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               pharmacyAddress: { type: 'string', description: 'Pharmacy Ethereum address' }
 *               registrationNumber: { type: 'string', description: 'Pharmacy registration number' }
 *             required: ['pharmacyAddress', 'registrationNumber']
 *     responses:
 *       200:
 *         description: Pharmacy registration queued
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 jobId: { type: 'string', description: 'Queue job ID' }
 *       403:
 *         description: Admin access required
 */
app.post('/register-pharmacy', authMiddleware, validate([
    body('pharmacyAddress').isEthereumAddress(),
    body('registrationNumber').notEmpty().isString(),
]), async (req, res, next) => {
    const end = httpRequestDuration.startTimer({ method: 'POST', route: '/register-pharmacy' });
    const { pharmacyAddress, registrationNumber } = req.body;
    try {
        if (req.user.role !== 'admin') throw new AuthorizationError('Admin access required');
        const callData = coreContract.interface.encodeFunctionData('registerPharmacy', [pharmacyAddress, registrationNumber]);
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });
        await User.findOneAndUpdate({ address: sanitizeMongo(pharmacyAddress) }, { role: 'pharmacy' }, { upsert: true });
        res.json({ jobId: job.id });
        end({ status: '200' });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /confirm-appointment:
 *   post:
 *     summary: Confirm an appointment as a doctor
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
 *               appointmentId: { type: 'integer', description: 'Appointment ID' }
 *               overridePriority: { type: 'boolean', description: 'Override priority flag (optional)' }
 *             required: ['appointmentId']
 *     responses:
 *       200:
 *         description: Appointment confirmation queued
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 jobId: { type: 'string', description: 'Queue job ID' }
 *       403:
 *         description: Doctor role required
 */
app.post('/confirm-appointment', authMiddleware, validate([
    body('appointmentId').isInt({ min: 1 }),
    body('overridePriority').optional().isBoolean(),
]), async (req, res, next) => {
    const end = httpRequestDuration.startTimer({ method: 'POST', route: '/confirm-appointment' });
    const { appointmentId, overridePriority } = req.body;
    try {
        if (req.user.role !== 'doctor') throw new AuthorizationError('Doctor role required');
        const callData = medicalContract.interface.encodeFunctionData('confirmAppointment', [appointmentId, overridePriority || false]);
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });
        await redisPub.publish('appointmentConfirmed', JSON.stringify({ id: appointmentId, jobId: job.id }));
        res.json({ jobId: job.id });
        end({ status: '200' });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /batch-confirm-appointments:
 *   post:
 *     summary: Batch confirm multiple appointments
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
 *               appointmentIds: { type: 'array', items: { type: 'integer' }, description: 'List of appointment IDs' }
 *             required: ['appointmentIds']
 *     responses:
 *       200:
 *         description: Batch confirmation queued
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 jobId: { type: 'string', description: 'Queue job ID' }
 *       403:
 *         description: Doctor role required
 */
app.post('/batch-confirm-appointments', authMiddleware, validate([
    body('appointmentIds').isArray().notEmpty(),
]), async (req, res, next) => {
    const end = httpRequestDuration.startTimer({ method: 'POST', route: '/batch-confirm-appointments' });
    const { appointmentIds } = req.body;
    try {
        if (req.user.role !== 'doctor') throw new AuthorizationError('Doctor role required');
        const callData = medicalContract.interface.encodeFunctionData('batchConfirmAppointments', [appointmentIds]);
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });
        await redisPub.publish('batchAppointmentsConfirmed', JSON.stringify({ ids: appointmentIds, jobId: job.id }));
        res.json({ jobId: job.id });
        end({ status: '200' });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /complete-appointment:
 *   post:
 *     summary: Complete an appointment with summary
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
 *               appointmentId: { type: 'integer', description: 'Appointment ID' }
 *               ipfsSummary: { type: 'string', description: 'IPFS hash of appointment summary' }
 *             required: ['appointmentId', 'ipfsSummary']
 *     responses:
 *       200:
 *         description: Appointment completion queued
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 jobId: { type: 'string', description: 'Queue job ID' }
 *       403:
 *         description: Doctor role required
 */
app.post('/complete-appointment', authMiddleware, validate([
    body('appointmentId').isInt({ min: 1 }),
    body('ipfsSummary').notEmpty().isString(),
]), async (req, res, next) => {
    const end = httpRequestDuration.startTimer({ method: 'POST', route: '/complete-appointment' });
    const { appointmentId, ipfsSummary } = req.body;
    try {
        if (req.user.role !== 'doctor') throw new AuthorizationError('Doctor role required');
        const callData = medicalContract.interface.encodeFunctionData('completeAppointment', [appointmentId, ipfsSummary]);
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });
        await redisPub.publish('appointmentCompleted', JSON.stringify({ id: appointmentId, jobId: job.id }));
        res.json({ jobId: job.id });
        end({ status: '200' });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /cancel-appointment:
 *   post:
 *     summary: Cancel an appointment
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
 *               appointmentId: { type: 'integer', description: 'Appointment ID' }
 *             required: ['appointmentId']
 *     responses:
 *       200:
 *         description: Appointment cancellation queued
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 jobId: { type: 'string', description: 'Queue job ID' }
 *       403:
 *         description: Patient role required
 */
app.post('/cancel-appointment', authMiddleware, validate([
    body('appointmentId').isInt({ min: 1 }),
]), async (req, res, next) => {
    const end = httpRequestDuration.startTimer({ method: 'POST', route: '/cancel-appointment' });
    const { appointmentId } = req.body;
    try {
        if (req.user.role !== 'patient') throw new AuthorizationError('Patient role required');
        const callData = medicalContract.interface.encodeFunctionData('cancelAppointment', [appointmentId]);
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });
        await redisPub.publish('appointmentCancelled', JSON.stringify({ address: req.user.address, id: appointmentId, jobId: job.id }));
        res.json({ jobId: job.id });
        end({ status: '200' });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /reschedule-appointment:
 *   post:
 *     summary: Reschedule an appointment
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
 *               appointmentId: { type: 'integer', description: 'Appointment ID' }
 *               newTimestamp: { type: 'integer', description: 'New Unix timestamp' }
 *             required: ['appointmentId', 'newTimestamp']
 *     responses:
 *       200:
 *         description: Appointment rescheduling queued
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 jobId: { type: 'string', description: 'Queue job ID' }
 *       403:
 *         description: Patient role required
 */
app.post('/reschedule-appointment', authMiddleware, validate([
    body('appointmentId').isInt({ min: 1 }),
    body('newTimestamp').isInt({ min: Math.floor(Date.now() / 1000) }),
]), async (req, res, next) => {
    const end = httpRequestDuration.startTimer({ method: 'POST', route: '/reschedule-appointment' });
    const { appointmentId, newTimestamp } = req.body;
    try {
        if (req.user.role !== 'patient') throw new AuthorizationError('Patient role required');
        const callData = medicalContract.interface.encodeFunctionData('rescheduleAppointment', [appointmentId, newTimestamp]);
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });
        await redisPub.publish('appointmentRescheduled', JSON.stringify({ address: req.user.address, id: appointmentId, newTimestamp, jobId: job.id }));
        res.json({ jobId: job.id });
        end({ status: '200' });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /analyze-symptoms:
 *   post:
 *     summary: Request AI symptom analysis
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
 *               symptoms: { type: 'string', description: 'Comma-separated list of symptoms' }
 *             required: ['symptoms']
 *     responses:
 *       200:
 *         description: Symptom analysis queued
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 jobId: { type: 'string', description: 'Queue job ID' }
 *                 ipfsHash: { type: 'string', description: 'IPFS hash of analysis result' }
 *       403:
 *         description: Patient role required
 */
app.post('/analyze-symptoms', authMiddleware, validate([
    body('symptoms').notEmpty().isString(),
]), async (req, res, next) => {
    const end = httpRequestDuration.startTimer({ method: 'POST', route: '/analyze-symptoms' });
    const { symptoms } = req.body;
    try {
        if (req.user.role !== 'patient') throw new AuthorizationError('Patient role required');
        const job = await aiQueue.add({ symptoms });
        const analysis = await job.finished();
        const ipfsResult = await ipfs.add(JSON.stringify(analysis));
        const callData = medicalContract.interface.encodeFunctionData('requestAISymptomAnalysis', [symptoms]);
        const userOp = await createUserOperation(req.user.address, callData);
        const userOpJob = await userOpQueue.add({ userOp });
        res.json({ jobId: userOpJob.id, ipfsHash: ipfsResult.path });
        end({ status: '200' });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /review-ai-analysis:
 *   post:
 *     summary: Review AI symptom analysis as a doctor
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
 *               aiAnalysisId: { type: 'integer', description: 'AI analysis ID' }
 *               analysisIpfsHash: { type: 'string', description: 'IPFS hash of analysis review' }
 *             required: ['aiAnalysisId', 'analysisIpfsHash']
 *     responses:
 *       200:
 *         description: AI analysis review queued
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 jobId: { type: 'string', description: 'Queue job ID' }
 *       403:
 *         description: Doctor role required
 */
app.post('/review-ai-analysis', authMiddleware, validate([
    body('aiAnalysisId').isInt({ min: 1 }),
    body('analysisIpfsHash').notEmpty().isString(),
]), async (req, res, next) => {
    const end = httpRequestDuration.startTimer({ method: 'POST', route: '/review-ai-analysis' });
    const { aiAnalysisId, analysisIpfsHash } = req.body;
    try {
        if (req.user.role !== 'doctor') throw new AuthorizationError('Doctor role required');
        const callData = medicalContract.interface.encodeFunctionData('reviewAISymptomAnalysis', [aiAnalysisId, analysisIpfsHash]);
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });
        res.json({ jobId: job.id });
        end({ status: '200' });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /order-lab-test:
 *   post:
 *     summary: Order a lab test for a patient
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
 *               patientAddress: { type: 'string', description: 'Patient Ethereum address' }
 *               testType: { type: 'string', description: 'Type of lab test' }
 *             required: ['patientAddress', 'testType']
 *     responses:
 *       200:
 *         description: Lab test order queued
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 jobId: { type: 'string', description: 'Queue job ID' }
 *       403:
 *         description: Doctor role required
 */
app.post('/order-lab-test', authMiddleware, validate([
    body('patientAddress').isEthereumAddress(),
    body('testType').notEmpty().isString(),
]), async (req, res, next) => {
    const end = httpRequestDuration.startTimer({ method: 'POST', route: '/order-lab-test' });
    const { patientAddress, testType } = req.body;
    try {
        if (req.user.role !== 'doctor') throw new AuthorizationError('Doctor role required');
        const callData = medicalContract.interface.encodeFunctionData('orderLabTest', [patientAddress, testType]);
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });
        res.json({ jobId: job.id });
        end({ status: '200' });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /collect-sample:
 *   post:
 *     summary: Collect a sample for a lab test
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
 *               labTestId: { type: 'integer', description: 'Lab test ID' }
 *               sampleIpfsHash: { type: 'string', description: 'IPFS hash of sample data' }
 *             required: ['labTestId', 'sampleIpfsHash']
 *     responses:
 *       200:
 *         description: Sample collection queued
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 jobId: { type: 'string', description: 'Queue job ID' }
 *       403:
 *         description: LabTech role required
 */
app.post('/collect-sample', authMiddleware, validate([
    body('labTestId').isInt({ min: 1 }),
    body('sampleIpfsHash').notEmpty().isString(),
]), async (req, res, next) => {
    const end = httpRequestDuration.startTimer({ method: 'POST', route: '/collect-sample' });
    const { labTestId, sampleIpfsHash } = req.body;
    try {
        if (req.user.role !== 'labTech') throw new AuthorizationError('LabTech role required');
        const callData = medicalContract.interface.encodeFunctionData('collectSample', [labTestId, sampleIpfsHash]);
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });
        res.json({ jobId: job.id });
        end({ status: '200' });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /upload-lab-results:
 *   post:
 *     summary: Upload lab test results
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
 *               labTestId: { type: 'integer', description: 'Lab test ID' }
 *               resultsIpfsHash: { type: 'string', description: 'IPFS hash of lab results' }
 *             required: ['labTestId', 'resultsIpfsHash']
 *     responses:
 *       200:
 *         description: Lab results upload queued
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 jobId: { type: 'string', description: 'Queue job ID' }
 *       403:
 *         description: LabTech role required
 */
app.post('/upload-lab-results', authMiddleware, validate([
    body('labTestId').isInt({ min: 1 }),
    body('resultsIpfsHash').notEmpty().isString(),
]), async (req, res, next) => {
    const end = httpRequestDuration.startTimer({ method: 'POST', route: '/upload-lab-results' });
    const { labTestId, resultsIpfsHash } = req.body;
    try {
        if (req.user.role !== 'labTech') throw new AuthorizationError('LabTech role required');
        const callData = medicalContract.interface.encodeFunctionData('uploadLabResults', [labTestId, resultsIpfsHash]);
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });
        res.json({ jobId: job.id });
        end({ status: '200' });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /review-lab-results:
 *   post:
 *     summary: Review lab results and issue prescription
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
 *               labTestId: { type: 'integer', description: 'Lab test ID' }
 *               medicationDetails: { type: 'string', description: 'Medication details' }
 *               prescriptionIpfsHash: { type: 'string', description: 'IPFS hash of prescription' }
 *             required: ['labTestId', 'medicationDetails', 'prescriptionIpfsHash']
 *     responses:
 *       200:
 *         description: Lab results review queued
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 jobId: { type: 'string', description: 'Queue job ID' }
 *       403:
 *         description: Doctor role required
 */
app.post('/review-lab-results', authMiddleware, validate([
    body('labTestId').isInt({ min: 1 }),
    body('medicationDetails').notEmpty().isString(),
    body('prescriptionIpfsHash').notEmpty().isString(),
]), async (req, res, next) => {
    const end = httpRequestDuration.startTimer({ method: 'POST', route: '/review-lab-results' });
    const { labTestId, medicationDetails, prescriptionIpfsHash } = req.body;
    try {
        if (req.user.role !== 'doctor') throw new AuthorizationError('Doctor role required');
        const callData = medicalContract.interface.encodeFunctionData('reviewLabResults', [labTestId, medicationDetails, prescriptionIpfsHash]);
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });
        res.json({ jobId: job.id });
        end({ status: '200' });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /verify-prescription:
 *   post:
 *     summary: Verify a prescription
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
 *               prescriptionId: { type: 'integer', description: 'Prescription ID' }
 *               verificationCodeHash: { type: 'string', description: 'Hash of verification code' }
 *             required: ['prescriptionId', 'verificationCodeHash']
 *     responses:
 *       200:
 *         description: Prescription verification queued
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 jobId: { type: 'string', description: 'Queue job ID' }
 *       403:
 *         description: Pharmacy role required
 */
app.post('/verify-prescription', authMiddleware, validate([
    body('prescriptionId').isInt({ min: 1 }),
    body('verificationCodeHash').notEmpty().isString(),
]), async (req, res, next) => {
    const end = httpRequestDuration.startTimer({ method: 'POST', route: '/verify-prescription' });
    const { prescriptionId, verificationCodeHash } = req.body;
    try {
        if (req.user.role !== 'pharmacy') throw new AuthorizationError('Pharmacy role required');
        const callData = medicalContract.interface.encodeFunctionData('verifyPrescription', [prescriptionId, ethers.utils.hexlify(verificationCodeHash)]);
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });
        res.json({ jobId: job.id });
        end({ status: '200' });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /fulfill-prescription:
 *   post:
 *     summary: Fulfill a prescription
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
 *               prescriptionId: { type: 'integer', description: 'Prescription ID' }
 *             required: ['prescriptionId']
 *     responses:
 *       200:
 *         description: Prescription fulfillment queued
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 jobId: { type: 'string', description: 'Queue job ID' }
 *       403:
 *         description: Pharmacy role required
 */
app.post('/fulfill-prescription', authMiddleware, validate([
    body('prescriptionId').isInt({ min: 1 }),
]), async (req, res, next) => {
    const end = httpRequestDuration.startTimer({ method: 'POST', route: '/fulfill-prescription' });
    const { prescriptionId } = req.body;
    try {
        if (req.user.role !== 'pharmacy') throw new AuthorizationError('Pharmacy role required');
        const callData = medicalContract.interface.encodeFunctionData('fulfillPrescription', [prescriptionId]);
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });
        res.json({ jobId: job.id });
        end({ status: '200' });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /toggle-data-monetization:
 *   post:
 *     summary: Toggle data monetization preference
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
 *               enable: { type: 'boolean', description: 'Enable or disable data monetization' }
 *             required: ['enable']
 *     responses:
 *       200:
 *         description: Data monetization toggle queued
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 jobId: { type: 'string', description: 'Queue job ID' }
 */
app.post('/toggle-data-monetization', authMiddleware, validate([
    body('enable').isBoolean(),
]), async (req, res, next) => {
    const end = httpRequestDuration.startTimer({ method: 'POST', route: '/toggle-data-monetization' });
    const { enable } = req.body;
    try {
        const callData = coreContract.interface.encodeFunctionData('toggleDataMonetization', [enable]);
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });
        res.json({ jobId: job.id });
        end({ status: '200' });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /claim-data-reward:
 *   post:
 *     summary: Claim data monetization reward
 *     tags: [Medical]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Data reward claim queued
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 jobId: { type: 'string', description: 'Queue job ID' }
 */
app.post('/claim-data-reward', authMiddleware, async (req, res, next) => {
    const end = httpRequestDuration.startTimer({ method: 'POST', route: '/claim-data-reward' });
    try {
        const callData = coreContract.interface.encodeFunctionData('claimDataReward');
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });
        res.json({ jobId: job.id });
        end({ status: '200' });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /deposit-ai-fund:
 *   post:
 *     summary: Deposit into AI analysis fund
 *     tags: [Payments]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               amount: { type: 'number', description: 'Amount in ETH' }
 *             required: ['amount']
 *     responses:
 *       200:
 *         description: AI fund deposit queued
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 jobId: { type: 'string', description: 'Queue job ID' }
 */
app.post('/deposit-ai-fund', authMiddleware, validate([
    body('amount').isNumeric({ min: 0 }),
]), async (req, res, next) => {
    const end = httpRequestDuration.startTimer({ method: 'POST', route: '/deposit-ai-fund' });
    const { amount } = req.body;
    try {
        const callData = paymentsContract.interface.encodeFunctionData('deposit', [coreContract.address, ethers.utils.parseEther(amount)]);
        const userOp = await createUserOperation(req.user.address, callData, {
            to: paymentsContract.address,
            value: ethers.utils.parseEther(amount),
        });
        const job = await userOpQueue.add({ userOp });
        res.json({ jobId: job.id });
        end({ status: '200' });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /deposit-reserve-fund:
 *   post:
 *     summary: Deposit into reserve fund
 *     tags: [Payments]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               amount: { type: 'number', description: 'Amount in ETH' }
 *             required: ['amount']
 *     responses:
 *       200:
 *         description: Reserve fund deposit queued
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 jobId: { type: 'string', description: 'Queue job ID' }
 */
app.post('/deposit-reserve-fund', authMiddleware, validate([
    body('amount').isNumeric({ min: 0 }),
]), async (req, res, next) => {
    const end = httpRequestDuration.startTimer({ method: 'POST', route: '/deposit-reserve-fund' });
    const { amount } = req.body;
    try {
        const callData = paymentsContract.interface.encodeFunctionData('deposit', [coreContract.address, ethers.utils.parseEther(amount)]);
        const userOp = await createUserOperation(req.user.address, callData, {
            to: paymentsContract.address,
            value: ethers.utils.parseEther(amount),
        });
        const job = await userOpQueue.add({ userOp });
        res.json({ jobId: job.id });
        end({ status: '200' });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /paymaster-deposit:
 *   post:
 *     summary: Deposit into paymaster for gas sponsorship
 *     tags: [Payments]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               amount: { type: 'number', description: 'Amount in ETH' }
 *               sponsorType: { type: 'integer', enum: [0, 1, 2], description: '0: ETH, 1: USDC, 2: SONIC' }
 *             required: ['amount', 'sponsorType']
 *     responses:
 *       200:
 *         description: Paymaster deposit queued
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 jobId: { type: 'string', description: 'Queue job ID' }
 */
app.post('/paymaster-deposit', authMiddleware, validate([
    body('amount').isNumeric({ min: 0 }),
    body('sponsorType').isInt({ min: 0, max: 2 }),
]), async (req, res, next) => {
    const end = httpRequestDuration.startTimer({ method: 'POST', route: '/paymaster-deposit' });
    const { amount, sponsorType } = req.body;
    try {
        const callData = paymasterContract.interface.encodeFunctionData('deposit', [sponsorType, ethers.utils.parseEther(amount)]);
        const userOp = await createUserOperation(req.user.address, callData, {
            to: paymasterContract.address,
            value: sponsorType === 0 ? ethers.utils.parseEther(amount) : 0,
        });
        const job = await userOpQueue.add({ userOp });
        res.json({ jobId: job.id });
        end({ status: '200' });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /subscribe:
 *   post:
 *     summary: Subscribe to a plan
 *     tags: [Payments]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               plan: { type: 'integer', enum: [0, 1], description: '0: Basic (0.01 ETH), 1: Premium (0.05 ETH)' }
 *             required: ['plan']
 *     responses:
 *       200:
 *         description: Subscription queued
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 jobId: { type: 'string', description: 'Queue job ID' }
 */
app.post('/subscribe', authMiddleware, validate([
    body('plan').isInt({ min: 0, max: 1 }),
]), async (req, res, next) => {
    const end = httpRequestDuration.startTimer({ method: 'POST', route: '/subscribe' });
    const { plan } = req.body;
    try {
        const callData = subscriptionContract.interface.encodeFunctionData('subscribe', [plan]);
        const userOp = await createUserOperation(req.user.address, callData, {
            to: subscriptionContract.address,
            value: ethers.utils.parseEther(plan === 0 ? '0.01' : '0.05'),
        });
        const job = await userOpQueue.add({ userOp });
        res.json({ jobId: job.id });
        end({ status: '200' });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /queue-withdraw-funds:
 *   post:
 *     summary: Queue a fund withdrawal (timelock)
 *     tags: [Governance]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               to: { type: 'string', description: 'Recipient Ethereum address' }
 *               amount: { type: 'number', description: 'Amount in ETH' }
 *             required: ['to', 'amount']
 *     responses:
 *       200:
 *         description: Fund withdrawal queued
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 jobId: { type: 'string', description: 'Queue job ID' }
 *                 timeLockId: { type: 'integer', description: 'Timelock ID' }
 *       403:
 *         description: Admin access required
 */
app.post('/queue-withdraw-funds', authMiddleware, validate([
    body('to').isEthereumAddress(),
    body('amount').isNumeric({ min: 0 }),
]), async (req, res, next) => {
    const end = httpRequestDuration.startTimer({ method: 'POST', route: '/queue-withdraw-funds' });
    const { to, amount } = req.body;
    try {
        if (req.user.role !== 'admin') throw new AuthorizationError('Admin access required');
        const callData = governanceContract.interface.encodeFunctionData('queueWithdrawFunds', [to, ethers.utils.parseEther(amount)]);
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });

        const timeLockId = (await TimeLock.countDocuments()) + 1;
        await TimeLock.create({
            id: timeLockId,
            action: 0,
            target: sanitizeMongo(to),
            value: ethers.utils.parseEther(amount).toString(),
            data: callData,
            timestamp: Math.floor(Date.now() / 1000),
            approvals: [req.user.address],
        });

        res.json({ jobId: job.id, timeLockId });
        end({ status: '200' });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /queue-add-admin:
 *   post:
 *     summary: Queue adding a new admin (timelock)
 *     tags: [Governance]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               newAdmin: { type: 'string', description: 'New admin Ethereum address' }
 *             required: ['newAdmin']
 *     responses:
 *       200:
 *         description: Admin addition queued
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 jobId: { type: 'string', description: 'Queue job ID' }
 *                 timeLockId: { type: 'integer', description: 'Timelock ID' }
 *       403:
 *         description: Admin access required
 */
app.post('/queue-add-admin', authMiddleware, validate([
    body('newAdmin').isEthereumAddress(),
]), async (req, res, next) => {
    const end = httpRequestDuration.startTimer({ method: 'POST', route: '/queue-add-admin' });
    const { newAdmin } = req.body;
    try {
        if (req.user.role !== 'admin') throw new AuthorizationError('Admin access required');
        const callData = governanceContract.interface.encodeFunctionData('queueAddAdmin', [newAdmin]);
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });

        const timeLockId = (await TimeLock.countDocuments()) + 1;
        await TimeLock.create({
            id: timeLockId,
            action: 1,
            target: sanitizeMongo(newAdmin),
            value: '0',
            data: callData,
            timestamp: Math.floor(Date.now() / 1000),
            approvals: [req.user.address],
        });

        res.json({ jobId: job.id, timeLockId });
        end({ status: '200' });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /approve-timelock:
 *   post:
 *     summary: Approve a timelock action
 *     tags: [Governance]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               timeLockId: { type: 'integer', description: 'Timelock ID' }
 *             required: ['timeLockId']
 *     responses:
 *       200:
 *         description: Timelock approval queued
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 jobId: { type: 'string', description: 'Queue job ID' }
 *       403:
 *         description: Admin access required
 *       404:
 *         description: Timelock not found
 */
app.post('/approve-timelock', authMiddleware, validate([
    body('timeLockId').isInt({ min: 1 }),
]), async (req, res, next) => {
    const end = httpRequestDuration.startTimer({ method: 'POST', route: '/approve-timelock' });
    const { timeLockId } = req.body;
    try {
        if (req.user.role !== 'admin') throw new AuthorizationError('Admin access required');
        const callData = governanceContract.interface.encodeFunctionData('approveTimeLock', [timeLockId]);
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });

        const timeLock = await TimeLock.findOne({ id: sanitizeMongo(timeLockId) });
        if (!timeLock) throw new NotFoundError('TimeLock not found');
        if (!timeLock.approvals.includes(req.user.address)) {
            timeLock.approvals.push(req.user.address);
            timeLock.approvalCount += 1;
            await timeLock.save();
        }

        res.json({ jobId: job.id });
        end({ status: '200' });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /execute-timelock:
 *   post:
 *     summary: Execute a timelock action
 *     tags: [Governance]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               timeLockId: { type: 'integer', description: 'Timelock ID' }
 *             required: ['timeLockId']
 *     responses:
 *       200:
 *         description: Timelock execution queued
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 jobId: { type: 'string', description: 'Queue job ID' }
 *       403:
 *         description: Admin access required
 *       404:
 *         description: Timelock not found
 */
app.post('/execute-timelock', authMiddleware, validate([
    body('timeLockId').isInt({ min: 1 }),
]), async (req, res, next) => {
    const end = httpRequestDuration.startTimer({ method: 'POST', route: '/execute-timelock' });
    const { timeLockId } = req.body;
    try {
        if (req.user.role !== 'admin') throw new AuthorizationError('Admin access required');
        const callData = governanceContract.interface.encodeFunctionData('executeTimeLock', [timeLockId]);
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });

        const timeLock = await TimeLock.findOne({ id: sanitizeMongo(timeLockId) });
        if (!timeLock) throw new NotFoundError('TimeLock not found');
        timeLock.executed = true;
        await timeLock.save();

        res.json({ jobId: job.id });
        end({ status: '200' });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /emergency-pause:
 *   post:
 *     summary: Trigger an emergency pause
 *     tags: [Emergency]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Emergency pause queued
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 jobId: { type: 'string', description: 'Queue job ID' }
 *       403:
 *         description: Admin access required
 */
app.post('/emergency-pause', authMiddleware, async (req, res, next) => {
    const end = httpRequestDuration.startTimer({ method: 'POST', route: '/emergency-pause' });
    try {
        if (req.user.role !== 'admin') throw new AuthorizationError('Admin access required');
        const callData = emergencyContract.interface.encodeFunctionData('emergencyPause');
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });
        res.json({ jobId: job.id });
        end({ status: '200' });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /request-emergency-unpause:
 *   post:
 *     summary: Request an emergency unpause
 *     tags: [Emergency]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Emergency unpause request queued
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 jobId: { type: 'string', description: 'Queue job ID' }
 *       403:
 *         description: Admin access required
 */
app.post('/request-emergency-unpause', authMiddleware, async (req, res, next) => {
    const end = httpRequestDuration.startTimer({ method: 'POST', route: '/request-emergency-unpause' });
    try {
        if (req.user.role !== 'admin') throw new AuthorizationError('Admin access required');
        const callData = emergencyContract.interface.encodeFunctionData('requestEmergencyUnpause');
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });
        res.json({ jobId: job.id });
        end({ status: '200' });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /request-onramp:
 *   post:
 *     summary: Request fiat on-ramp
 *     tags: [Payments]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               fiatAmount: { type: 'number', description: 'Fiat amount in USD' }
 *               targetToken: { type: 'integer', enum: [0, 1, 2], description: '0: ETH, 1: USDC, 2: SONIC' }
 *               provider: { type: 'string', enum: ['yellowcard', 'moonpay'], description: 'On-ramp provider' }
 *             required: ['fiatAmount', 'targetToken', 'provider']
 *     responses:
 *       200:
 *         description: On-ramp request queued
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 jobId: { type: 'string', description: 'Queue job ID' }
 *                 providerReference: { type: 'string', description: 'Provider transaction ID' }
 *                 status: { type: 'string', description: 'Transaction status' }
 *       400:
 *         description: Validation error
 */
app.post('/request-onramp', authMiddleware, validate([
    body('fiatAmount').isNumeric({ min: 0 }),
    body('targetToken').isInt({ min: 0, max: 2 }),
    body('provider').isIn(['yellowcard', 'moonpay']),
]), async (req, res, next) => {
    const end = httpRequestDuration.startTimer({ method: 'POST', route: '/request-onramp' });
    const { fiatAmount, targetToken, provider } = req.body;
    try {
        let providerReference;
        if (provider === 'yellowcard') {
            providerReference = await yellowCardBreaker.fire(fiatAmount, targetToken, req.user.address);
        } else if (provider === 'moonpay') {
            providerReference = await moonPayBreaker.fire(fiatAmount, targetToken, req.user.address);
        } else {
            throw new ValidationError('Unsupported provider');
        }

        if (providerReference.error) {
            logger.warn(`${provider} on-ramp failed, using fallback`, { error: providerReference.error });
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
        res.json({ jobId: job.id, providerReference: providerReference.transactionId, status: providerReference.status });
        end({ status: '200' });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /request-offramp:
 *   post:
 *     summary: Request crypto off-ramp
 *     tags: [Payments]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               sourceToken: { type: 'integer', enum: [0, 1, 2], description: '0: ETH, 1: USDC, 2: SONIC' }
 *               cryptoAmount: { type: 'number', description: 'Crypto amount' }
 *               bankDetails: { type: 'string', description: 'Bank details' }
 *               provider: { type: 'string', enum: ['yellowcard', 'moonpay'], description: 'Off-ramp provider' }
 *             required: ['sourceToken', 'cryptoAmount', 'bankDetails', 'provider']
 *     responses:
 *       200:
 *         description: Off-ramp request queued
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 jobId: { type: 'string', description: 'Queue job ID' }
 *                 providerReference: { type: 'string', description: 'Provider transaction ID' }
 *       400:
 *         description: Validation error
 */
app.post('/request-offramp', authMiddleware, validate([
    body('sourceToken').isInt({ min: 0, max: 2 }),
    body('cryptoAmount').isNumeric({ min: 0 }),
    body('bankDetails').notEmpty().isString(),
    body('provider').isIn(['yellowcard', 'moonpay']),
]), async (req, res, next) => {
    const end = httpRequestDuration.startTimer({ method: 'POST', route: '/request-offramp' });
    const { sourceToken, cryptoAmount, bankDetails, provider } = req.body;
    try {
        let providerReference;
        if (provider === 'yellowcard') {
            providerReference = await initiateYellowCardOffRamp(cryptoAmount, sourceToken, bankDetails, req.user.address);
        } else if (provider === 'moonpay') {
            providerReference = await initiateMoonPayOffRamp(cryptoAmount, sourceToken, bankDetails, req.user.address);
        } else {
            throw new ValidationError('Unsupported provider');
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
        res.json({ jobId: job.id, providerReference: providerReference.transactionId });
        end({ status: '200' });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /raise-dispute:
 *   post:
 *     summary: Raise a dispute
 *     tags: [Governance]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               relatedId: { type: 'integer', description: 'Related entity ID (e.g., appointment)' }
 *               reason: { type: 'string', description: 'Reason for dispute' }
 *             required: ['relatedId', 'reason']
 *     responses:
 *       200:
 *         description: Dispute raised
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 jobId: { type: 'string', description: 'Queue job ID' }
 *                 disputeId: { type: 'integer', description: 'Dispute ID' }
 */
app.post('/raise-dispute', authMiddleware, validate([
    body('relatedId').isInt({ min: 1 }),
    body('reason').notEmpty().isString(),
]), async (req, res, next) => {
    const end = httpRequestDuration.startTimer({ method: 'POST', route: '/raise-dispute' });
    const { relatedId, reason } = req.body;
    try {
        const callData = governanceContract.interface.encodeFunctionData('queueWithdrawFunds', [req.user.address, 0]);
        const userOp = await createUserOperation(req.user.address, callData);
        const job = await userOpQueue.add({ userOp });

        const disputeId = (await Dispute.countDocuments()) + 1;
        await Dispute.create({
            id: disputeId,
            initiator: sanitizeMongo(req.user.address),
            relatedId,
            status: 0,
            reason,
        });

        res.json({ jobId: job.id, disputeId });
        end({ status: '200' });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /paymaster-status:
 *   get:
 *     summary: Get paymaster balance status
 *     tags: [Payments]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Paymaster status
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ethBalance: { type: 'string', description: 'ETH balance in wei' }
 *                 usdcBalance: { type: 'string', description: 'USDC balance in 6 decimals' }
 *                 sonicBalance: { type: 'string', description: 'SONIC balance in 18 decimals' }
 */
app.get('/paymaster-status', authMiddleware, async (req, res, next) => {
    const end = httpRequestDuration.startTimer({ method: 'GET', route: '/paymaster-status' });
    try {
        const cacheKey = 'paymaster_status';
        const cached = await redisClient.get(cacheKey);
        if (cached) {
            res.json(JSON.parse(cached));
            end({ status: '200' });
            return;
        }

        const ethBalance = await paymasterContractBreaker.fire('getBalance', 0);
        const usdcBalance = await paymasterContractBreaker.fire('getBalance', 1);
        const sonicBalance = await paymasterContractBreaker.fire('getBalance', 2);
        const result = {
            ethBalance: ethBalance.error ? '0' : ethers.utils.formatEther(ethBalance),
            usdcBalance: usdcBalance.error ? '0' : ethers.utils.formatUnits(usdcBalance, 6),
            sonicBalance: sonicBalance.error ? '0' : ethers.utils.formatUnits(sonicBalance, 18),
        };
        await redisClient.setEx(cacheKey, env.REDIS_TTL_STATUS, JSON.stringify(result));
        res.json(result);
        end({ status: '200' });
    } catch (error) {
        next(error);
    }
});

/**
 * @swagger
 * /patient-level/{address}:
 *   get:
 *     summary: Get patient level
 *     tags: [Medical]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: address
 *         required: true
 *         schema:
 *           type: string
 *         description: Patient Ethereum address
 *     responses:
 *       200:
 *         description: Patient level
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 level: { type: 'integer', description: 'Patient level' }
 */
app.get('/patient-level/:address', authMiddleware, async (req, res, next) => {
    const end = httpRequestDuration.startTimer({ method: 'GET', route: '/patient-level' });
    try {
        const cacheKey = `patient_level:${req.params.address}`;
        const level = await getCachedOrContractData(cacheKey, coreContract, 'getPatientLevel', env.REDIS_TTL_STATUS, req.params.address);
        res.json({ level: level.error ? 0 : level });
        end({ status: '200' });
    } catch (error) {
        next(error);
    }
});

// WebSocket with Redis Cluster
const wsRateLimiter = rateLimit({ windowMs: 60 * 1000, max: 100, keyGenerator: (req) => req.socket.remoteAddress });

wss.on('connection', (ws, req) => {
    wsRateLimiter(req, null, (err) => {
        if (err) {
            ws.close(1008, 'WebSocket rate limit exceeded');
            return;
        }

        const token = req.url.split('token=')[1];
        try {
            const decoded = jwt.verify(token, env.JWT_SECRET);
            ws.user = decoded;
            wsConnectionsGauge.inc();

            ws.isAlive = true;
            ws.on('pong', () => { ws.isAlive = true; });

            ws.on('message', async (message) => {
                try {
                    const data = JSON.parse(message.toString('utf8'));
                    if (data.type === 'ping') {
                        ws.send(JSON.stringify({ type: 'pong' }));
                    }
                } catch (error) {
                    logger.warn('Invalid WebSocket message', { error: error.message });
                }
            });

            ws.on('close', () => {
                wsConnectionsGauge.dec();
            });

            ws.on('error', (error) => {
                logger.error('WebSocket error', { error: error.message });
            });
        } catch (error) {
            ws.close(1008, 'Invalid token');
            logger.warn('WebSocket authentication failed', { error: error.message });
        }
    });
});

// Redis Pub/Sub for WebSocket Clustering
redisSub.subscribe('appointment', 'appointmentConfirmed', 'appointmentCompleted', 'appointmentCancelled', 'appointmentRescheduled', 'batchAppointmentsConfirmed');
redisSub.on('message', (channel, message) => {
    const data = JSON.parse(message);
    wss.clients.forEach((ws) => {
        if (ws.user && (
            (channel === 'appointment' && ws.user.address === data.address) ||
            (channel === 'appointmentConfirmed' && ws.user.role === 'patient') ||
            ws.user.role === 'admin'
        )) {
            ws.send(JSON.stringify({ channel, data }));
        }
    });
});

// Heartbeat
const heartbeatInterval = setInterval(() => {
    wss.clients.forEach((ws) => {
        if (!ws.isAlive) {
            ws.terminate();
            wsConnectionsGauge.dec();
            return;
        }
        ws.isAlive = false;
        ws.ping();
    });
}, 30000);

// Server Start
server.listen(8080, () => {
    logger.info('Server running on https://localhost:8080');
});

// Graceful Shutdown
const gracefulShutdown = async () => {
    logger.info('Shutting down gracefully...');
    await Promise.all([
        redisClient.quit(),
        redisPub.quit(),
        redisSub.quit(),
        mongoose.connection.close(),
        userOpQueue.close(),
        aiQueue.close(),
        deadLetterQueue.close(),
    ]);
    clearInterval(heartbeatInterval);
    wss.clients.forEach(ws => ws.terminate());
    server.close(() => {
        logger.info('Server closed');
        process.exit(0);
    });
};

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

app.use(errorHandler);

// Enhanced Testing Suite
if (process.env.NODE_ENV === 'test') {
    const mocha = require('mocha');
    const assert = require('assert');
    const sinon = require('sinon');
    const supertest = require('supertest');

    describe('Telemedicine Backend Tests', () => {
        let sandbox;

        beforeEach(() => {
            sandbox = sinon.createSandbox();
        });

        afterEach(() => {
            sandbox.restore();
        });

        after(async () => {
            await mongoose.connection.dropDatabase();
            await mongoose.connection.close();
        });

        it('should create and validate a UserOp', async () => {
            const sender = '0x1234567890123456789012345678901234567890';
            const callData = '0xabcdef';
            sandbox.stub(provider, 'estimateGas').resolves(ethers.BigNumber.from('100000'));
            sandbox.stub(wallet, 'signMessage').resolves('0xsignature');
            sandbox.stub(coreContractBreaker, 'fire').resolves(ethers.BigNumber.from('0'));

            const userOp = await createUserOperation(sender, callData);
            assert.strictEqual(userOp.sender, sender);
            assert.strictEqual(userOp.callData, callData);

            sandbox.stub(ethers.utils, 'verifyMessage').returns(sender);
            const isValid = await validateUserOp(userOp);
            assert.strictEqual(isValid, true);
        });

        it('should fail UserOp validation with invalid signature', async () => {
            const userOp = { sender: '0x123', signature: '0xwrong' };
            sandbox.stub(ethers.utils, 'verifyMessage').returns('0xother');
            await assert.rejects(validateUserOp(userOp), AuthenticationError);
        });

        it('should handle AI symptom analysis with local fallback', async () => {
            sandbox.stub(axios, 'post').rejects(new Error('Service down'));
            const result = await analyzeSymptoms('fever,cough');
            assert.strictEqual(result.diagnosis, 'Possible Flu');
            assert(result.confidence > 0.5);
        });

        it('should fail AI analysis with invalid input', async () => {
            sandbox.stub(axios, 'post').rejects(new Error('Service down'));
            const result = await localSymptomAnalysis('');
            assert.strictEqual(result, null);
        });

        it('should authenticate WebSocket connection', (done) => {
            const token = jwt.sign({ address: '0xuser', role: 'patient' }, env.JWT_SECRET);
            const ws = new WebSocket('wss://localhost:8080?token=' + token, {
                rejectUnauthorized: false
            });

            ws.on('open', () => {
                assert(wsConnectionsGauge.get().values[0].value > 0);
                ws.close();
                done();
            });
        });

        it('should reject WebSocket with invalid token', (done) => {
            const ws = new WebSocket('wss://localhost:8080?token=invalid', {
                rejectUnauthorized: false
            });

            ws.on('close', (code) => {
                assert.strictEqual(code, 1008);
                done();
            });
        });

        it('should queue and process UserOp', async () => {
            const userOp = {
                sender: '0xuser',
                nonce: 0,
                initCode: '0x',
                callData: '0xabcdef',
                callGasLimit: 100000,
                verificationGasLimit: 150000,
                preVerificationGas: 25000,
                maxFeePerGas: ethers.utils.parseUnits('15', 'gwei'),
                maxPriorityFeePerGas: ethers.utils.parseUnits('2', 'gwei'),
                paymasterAndData: '0x',
                signature: '0xsignature'
            };
            sandbox.stub(entryPoint, 'handleOps').resolves({ hash: '0xtxhash', wait: () => Promise.resolve() });
            sandbox.stub(validateUserOp).resolves(true);

            const job = await userOpQueue.add({ userOp });
            const result = await job.finished();
            assert.strictEqual(result, '0xtxhash');

            const dbUserOp = await UserOp.findOne({ txHash: '0xtxhash' });
            assert.strictEqual(dbUserOp.status, 'submitted');
        });

        it('should handle /login endpoint', async () => {
            const address = '0xuser';
            const message = 'Login message';
            const signature = await wallet.signMessage(message);
            sandbox.stub(User, 'findOne').resolves(null);
            sandbox.stub(User.prototype, 'save').resolves();

            const response = await supertest(app)
                .post('/login')
                .send({ address, signature, message })
                .expect(200);

            assert(response.body.token);
            assert(response.body.csrfToken);
        });

        it('should reject /login with invalid signature', async () => {
            const response = await supertest(app)
                .post('/login')
                .send({ address: '0xuser', signature: '0xwrong', message: 'Login message' })
                .expect(401);

            assert.strictEqual(response.body.error.message, 'Invalid signature');
        });

        it('should handle /book-appointment endpoint', async () => {
            const token = jwt.sign({ address: '0xpatient', role: 'patient' }, env.JWT_SECRET);
            sandbox.stub(createUserOperation).resolves({ sender: '0xpatient' });
            sandbox.stub(userOpQueue, 'add').resolves({ id: 'job123' });

            const response = await supertest(app)
                .post('/book-appointment')
                .set('Authorization', `Bearer ${token}`)
                .send({
                    doctorAddress: '0xdoctor',
                    timestamp: Math.floor(Date.now() / 1000) + 3600,
                    paymentType: 0,
                    isVideoCall: true,
                    videoCallLink: 'https://zoom.us/j/123'
                })
                .expect(200);

            assert.strictEqual(response.body.jobId, 'job123');
        });

        it('should reject /book-appointment with past timestamp', async () => {
            const token = jwt.sign({ address: '0xpatient', role: 'patient' }, env.JWT_SECRET);
            const response = await supertest(app)
                .post('/book-appointment')
                .set('Authorization', `Bearer ${token}`)
                .send({
                    doctorAddress: '0xdoctor',
                    timestamp: Math.floor(Date.now() / 1000) - 3600,
                    paymentType: 0,
                    isVideoCall: true
                })
                .expect(400);

            assert.strictEqual(response.body.error.message, 'Validation failed');
        });

        it('should reject unauthorized access', async () => {
            const token = jwt.sign({ address: '0xuser', role: 'patient' }, env.JWT_SECRET);
            const response = await supertest(app)
                .post('/verify-doctor')
                .set('Authorization', `Bearer ${token}`)
                .send({ doctorAddress: '0xdoctor', licenseNumber: '123', fee: '0.1' })
                .expect(403);

            assert.strictEqual(response.body.error.message, 'Admin access required');
        });

        it('should handle MongoDB disconnection', async () => {
            sandbox.stub(mongoose.connection, 'readyState').value(0);
            const response = await supertest(app)
                .get('/health')
                .expect(503);

            assert.strictEqual(response.body.status, 'unhealthy');
        });
    });
}

module.exports = app;
