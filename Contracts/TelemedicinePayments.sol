// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import {SafeMathUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";
import {IERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import {SafeERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import {AggregatorV3Interface} from "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";
import {TelemedicineCore} from "./TelemedicineCore.sol";
import {TelemedicineDisputeResolution} from "./TelemedicineDisputeResolution.sol";
import {TelemedicineOperations} from "./TelemedicineOperations.sol";
import {ITelemedicinePayments} from "./Interfaces/ITelemedicinePayments.sol";

/// @title TelemedicinePayments
/// @notice Handles on-ramp, off-ramp, payment queuing, patient refunds, and reward validation
/// @dev UUPS upgradeable, integrates with TelemedicineCore, DisputeResolution, and Operations
/// @dev Optimized for Sonic Blockchain. Prices (bookings, lab tests, medications) in Sonic USDC (6 decimals); rewards in Sonic $S (18 decimals).
contract TelemedicinePayments is Initializable, UUPSUpgradeable, ReentrancyGuardUpgradeable, PausableUpgradeable {
    using SafeMathUpgradeable for uint256;
    using SafeERC20Upgradeable for IERC20Upgradeable;

    // Custom Errors
    error NotAuthorized();
    error ContractPaused();
    error InvalidAddress();
    error InsufficientFunds();
    error PaymentFailed();
    error InvalidRequestStatus();
    error StalePriceFeed();
    error OracleFailure();
    error ExternalCallFailed();
    error InvalidSignature();
    error InsufficientReserve();
    error InvalidFee();
    error CounterOverflow();
    error InvalidInput();
    error InvalidConfiguration();
    error InvalidRewardAmount(); // New: For $S reward validation
    error InvalidRewardBounds(); // New: For reward bounds configuration

    // Constants
    uint256 public constant MIN_FEE_USD = 0.1 * 10**18; // 0.1 USD minimum (18 decimals)
    uint48 public constant MAX_STALENESS = 1 hours;
    uint48 public constant PENDING_PAYMENT_TIMEOUT = 7 days;
    uint256 public constant DEFAULT_FIAT_PRICE = 10**8; // 1 USD in 8 decimals (fallback)
    uint256 public constant ETH_TRANSFER_GAS_LIMIT = 30000; // Fixed 30,000 gas
    uint256 public constant MAX_PENDING_PAYMENTS = 1_000_000; // Limit pending payments
    uint256 public constant MAX_ITERATIONS = 100; // Limit loop iterations

    // State Variables
    TelemedicineCore public immutable core;
    TelemedicineDisputeResolution public immutable disputeResolution;
    TelemedicineOperations public immutable operations;
    IERC20Upgradeable public usdcToken; // Sonic USDC (6 decimals)
    IERC20Upgradeable public sonicToken; // Sonic $S (18 decimals)
    AggregatorV3Interface public ethUsdPriceFeed;
    AggregatorV3Interface public sonicUsdPriceFeed;
    AggregatorV3Interface public usdFiatOracle;
    address public onRampProvider;
    address public offRampProvider;
    address public multiSigWallet;
    address[] public trustedOracles;
    uint256 public onRampFee; // USD (18 decimals)
    uint256 public offRampFee; // USD (18 decimals)
    uint256 public onRampCounter;
    uint256 public offRampCounter;
    uint256 public pendingPaymentCounter;
    uint256 public versionNumber; // Track contract version
    uint256 public maxFeeCapUsd; // Configurable max fee (USDC decimals, 6)
    uint256 public MIN_REWARD; // New: Min reward in Sonic $S (18 decimals)
    uint256 public MAX_REWARD; // New: Max reward in Sonic $S (18 decimals)

    // Mappings
    mapping(uint256 => OnRampRequest) public onRampRequests;
    mapping(uint256 => OffRampRequest) public offRampRequests;
    mapping(uint256 => PendingPayment) public pendingPayments;
    mapping(uint256 => mapping(address => bool)) private signatureUsed;
    mapping(uint256 => uint256) private nonces;

    // Structs
    struct PendingPayment {
        address recipient;
        uint256 amount;
        ITelemedicinePayments.PaymentType paymentType;
        bool processed;
        uint48 requestTimestamp; // For timeout tracking
    }

    enum OnRampStatus { Pending, Fulfilled, Failed }
    enum OffRampStatus { Pending, Locked, Fulfilled, Failed }

    struct OnRampRequest {
        uint256 id;
        address user;
        uint256 fiatAmount;
        ITelemedicinePayments.PaymentType targetToken;
        OnRampStatus status;
        uint256 cryptoAmount;
        uint48 requestTimestamp;
        bytes32 providerReference;
        uint256 feePaid;
    }

    struct OffRampRequest {
        uint256 id;
        address user;
        ITelemedicinePayments.PaymentType sourceToken;
        uint256 cryptoAmount;
        uint256 fiatAmount;
        OffRampStatus status;
        uint48 requestTimestamp;
        bytes32 bankDetails;
    }

    // Events
    event OnRampRequested(uint256 indexed requestId, address indexed user, uint256 fiatAmount, ITelemedicinePayments.PaymentType targetToken, bytes32 providerReference);
    event OnRampFulfilled(uint256 indexed requestId, address indexed user, uint256 cryptoAmount);
    event OnRampFailed(uint256 indexed requestId, address indexed user, string reason);
    event OffRampRequested(uint256 indexed requestId, address indexed user, ITelemedicinePayments.PaymentType sourceToken, uint256 cryptoAmount, bytes32 bankDetails);
    event OffRampLocked(uint256 indexed requestId, address indexed user, uint256 cryptoAmount);
    event OffRampFulfilled(uint256 indexed requestId, address indexed user, uint256 fiatAmount);
    event OffRampFailed(uint256 indexed requestId, address indexed user, string reason);
    event ProviderUpdated(string indexed providerType, address indexed oldProvider, address indexed newProvider);
    event RampFeeUpdated(string indexed rampType, uint256 oldFee, uint256 newFee);
    event PriceFeedUpdated(string indexed feedType, address indexed oldFeed, address indexed newFeed);
    event PatientRefunded(address indexed patient, uint256 amount, ITelemedicinePayments.PaymentType paymentType);
    event PaymentQueued(uint256 indexed paymentId, address recipient, uint256 amount, ITelemedicinePayments.PaymentType paymentType);
    event PaymentReleasedFromQueue(uint256 indexed paymentId, address recipient, uint256 amount);
    event PendingPaymentCleaned(uint256 indexed paymentId, address recipient, uint256 amount);
    event ReserveFundAllocated(uint256 indexed operationId, uint256 amount, ITelemedicinePayments.PaymentType paymentType);
    event PlatformFeeAllocated(uint256 indexed operationId, uint256 amount, ITelemedicinePayments.PaymentType paymentType);
    event RewardBoundsUpdated(uint256 newMinReward, uint256 newMaxReward); // New: Reward bounds update

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the contract
    /// @param _core Address of TelemedicineCore contract
    /// @param _usdcToken Address of Sonic USDC token (6 decimals)
    /// @param _sonicToken Address of Sonic $S token (18 decimals)
    /// @param _ethUsdPriceFeed Address of ETH/USD price feed
    /// @param _sonicUsdPriceFeed Address of Sonic $S/USD price feed
    /// @param _usdFiatOracle Address of USD/Fiat oracle
    /// @param _onRampProvider Address of on-ramp provider
    /// @param _offRampProvider Address of off-ramp provider
    /// @param _disputeResolution Address of DisputeResolution contract
    /// @param _operations Address of Operations contract
    /// @param _multiSigWallet Address of multi-sig wallet
    function initialize(
        address _core,
        address _usdcToken,
        address _sonicToken,
        address _ethUsdPriceFeed,
        address _sonicUsdPriceFeed,
        address _usdFiatOracle,
        address _onRampProvider,
        address _offRampProvider,
        address _disputeResolution,
        address _operations,
        address _multiSigWallet
    ) external initializer {
        if (_core == address(0) || _usdcToken == address(0) || _sonicToken == address(0) ||
            _ethUsdPriceFeed == address(0) || _sonicUsdPriceFeed == address(0) || _usdFiatOracle == address(0) ||
            _onRampProvider == address(0) || _offRampProvider == address(0) || _disputeResolution == address(0) ||
            _operations == address(0) || _multiSigWallet == address(0)) revert InvalidAddress();
        if (!_isContract(_multiSigWallet)) revert InvalidAddress();

        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        __Pausable_init();

        core = TelemedicineCore(_core);
        usdcToken = IERC20Upgradeable(_usdcToken);
        sonicToken = IERC20Upgradeable(_sonicToken);
        ethUsdPriceFeed = AggregatorV3Interface(_ethUsdPriceFeed);
        sonicUsdPriceFeed = AggregatorV3Interface(_sonicUsdPriceFeed);
        usdFiatOracle = AggregatorV3Interface(_usdFiatOracle);
        onRampProvider = _onRampProvider;
        offRampProvider = _offRampProvider;
        disputeResolution = TelemedicineDisputeResolution(_disputeResolution);
        operations = TelemedicineOperations(_operations);
        multiSigWallet = _multiSigWallet;
        trustedOracles.push(_ethUsdPriceFeed);
        trustedOracles.push(_sonicUsdPriceFeed);
        trustedOracles.push(_usdFiatOracle);
        onRampFee = 1 * 10**18; // 1 USD (18 decimals)
        offRampFee = 2 * 10**18; // 2 USD (18 decimals)
        maxFeeCapUsd = 10 * 10**6; // 10 USDC (6 decimals)
        versionNumber = 1;
        MIN_REWARD = 10_000_000_000_000_000; // 0.01 $S (10^16 units, 18 decimals)
        MAX_REWARD = 1_000_000_000_000_000_000_000; // 1000 $S (10^21 units, 18 decimals)

        emit RewardBoundsUpdated(MIN_REWARD, MAX_REWARD);
    }

    /// @notice Returns the contract version
    function version() external view returns (uint256) {
        return versionNumber;
    }

    /// @notice Authorizes an upgrade
    function _authorizeUpgrade(address newImplementation) internal override {
        if (msg.sender != multiSigWallet) revert NotAuthorized();
        if (!_isContract(newImplementation)) revert InvalidAddress();
        versionNumber++;
    }

    /// @notice Returns the Sonic USDC token contract
    function sonicToken() external view returns (IERC20Upgradeable) {
        return usdcToken;
    }

    /// @notice Returns the Sonic $S token contract
    function sonicNativeToken() external view returns (IERC20Upgradeable) {
        return sonicToken;
    }

    /// @notice Updates the minimum and maximum reward bounds for Sonic $S payments
    /// @param _newMinReward New minimum reward in Sonic $S units (18 decimals)
    /// @param _newMaxReward New maximum reward in Sonic $S units (18 decimals)
    /// @dev Restricted to ADMIN_ROLE; ensures min <= max and reasonable bounds
    function updateRewardBounds(uint256 _newMinReward, uint256 _newMaxReward) 
        external 
        onlyRole(core.ADMIN_ROLE()) 
    {
        if (_newMinReward == 0 || _newMinReward > _newMaxReward) revert InvalidRewardBounds();
        if (_newMaxReward > type(uint192).max) revert InvalidRewardBounds(); // Ensure fits in potential future storage

        MIN_REWARD = _newMinReward;
        MAX_REWARD = _newMaxReward;
        emit RewardBoundsUpdated(_newMinReward, _newMaxReward);
    }

    /// @notice Queues a payment
    /// @param _recipient Recipient address
    /// @param _amount Amount in token units (USDC: 6 decimals, $S: 18 decimals)
    /// @param _paymentType Payment type (ETH, USDC, SONIC)
    /// @dev Validates $S amounts against MIN_REWARD/MAX_REWARD
    function queuePayment(address _recipient, uint256 _amount, ITelemedicinePayments.PaymentType _paymentType)
        external
        nonReentrant
        whenNotPaused
    {
        try core.hasRole(core.ADMIN_ROLE(), msg.sender) returns (bool isAdmin) {
            if (msg.sender != address(operations) && !isAdmin) revert NotAuthorized();
        } catch {
            revert ExternalCallFailed();
        }
        if (_recipient == address(0)) revert InvalidAddress();
        if (_amount == 0) revert InsufficientFunds();
        if (pendingPaymentCounter >= MAX_PENDING_PAYMENTS) revert CounterOverflow();
        if (_paymentType == ITelemedicinePayments.PaymentType.SONIC) {
            if (_amount < MIN_REWARD || _amount > MAX_REWARD) revert InvalidRewardAmount();
        }

        pendingPaymentCounter = pendingPaymentCounter.add(1);
        pendingPayments[pendingPaymentCounter] = PendingPayment(_recipient, _amount, _paymentType, false, uint48(block.timestamp));
        emit PaymentQueued(pendingPaymentCounter, _recipient, _amount, _paymentType);
    }

    /// @notice Requests an on-ramp operation
    /// @param _fiatAmount Fiat amount (USD, 18 decimals)
    /// @param _targetToken Target token (ETH, USDC, SONIC)
    /// @param _providerReference Provider reference hash
    function requestOnRamp(uint256 _fiatAmount, ITelemedicinePayments.PaymentType _targetToken, bytes32 _providerReference)
        external
        payable
        onlyRole(core.PATIENT_ROLE())
        nonReentrant
        whenNotPaused
    {
        uint256 dynamicFee = _calculateDynamicFee(onRampFee);
        if (_fiatAmount == 0) revert InsufficientFunds();
        if (msg.value < dynamicFee) revert InsufficientFunds();

        uint256 cryptoAmount = _calculateCryptoAmount(_fiatAmount, _targetToken);
        onRampCounter = onRampCounter.add(1);
        onRampRequests[onRampCounter] = OnRampRequest(
            onRampCounter,
            msg.sender,
            _fiatAmount,
            _targetToken,
            OnRampStatus.Pending,
            cryptoAmount,
            uint48(block.timestamp),
            _providerReference,
            dynamicFee
        );

        _safeTransferETH(onRampProvider, dynamicFee);
        if (msg.value > dynamicFee) {
            _safeTransferETH(msg.sender, msg.value.sub(dynamicFee));
        }
        emit OnRampRequested(onRampCounter, msg.sender, _fiatAmount, _targetToken, _providerReference);
    }

    /// @notice Batch fulfills on-ramp requests
    function batchFulfillOnRamp(uint256[] calldata _requestIds, bytes[][] calldata _oracleSignatures)
        external
        onlyRole(core.ADMIN_ROLE())
        nonReentrant
        whenNotPaused
    {
        if (_requestIds.length > MAX_ITERATIONS) revert InvalidInput();
        for (uint256 i = 0; i < _requestIds.length; i++) {
            OnRampRequest storage request = onRampRequests[_requestIds[i]];
            if (request.status != OnRampStatus.Pending) continue;
            if (!_verifyMultiOracleConsensus(_requestIds[i], request.cryptoAmount, _oracleSignatures[i])) continue;

            request.status = OnRampStatus.Fulfilled;
            _releasePayment(request.user, request.cryptoAmount, request.targetToken);
            emit OnRampFulfilled(_requestIds[i], request.user, request.cryptoAmount);
        }
    }

    /// @notice Marks an on-ramp request as failed
    function failOnRamp(uint256 _requestId, string calldata _reason)
        external
        onlyRole(core.ADMIN_ROLE())
        whenNotPaused
    {
        OnRampRequest storage request = onRampRequests[_requestId];
        if (request.status != OnRampStatus.Pending) revert InvalidRequestStatus();
        request.status = OnRampStatus.Failed;

        if (request.feePaid > 0 && address(this).balance >= request.feePaid) {
            _safeTransferETH(request.user, request.feePaid);
        }
        emit OnRampFailed(_requestId, request.user, _reason);
    }

    /// @notice Requests an off-ramp operation
    /// @param _sourceToken Source token (ETH, USDC, SONIC)
    /// @param _cryptoAmount Amount in token units
    /// @param _bankDetails Bank details hash
    function requestOffRamp(ITelemedicinePayments.PaymentType _sourceToken, uint256 _cryptoAmount, bytes32 _bankDetails)
        external
        payable
        onlyRole(core.PATIENT_ROLE())
        nonReentrant
        whenNotPaused
    {
        uint256 dynamicFee = _calculateDynamicFee(offRampFee);
        if (_cryptoAmount == 0) revert InsufficientFunds();
        if (msg.value < dynamicFee) revert InsufficientFunds();

        uint256 fiatAmount = _calculateFiatAmount(_cryptoAmount, _sourceToken);
        if (_sourceToken == ITelemedicinePayments.PaymentType.ETH) {
            uint256 requiredEth = _cryptoAmount.add(dynamicFee);
            if (msg.value < requiredEth) revert InsufficientFunds();
            if (msg.value > requiredEth) {
                _safeTransferETH(msg.sender, msg.value.sub(requiredEth));
            }
        } else if (_sourceToken == ITelemedicinePayments.PaymentType.USDC) {
            try usdcToken.safeTransferFrom(msg.sender, address(this), _cryptoAmount) {} catch {
                revert ExternalCallFailed();
            }
        } else if (_sourceToken == ITelemedicinePayments.PaymentType.SONIC) {
            try sonicToken.safeTransferFrom(msg.sender, address(this), _cryptoAmount) {} catch {
                revert ExternalCallFailed();
            }
        } else {
            revert InvalidRequestStatus();
        }

        offRampCounter = offRampCounter.add(1);
        offRampRequests[offRampCounter] = OffRampRequest(
            offRampCounter,
            msg.sender,
            _sourceToken,
            _cryptoAmount,
            fiatAmount,
            OffRampStatus.Pending,
            uint48(block.timestamp),
            _bankDetails
        );

        _safeTransferETH(offRampProvider, dynamicFee);
        emit OffRampRequested(offRampCounter, msg.sender, _sourceToken, _cryptoAmount, _bankDetails);
    }

    /// @notice Locks an off-ramp request
    function lockOffRamp(uint256 _requestId)
        external
        onlyRole(core.ADMIN_ROLE())
        nonReentrant
        whenNotPaused
    {
        OffRampRequest storage request = offRampRequests[_requestId];
        if (request.status != OffRampStatus.Pending) revert InvalidRequestStatus();
        request.status = OffRampStatus.Locked;
        emit OffRampLocked(_requestId, request.user, request.cryptoAmount);
    }

    /// @notice Batch fulfills off-ramp requests
    function batchFulfillOffRamp(uint256[] calldata _requestIds, bytes[][] calldata _oracleSignatures)
        external
        onlyRole(core.ADMIN_ROLE())
        nonReentrant
        whenNotPaused
    {
        if (_requestIds.length > MAX_ITERATIONS) revert InvalidInput();
        for (uint256 i = 0; i < _requestIds.length; i++) {
            OffRampRequest storage request = offRampRequests[_requestIds[i]];
            if (request.status != OffRampStatus.Locked) continue;
            if (!_verifyMultiOracleConsensus(_requestIds[i], request.fiatAmount, _oracleSignatures[i])) continue;

            request.status = OffRampStatus.Fulfilled;
            emit OffRampFulfilled(_requestIds[i], request.user, request.fiatAmount);
        }
    }

    /// @notice Marks an off-ramp request as failed
    function failOffRamp(uint256 _requestId, string calldata _reason)
        external
        onlyRole(core.ADMIN_ROLE())
        nonReentrant
        whenNotPaused
    {
        OffRampRequest storage request = offRampRequests[_requestId];
        if (request.status != OffRampStatus.Pending && request.status != OffRampStatus.Locked) revert InvalidRequestStatus();
        request.status = OffRampStatus.Failed;

        _refundPatient(request.user, request.cryptoAmount, request.sourceToken);
        emit OffRampFailed(_requestId, request.user, _reason);
    }

    /// @notice Updates configuration parameters
    function updateConfiguration(string memory _parameter, address _value) external onlyConfigAdmin {
        bytes32 paramHash = keccak256(abi.encodePacked(_parameter));
        if (_value == address(0)) revert InvalidAddress();

        if (paramHash == keccak256(abi.encodePacked("onRampProvider"))) {
            address oldProvider = onRampProvider;
            onRampProvider = _value;
            emit ProviderUpdated("onRamp", oldProvider, _value);
        } else if (paramHash == keccak256(abi.encodePacked("offRampProvider"))) {
            address oldProvider = offRampProvider;
            offRampProvider = _value;
            emit ProviderUpdated("offRamp", oldProvider, _value);
        } else if (paramHash == keccak256(abi.encodePacked("ethUsdPriceFeed"))) {
            address oldFeed = address(ethUsdPriceFeed);
            ethUsdPriceFeed = AggregatorV3Interface(_value);
            _updateTrustedOracle(oldFeed, _value);
            emit PriceFeedUpdated("ETH/USD", oldFeed, _value);
        } else if (paramHash == keccak256(abi.encodePacked("sonicUsdPriceFeed"))) {
            address oldFeed = address(sonicUsdPriceFeed);
            sonicUsdPriceFeed = AggregatorV3Interface(_value);
            _updateTrustedOracle(oldFeed, _value);
            emit PriceFeedUpdated("Sonic/USD", oldFeed, _value);
        } else if (paramHash == keccak256(abi.encodePacked("usdFiatOracle"))) {
            address oldFeed = address(usdFiatOracle);
            usdFiatOracle = AggregatorV3Interface(_value);
            _updateTrustedOracle(oldFeed, _value);
            emit PriceFeedUpdated("USD/Fiat", oldFeed, _value);
        } else {
            revert InvalidConfiguration();
        }
    }

    /// @notice Updates ramp fees
    function updateRampFee(string calldata _rampType, uint256 _newFee) external onlyConfigAdmin {
        if (_newFee < MIN_FEE_USD || _newFee > maxFeeCapUsd.mul(10**12)) revert InvalidFee();
        bytes32 rampHash = keccak256(abi.encodePacked(_rampType));
        if (rampHash == keccak256("onRamp")) {
            uint256 oldFee = onRampFee;
            onRampFee = _newFee;
            emit RampFeeUpdated("onRamp", oldFee, _newFee);
        } else if (rampHash == keccak256("offRamp")) {
            uint256 oldFee = offRampFee;
            offRampFee = _newFee;
            emit RampFeeUpdated("offRamp", oldFee, _newFee);
        } else {
            revert InvalidConfiguration();
        }
    }

    /// @notice Processes a payment with reserve and platform fee allocation
    /// @param _type Payment type (ETH, USDC, SONIC)
    /// @param _amount Amount in token units
    function _processPayment(ITelemedicinePayments.PaymentType _type, uint256 _amount)
        external
        payable
        nonReentrant
        whenNotPaused
    {
        if (msg.sender != address(operations)) revert NotAuthorized();
        if (_type == ITelemedicinePayments.PaymentType.SONIC) {
            if (_amount < MIN_REWARD || _amount > MAX_REWARD) revert InvalidRewardAmount();
        }

        uint256 reservePercentage = core.reserveFundPercentage();
        uint256 platformPercentage = core.platformFeePercentage();
        uint256 percentageDenominator = core.PERCENTAGE_DENOMINATOR();
        uint256 reserveAmount = _amount.mul(reservePercentage).div(percentageDenominator);
        uint256 platformAmount = _amount.mul(platformPercentage).div(percentageDenominator);

        uint256 operationId;
        try operations.getOperationId(msg.sender, block.timestamp) returns (uint256 id) {
            operationId = id;
        } catch {
            revert ExternalCallFailed();
        }

        try core.getReserveFundBalance(_type) returns (uint256 currentReserve) {
            if (_type == ITelemedicinePayments.PaymentType.ETH) {
                if (msg.value < _amount) revert InsufficientFunds();
                if (address(this).balance < currentReserve.add(reserveAmount)) revert InsufficientReserve();
                try core.updateReserveFund(_type, currentReserve.add(reserveAmount)) {
                    if (msg.value > _amount) {
                        _safeTransferETH(msg.sender, msg.value.sub(_amount));
                    }
                } catch {
                    revert ExternalCallFailed();
                }
            } else if (_type == ITelemedicinePayments.PaymentType.USDC) {
                if (usdcToken.balanceOf(address(this)) < currentReserve.add(reserveAmount)) revert InsufficientReserve();
                try usdcToken.safeTransferFrom(msg.sender, address(this), _amount) {
                    try core.updateReserveFund(_type, currentReserve.add(reserveAmount)) {} catch {
                        revert ExternalCallFailed();
                    }
                } catch {
                    revert ExternalCallFailed();
                }
            } else if (_type == ITelemedicinePayments.PaymentType.SONIC) {
                if (sonicToken.balanceOf(address(this)) < currentReserve.add(reserveAmount)) revert InsufficientReserve();
                try sonicToken.safeTransferFrom(msg.sender, address(this), _amount) {
                    try core.updateReserveFund(_type, currentReserve.add(reserveAmount)) {} catch {
                        revert ExternalCallFailed();
                    }
                } catch {
                    revert ExternalCallFailed();
                }
            } else {
                revert InvalidRequestStatus();
            }
        } catch {
            revert ExternalCallFailed();
        }

        emit ReserveFundAllocated(operationId, reserveAmount, _type);
        emit PlatformFeeAllocated(operationId, platformAmount, _type);
    }

    /// @notice Refunds a patient from reserve funds
    function _refundPatient(address _patient, uint256 _amount, ITelemedicinePayments.PaymentType _type)
        public
        onlyDisputeResolution
        nonReentrant
        whenNotPaused
    {
        if (_amount == 0) return;
        try core.getReserveFundBalance(_type) returns (uint256 reserveBalance) {
            if (reserveBalance < core.minReserveBalance() || reserveBalance < _amount) revert InsufficientReserve();
            _releasePayment(_patient, _amount, _type);
            emit PatientRefunded(_patient, _amount, _type);
        } catch {
            revert ExternalCallFailed();
        }
    }

    /// @notice Releases queued payments
    /// @param _startId Starting payment ID
    /// @param _endId Ending payment ID
    function releasePendingPayments(uint256 _startId, uint256 _endId)
        external
        onlyRole(core.ADMIN_ROLE())
        nonReentrant
    {
        if (_startId > _endId || _endId > pendingPaymentCounter) revert InvalidRequestStatus();
        uint256 iterations = _endId.sub(_startId).add(1);
        if (iterations > MAX_ITERATIONS) revert InvalidInput();

        for (uint256 i = _startId; i <= _endId; i++) {
            PendingPayment storage payment = pendingPayments[i];
            if (payment.processed || payment.amount == 0) continue;
            if (payment.paymentType == ITelemedicinePayments.PaymentType.SONIC) {
                if (payment.amount < MIN_REWARD || payment.amount > MAX_REWARD) revert InvalidRewardAmount();
            }

            if (_hasSufficientFunds(payment.amount, payment.paymentType)) {
                _releasePayment(payment.recipient, payment.amount, payment.paymentType);
                payment.processed = true;
                emit PaymentReleasedFromQueue(i, payment.recipient, payment.amount);
            }
        }
    }

    /// @notice Cleans stale pending payments
    function cleanPendingPayments(uint256 _startId, uint256 _endId)
        external
        onlyRole(core.ADMIN_ROLE())
        nonReentrant
    {
        if (_startId > _endId || _endId > pendingPaymentCounter) revert InvalidRequestStatus();
        uint256 iterations = _endId.sub(_startId).add(1);
        if (iterations > MAX_ITERATIONS) revert InvalidInput();

        for (uint256 i = _startId; i <= _endId; i++) {
            PendingPayment storage payment = pendingPayments[i];
            if (payment.processed || payment.amount == 0) continue;
            if (block.timestamp > payment.requestTimestamp + PENDING_PAYMENT_TIMEOUT) {
                emit PendingPaymentCleaned(i, payment.recipient, payment.amount);
                delete pendingPayments[i];
            }
        }
    }

    // Internal Functions

    function _calculateCryptoAmount(uint256 _fiatAmount, ITelemedicinePayments.PaymentType _targetToken)
        internal
        view
        returns (uint256)
    {
        (, int256 usdPrice, , uint256 updatedAt, ) = usdFiatOracle.latestRoundData();
        bool usdStale = usdPrice <= 0 || block.timestamp > updatedAt + MAX_STALENESS;
        uint256 fiatInUsd = usdStale ? _fiatAmount : _fiatAmount.mul(uint256(usdPrice)).div(10**usdFiatOracle.decimals());

        if Moderation if (_targetToken == ITelemedicinePayments.PaymentType.ETH) {
            (, int256 ethPrice, , uint256 ethUpdatedAt, ) = ethUsdPriceFeed.latestRoundData();
            if (ethPrice <= 0 || block.timestamp > ethUpdatedAt + MAX_STALENESS) {
                if (usdStale) revert OracleFailure();
                return fiatInUsd.mul(10**18).div(2000 * 10**8);
            }
            return fiatInUsd.mul(10**18).div(uint256(ethPrice));
        } else if (_targetToken == ITelemedicinePayments.PaymentType.USDC) {
            return fiatInUsd.mul(10**6).div(10**8);
        } else if (_targetToken == ITelemedicinePayments.PaymentType.SONIC) {
            (, int256 sonicPrice, , uint256 sonicUpdatedAt, ) = sonicUsdPriceFeed.latestRoundData();
            if (sonicPrice <= 0 || block.timestamp > sonicUpdatedAt + MAX_STALENESS) {
                if (usdStale) revert OracleFailure();
                return fiatInUsd.mul(10**18).div(10**8);
            }
            return fiatInUsd.mul(10**18).div(uint256(sonicPrice));
        }
        revert InvalidRequestStatus();
    }

    function _calculateFiatAmount(uint256 _cryptoAmount, ITelemedicinePayments.PaymentType _sourceToken)
        internal
        view
        returns (uint256)
    {
        (, int256 usdPrice, , uint256 updatedAt, ) = usdFiatOracle.latestRoundData();
        bool usdStale = usdPrice <= 0 || block.timestamp > updatedAt + MAX_STALENESS;
        uint256 usdPriceAdjusted = usdStale ? DEFAULT_FIAT_PRICE : uint256(usdPrice);

        if (_sourceToken == ITelemedicinePayments.PaymentType.ETH) {
            (, int256 ethPrice, , uint256 ethUpdatedAt, ) = ethUsdPriceFeed.latestRoundData();
            if (ethPrice <= 0 || block.timestamp > ethUpdatedAt + MAX_STALENESS) {
                if (usdStale) revert OracleFailure();
                return _cryptoAmount.mul(2000 * 10**8).div(10**18).mul(10**usdFiatOracle.decimals()).div(DEFAULT_FIAT_PRICE);
            }
            return _cryptoAmount.mul(uint256(ethPrice)).div(10**18).mul(10**usdFiatOracle.decimals()).div(usdPriceAdjusted);
        } else if (_sourceToken == ITelemedicinePayments.PaymentType.USDC) {
            return _cryptoAmount.mul(10**8).div(10**6).mul(10**usdFiatOracle.decimals()).div(usdPriceAdjusted);
        } else if (_sourceToken == ITelemedicinePayments.PaymentType.SONIC) {
            (, int256 sonicPrice, , uint256 sonicUpdatedAt, ) = sonicUsdPriceFeed.latestRoundData();
            if (sonicPrice <= 0 || block.timestamp > sonicUpdatedAt + MAX_STALENESS) {
                if (usdStale) revert OracleFailure();
                return _cryptoAmount.mul(10**8).div(10**18).mul(10**usdFiatOracle.decimals()).div(DEFAULT_FIAT_PRICE);
            }
            return _cryptoAmount.mul(uint256(sonicPrice)).div(10**18).mul(10**usdFiatOracle.decimals()).div(usdPriceAdjusted);
        }
        revert InvalidRequestStatus();
    }

    function _calculateDynamicFee(uint256 _baseFeeUsd) internal view returns (uint256) {
        (, int256 ethPrice, , uint256 updatedAt, ) = ethUsdPriceFeed.latestRoundData();
        if (ethPrice <= 0 || block.timestamp > updatedAt + MAX_STALENESS) {
            return _baseFeeUsd.mul(10**18).div(2000 * 10**8);
        }
        uint256 feeInEth = _baseFeeUsd.mul(10**18).div(uint256(ethPrice));
        uint256 maxFeeInEth = maxFeeCapUsd.mul(10**12).mul(10**18).div(uint256(ethPrice));
        return feeInEth > maxFeeInEth ? maxFeeInEth : feeInEth;
    }

    function _verifyMultiOracleConsensus(uint256 _id, uint256 _value, bytes[] calldata _signatures)
        internal
        view
        returns (bool)
    {
        if (_signatures.length < trustedOracles.length / 2 + 1) return false;
        bytes32 message = keccak256(abi.encode(_id, _value, block.timestamp, nonces[_id]));
        uint256 validSignatures = 0;
        mapping(address => bool) storage usedSigners = signatureUsed[_id];

        for (uint256 i = 0; i < _signatures.length; i++) {
            address signer = recoverSigner(message, _signatures[i]);
            if (usedSigners[signer]) continue;
            for (uint256 j = 0; j < trustedOracles.length; j++) {
                if (signer == trustedOracles[j]) {
                    validSignatures = validSignatures.add(1);
                    usedSigners[signer] = true;
                    break;
                }
            }
        }
        return validSignatures >= trustedOracles.length / 2 + 1;
    }

    function _updateTrustedOracle(address _oldOracle, address _newOracle) internal {
        bool found = false;
        for (uint256 i = 0; i < trustedOracles.length; i++) {
            if (trustedOracles[i] == _oldOracle) {
                trustedOracles[i] = _newOracle;
                found = true;
                break;
            }
        }
        if (!found) revert InvalidAddress();
    }

    function _safeTransferETH(address _to, uint256 _amount) internal {
        (bool success, ) = _to.call{value: _amount, gas: ETH_TRANSFER_GAS_LIMIT}("");
        if (!success) revert PaymentFailed();
    }

    function _releasePayment(address _to, uint256 _amount, ITelemedicinePayments.PaymentType _paymentType) internal {
        if (!_hasSufficientFunds(_amount, _paymentType)) {
            if (pendingPaymentCounter >= MAX_PENDING_PAYMENTS) revert CounterOverflow();
            pendingPaymentCounter = pendingPaymentCounter.add(1);
            if (_paymentType == ITelemedicinePayments.PaymentType.SONIC) {
                if (_amount < MIN_REWARD || _amount > MAX_REWARD) revert InvalidRewardAmount();
            }
            pendingPayments[pendingPaymentCounter] = PendingPayment(_to, _amount, _paymentType, false, uint48(block.timestamp));
            emit PaymentQueued(pendingPaymentCounter, _to, _amount, _paymentType);
            return;
        }

        if (_paymentType == ITelemedicinePayments.PaymentType.ETH) {
            _safeTransferETH(_to, _amount);
        } else if (_paymentType == ITelemedicinePayments.PaymentType.USDC) {
            try usdcToken.safeTransfer(_to, _amount) {} catch {
                revert ExternalCallFailed();
            }
        } else if (_paymentType == ITelemedicinePayments.PaymentType.SONIC) {
            if (_amount < MIN_REWARD || _amount > MAX_REWARD) revert InvalidRewardAmount();
            try sonicToken.safeTransfer(_to, _amount) {} catch {
                revert ExternalCallFailed();
            }
        }
    }

    function _hasSufficientFunds(uint256 _amount, ITelemedicinePayments.PaymentType _paymentType)
        internal
        view
        returns (bool)
    {
        if (_paymentType == ITelemedicinePayments.PaymentType.ETH) {
            return address(this).balance >= _amount;
        } else if (_paymentType == ITelemedicinePayments.PaymentType.USDC) {
            return usdcToken.balanceOf(address(this)) >= _amount;
        } else if (_paymentType == ITelemedicinePayments.PaymentType.SONIC) {
            return sonicToken.balanceOf(address(this)) >= _amount;
        }
        return false;
    }

    function recoverSigner(bytes32 message, bytes memory signature) internal pure returns (address) {
        if (signature.length != 65) revert InvalidSignature();
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        if (v < 27) v += 27;
        if (v != 27 && v != 28) revert InvalidSignature();
        address signer = ecrecover(message, v, r, s);
        if (signer == address(0)) revert InvalidSignature();
        return signer;
    }

    function _isContract(address addr) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(addr)
        }
        return size > 0;
    }

    // Modifiers

    modifier onlyRole(bytes32 role) {
        try core.hasRole(role, msg.sender) returns (bool hasRole) {
            if (!hasRole) revert NotAuthorized();
            _;
        } catch {
            revert ExternalCallFailed();
        }
    }

    modifier onlyDisputeResolution() {
        if (msg.sender != address(disputeResolution)) revert NotAuthorized();
        _;
    }

    modifier onlyConfigAdmin() {
        try core.isConfigAdmin(msg.sender) returns (bool isAdmin) {
            if (!isAdmin) revert NotAuthorized();
            _;
        } catch {
            revert ExternalCallFailed();
        }
    }

    modifier whenNotPaused() {
        try core.paused() returns (bool corePaused) {
            if (corePaused != paused()) {
                corePaused ? _pause() : _unpause();
            }
            if (paused()) revert ContractPaused();
            _;
        } catch {
            revert ExternalCallFailed();
        }
    }

    // View Functions

    function getOnRampRequest(uint256 _requestId)
        external
        view
        onlyRole(core.ADMIN_ROLE())
        returns (OnRampRequest memory)
    {
        return onRampRequests[_requestId];
    }

    function getOffRampRequest(uint256 _requestId)
        external
        view
        onlyRole(core.ADMIN_ROLE())
        returns (OffRampRequest memory)
    {
        return offRampRequests[_requestId];
    }

    function getPendingPayment(uint256 _paymentId)
        external
        view
        onlyRole(core.ADMIN_ROLE())
        returns (PendingPayment memory)
    {
        return pendingPayments[_paymentId];
    }

    // Fallback
    receive() external payable {}

    // Storage gap
    uint256[48] private __gap; // Reduced from 50 due to MIN_REWARD, MAX_REWARD
}
