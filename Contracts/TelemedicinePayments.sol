// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {SafeMathUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";
import {IERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import {SafeERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import {AggregatorV3Interface} from "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";
import {TelemedicineCore} from "./TelemedicineCore.sol";
import {TelemedicineDisputeResolution} from "./TelemedicineDisputeResolution.sol";

contract TelemedicinePayments is Initializable, ReentrancyGuardUpgradeable {
    using SafeMathUpgradeable for uint256;
    using SafeERC20Upgradeable for IERC20Upgradeable;

    // Custom Errors
    error NotAuthorized();
    error ContractPaused();
    error InvalidAddress();
    error InsufficientFunds();
    error PaymentFailed();
    error InvalidStatus();
    error StalePriceFeed();

    TelemedicineCore public core;
    TelemedicineDisputeResolution public disputeResolution;
    IERC20Upgradeable public usdcToken;
    IERC20Upgradeable public sonicToken;
    AggregatorV3Interface public ethUsdPriceFeed;
    AggregatorV3Interface public sonicUsdPriceFeed;
    AggregatorV3Interface public usdFiatOracle;
    address public onRampProvider;
    address public offRampProvider;
    address[] public trustedOracles;

    uint256 public onRampFee;
    uint256 public offRampFee;
    uint256 public onRampCounter;
    uint256 public offRampCounter;

    mapping(uint256 => OnRampRequest) public onRampRequests;
    mapping(uint256 => OffRampRequest) public offRampRequests;

    struct PendingPayment {
        address recipient;
        uint256 amount;
        PaymentType paymentType;
        bool processed;
        uint48 requestTimestamp; // Added for timeout tracking
    }
    mapping(uint256 => PendingPayment) public pendingPayments;
    uint256 public pendingPaymentCounter;

    enum PaymentType { ETH, USDC, SONIC }
    enum OnRampStatus { Pending, Fulfilled, Failed }
    enum OffRampStatus { Pending, Locked, Fulfilled, Failed }

    struct OnRampRequest {
        uint256 id;
        address user;
        uint256 fiatAmount;
        PaymentType targetToken;
        OnRampStatus status;
        uint256 cryptoAmount;
        uint48 requestTimestamp;
        string providerReference;
    }

    struct OffRampRequest {
        uint256 id;
        address user;
        PaymentType sourceToken;
        uint256 cryptoAmount;
        uint256 fiatAmount;
        OffRampStatus status;
        uint48 requestTimestamp;
        string bankDetails;
    }

    // Constants for improvements
    uint256 public constant MAX_FEE_CAP = 0.01 ether; // Cap for dynamic fees
    uint48 public constant MAX_STALENESS = 1 hours; // Maximum allowed staleness for price feeds
    uint48 public constant PENDING_PAYMENT_TIMEOUT = 7 days; // Timeout for pending payments

    event OnRampRequested(uint256 indexed requestId, address indexed user, uint256 fiatAmount, PaymentType targetToken, string providerReference);
    event OnRampFulfilled(uint256 indexed requestId, address indexed user, uint256 cryptoAmount);
    event OnRampFailed(uint256 indexed requestId, address indexed user, string reason);
    event OffRampRequested(uint256 indexed requestId, address indexed user, PaymentType sourceToken, uint256 cryptoAmount, string bankDetails);
    event OffRampLocked(uint256 indexed requestId, address indexed user, uint256 cryptoAmount);
    event OffRampFulfilled(uint256 indexed requestId, address indexed user, uint256 fiatAmount);
    event OffRampFailed(uint256 indexed requestId, address indexed user, string reason);
    event OnRampProviderUpdated(address indexed oldProvider, address indexed newProvider);
    event OffRampProviderUpdated(address indexed oldProvider, address indexed newProvider);
    event RampFeeUpdated(string indexed rampType, uint256 oldFee, uint256 newFee);
    event PriceFeedUpdated(string indexed feedType, address indexed oldFeed, address indexed newFeed);
    event PatientRefunded(uint256 indexed disputeId, address indexed patient, uint256 amount, PaymentType paymentType);
    event PaymentQueued(uint256 indexed paymentId, address recipient, uint256 amount, PaymentType paymentType);
    event PaymentReleasedFromQueue(uint256 indexed paymentId, address recipient, uint256 amount);
    event PendingPaymentCleaned(uint256 indexed paymentId, address recipient, uint256 amount);

    /// @notice Queues a payment when funds are insufficient
    /// @param _recipient Address to receive the payment
    /// @param _amount Amount to queue
    /// @param _paymentType Type of payment (ETH, USDC, SONIC)
    /// @param _timestamp Timestamp of the request
    function queuePayment(address _recipient, uint256 _amount, PaymentType _paymentType, uint48 _timestamp) 
        external 
        nonReentrant 
        whenNotPaused 
    {
        if (_recipient == address(0)) revert InvalidAddress();
        if (_amount == 0) revert InsufficientFunds();
        
        pendingPaymentCounter = pendingPaymentCounter.add(1);
        pendingPayments[pendingPaymentCounter] = PendingPayment(
            _recipient,
            _amount,
            _paymentType,
            false,
            _timestamp
        );
        emit PaymentQueued(pendingPaymentCounter, _recipient, _amount, _paymentType);
    }

    /// @notice Initializes the contract with external dependencies and default settings
    /// @param _core Address of the TelemedicineCore contract
    /// @param _usdcToken Address of the USDC token contract
    /// @param _sonicToken Address of the SONIC token contract
    /// @param _ethUsdPriceFeed Address of the ETH/USD Chainlink price feed
    /// @param _sonicUsdPriceFeed Address of the SONIC/USD Chainlink price feed
    /// @param _usdFiatOracle Address of the USD/Fiat Chainlink price feed
    /// @param _onRampProvider Address of the on-ramp provider
    /// @param _offRampProvider Address of the off-ramp provider
    /// @param _disputeResolution Address of the dispute resolution contract
    function initialize(
        address _core,
        address _usdcToken,
        address _sonicToken,
        address _ethUsdPriceFeed,
        address _sonicUsdPriceFeed,
        address _usdFiatOracle,
        address _onRampProvider,
        address _offRampProvider,
        address _disputeResolution
    ) external initializer {
        if (_core == address(0) || _usdcToken == address(0) || _sonicToken == address(0) ||
            _ethUsdPriceFeed == address(0) || _sonicUsdPriceFeed == address(0) || _usdFiatOracle == address(0) ||
            _onRampProvider == address(0) || _offRampProvider == address(0) || _disputeResolution == address(0)) revert InvalidAddress();

        __ReentrancyGuard_init();
        core = TelemedicineCore(_core);
        usdcToken = IERC20Upgradeable(_usdcToken);
        sonicToken = IERC20Upgradeable(_sonicToken);
        ethUsdPriceFeed = AggregatorV3Interface(_ethUsdPriceFeed);
        sonicUsdPriceFeed = AggregatorV3Interface(_sonicUsdPriceFeed);
        usdFiatOracle = AggregatorV3Interface(_usdFiatOracle);
        onRampProvider = _onRampProvider;
        offRampProvider = _offRampProvider;
        disputeResolution = TelemedicineDisputeResolution(_disputeResolution);
        trustedOracles.push(_ethUsdPriceFeed);
        trustedOracles.push(_sonicUsdPriceFeed);
        trustedOracles.push(_usdFiatOracle);
        onRampFee = 0.001 ether;
        offRampFee = 0.002 ether;
        onRampCounter = 0;
        offRampCounter = 0;
        pendingPaymentCounter = 0;
    }

    /// @notice Requests an on-ramp operation to convert fiat to cryptocurrency
    /// @param _fiatAmount Amount of fiat to convert
    /// @param _targetToken Target cryptocurrency (ETH, USDC, SONIC)
    /// @param _providerReference Reference string for the on-ramp provider
    function requestOnRamp(uint256 _fiatAmount, PaymentType _targetToken, string calldata _providerReference) external payable onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
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
            _providerReference
        );

        _safeTransferETH(onRampProvider, dynamicFee);
        if (msg.value > dynamicFee) {
            _safeTransferETH(msg.sender, msg.value.sub(dynamicFee)); // Refund excess ETH
        }
        emit OnRampRequested(onRampCounter, msg.sender, _fiatAmount, _targetToken, _providerReference);
    }

    /// @notice Fulfills an on-ramp request, delivering cryptocurrency to the user
    /// @param _requestId ID of the on-ramp request
    /// @param _oracleSignatures Signatures from trusted oracles for consensus
    function fulfillOnRamp(uint256 _requestId, bytes[] calldata _oracleSignatures) external onlyRole(core.ADMIN_ROLE()) nonReentrant whenNotPaused {
        OnRampRequest storage request = onRampRequests[_requestId];
        if (request.status != OnRampStatus.Pending) revert InvalidStatus();
        if (!_verifyMultiOracleConsensus(_requestId, request.cryptoAmount, _oracleSignatures)) revert NotAuthorized();

        request.status = OnRampStatus.Fulfilled;
        _releasePayment(request.user, request.cryptoAmount, request.targetToken);
        emit OnRampFulfilled(_requestId, request.user, request.cryptoAmount);
    }

    /// @notice Marks an on-ramp request as failed
    /// @param _requestId ID of the on-ramp request
    /// @param _reason Reason for the failure
    function failOnRamp(uint256 _requestId, string calldata _reason) external onlyRole(core.ADMIN_ROLE()) whenNotPaused {
        OnRampRequest storage request = onRampRequests[_requestId];
        if (request.status != OnRampStatus.Pending) revert InvalidStatus();
        request.status = OnRampStatus.Failed;
        emit OnRampFailed(_requestId, request.user, _reason);
    }

    /// @notice Requests an off-ramp operation to convert cryptocurrency to fiat
    /// @param _sourceToken Source cryptocurrency (ETH, USDC, SONIC)
    /// @param _cryptoAmount Amount of cryptocurrency to convert
    /// @param _bankDetails Bank details for fiat delivery
    function requestOffRamp(PaymentType _sourceToken, uint256 _cryptoAmount, string calldata _bankDetails) external payable onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
        uint256 dynamicFee = _calculateDynamicFee(offRampFee);
        if (_cryptoAmount == 0) revert InsufficientFunds();
        if (msg.value < dynamicFee) revert InsufficientFunds();

        uint256 fiatAmount = _calculateFiatAmount(_cryptoAmount, _sourceToken);
        if (_sourceToken == PaymentType.ETH) {
            uint256 requiredEth = _cryptoAmount.add(dynamicFee);
            if (msg.value < requiredEth) revert InsufficientFunds();
            if (msg.value > requiredEth) {
                _safeTransferETH(msg.sender, msg.value.sub(requiredEth)); // Refund excess ETH
            }
        } else if (_sourceToken == PaymentType.USDC) {
            usdcToken.safeTransferFrom(msg.sender, address(this), _cryptoAmount);
        } else if (_sourceToken == PaymentType.SONIC) {
            sonicToken.safeTransferFrom(msg.sender, address(this), _cryptoAmount);
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

    /// @notice Locks an off-ramp request for processing
    /// @param _requestId ID of the off-ramp request
    function lockOffRamp(uint256 _requestId) external onlyRole(core.ADMIN_ROLE()) nonReentrant whenNotPaused {
        OffRampRequest storage request = offRampRequests[_requestId];
        if (request.status != OffRampStatus.Pending) revert InvalidStatus();
        request.status = OffRampStatus.Locked;
        emit OffRampLocked(_requestId, request.user, request.cryptoAmount);
    }

    /// @notice Fulfills a locked off-ramp request
    /// @param _requestId ID of the off-ramp request
    /// @param _oracleSignatures Signatures from trusted oracles for consensus
    function fulfillOffRamp(uint256 _requestId, bytes[] calldata _oracleSignatures) external onlyRole(core.ADMIN_ROLE()) nonReentrant whenNotPaused {
        OffRampRequest storage request = offRampRequests[_requestId];
        if (request.status != OffRampStatus.Locked) revert InvalidStatus();
        if (!_verifyMultiOracleConsensus(_requestId, request.fiatAmount, _oracleSignatures)) revert NotAuthorized();

        request.status = OffRampStatus.Fulfilled;
        emit OffRampFulfilled(_requestId, request.user, request.fiatAmount);
    }

    /// @notice Marks an off-ramp request as failed and refunds the user
    /// @param _requestId ID of the off-ramp request
    /// @param _reason Reason for the failure
    function failOffRamp(uint256 _requestId, string calldata _reason) external onlyRole(core.ADMIN_ROLE()) nonReentrant whenNotPaused {
        OffRampRequest storage request = offRampRequests[_requestId];
        if (request.status != OffRampStatus.Pending && request.status != OffRampStatus.Locked) revert InvalidStatus();
        request.status = OffRampStatus.Failed;

        refundPatient(request.user, request.cryptoAmount, request.sourceToken, _requestId);
        emit OffRampFailed(_requestId, request.user, _reason);
    }

    /// @notice Updates the on-ramp provider address
    /// @param _newProvider New on-ramp provider address
    function updateOnRampProvider(address _newProvider) external onlyRole(core.ADMIN_ROLE()) {
        if (_newProvider == address(0)) revert InvalidAddress();
        address oldProvider = onRampProvider;
        onRampProvider = _newProvider;
        emit OnRampProviderUpdated(oldProvider, _newProvider);
    }

    /// @notice Updates the off-ramp provider address
    /// @param _newProvider New off-ramp provider address
    function updateOffRampProvider(address _newProvider) external onlyRole(core.ADMIN_ROLE()) {
        if (_newProvider == address(0)) revert InvalidAddress();
        address oldProvider = offRampProvider;
        offRampProvider = _newProvider;
        emit OffRampProviderUpdated(oldProvider, _newProvider);
    }

    /// @notice Updates the ETH/USD price feed address
    /// @param _newFeed New ETH/USD price feed address
    function updateEthUsdPriceFeed(address _newFeed) external onlyRole(core.ADMIN_ROLE()) {
        if (_newFeed == address(0)) revert InvalidAddress();
        address oldFeed = address(ethUsdPriceFeed);
        ethUsdPriceFeed = AggregatorV3Interface(_newFeed);
        _updateTrustedOracle(oldFeed, _newFeed);
        emit PriceFeedUpdated("ETH/USD", oldFeed, _newFeed);
    }

    /// @notice Updates the SONIC/USD price feed address
    /// @param _newFeed New SONIC/USD price feed address
    function updateSonicUsdPriceFeed(address _newFeed) external onlyRole(core.ADMIN_ROLE()) {
        if (_newFeed == address(0)) revert InvalidAddress();
        address oldFeed = address(sonicUsdPriceFeed);
        sonicUsdPriceFeed = AggregatorV3Interface(_newFeed);
        _updateTrustedOracle(oldFeed, _newFeed);
        emit PriceFeedUpdated("Sonic/USD", oldFeed, _newFeed);
    }

    /// @notice Updates the USD/Fiat oracle address
    /// @param _newOracle New USD/Fiat oracle address
    function updateUsdFiatOracle(address _newOracle) external onlyRole(core.ADMIN_ROLE()) {
        if (_newOracle == address(0)) revert InvalidAddress();
        address oldFeed = address(usdFiatOracle);
        usdFiatOracle = AggregatorV3Interface(_newOracle);
        _updateTrustedOracle(oldFeed, _newOracle);
        emit PriceFeedUpdated("USD/Fiat", oldFeed, _newOracle);
    }

    /// @notice Updates the on-ramp or off-ramp fee
    /// @param _rampType Type of ramp ("onRamp" or "offRamp")
    /// @param _newFee New fee amount
    function updateRampFee(string calldata _rampType, uint256 _newFee) external onlyRole(core.ADMIN_ROLE()) {
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
            revert("Invalid ramp type");
        }
    }

    /// @notice Processes a payment in USDC or SONIC tokens
    /// @param _type Payment type (USDC or SONIC)
    /// @param _amount Amount to transfer
    function _processPayment(PaymentType _type, uint256 _amount) external nonReentrant whenNotPaused {
        if (_type == PaymentType.USDC) {
            usdcToken.safeTransferFrom(msg.sender, address(this), _amount);
        } else if (_type == PaymentType.SONIC) {
            sonicToken.safeTransferFrom(msg.sender, address(this), _amount);
        } else {
            revert InvalidStatus();
        }
    }

    /// @notice Refunds a patient from the reserve fund
    /// @param _patient Address of the patient to refund
    /// @param _amount Amount to refund
    /// @param _type Payment type (ETH, USDC, SONIC)
    /// @param _disputeId ID of the dispute triggering the refund
    function refundPatient(address _patient, uint256 _amount, PaymentType _type, uint256 _disputeId) external onlyDisputeResolution nonReentrant whenNotPaused {
        if (_amount == 0) return;
        if (core.getReserveFundBalance() < core.RESERVE_FUND_THRESHOLD()) revert InsufficientFunds();
        _releasePayment(_patient, _amount, _type);
        emit PatientRefunded(_disputeId, _patient, _amount, _type);
    }

    /// @notice Releases queued payments when funds are available
    /// @param _startId Starting ID of payments to process
    /// @param _count Number of payments to process
    function releasePendingPayments(uint256 _startId, uint256 _count) external onlyRole(core.ADMIN_ROLE()) nonReentrant {
        uint256 endId = _startId.add(_count) > pendingPaymentCounter ? pendingPaymentCounter : _startId.add(_count);
        for (uint256 i = _startId; i < endId; i++) {
            PendingPayment storage payment = pendingPayments[i];
            if (payment.processed || payment.amount == 0) continue;

            if (_hasSufficientFunds(payment.amount, payment.paymentType)) {
                _releasePayment(payment.recipient, payment.amount, payment.paymentType);
                payment.processed = true;
                emit PaymentReleasedFromQueue(i, payment.recipient, payment.amount);
            }
        }
    }

    /// @notice Cleans up stale pending payments older than the timeout period
    /// @param _startId Starting ID of payments to check
    /// @param _count Number of payments to check
    function cleanPendingPayments(uint256 _startId, uint256 _count) external onlyRole(core.ADMIN_ROLE()) nonReentrant {
        uint256 endId = _startId.add(_count) > pendingPaymentCounter ? pendingPaymentCounter : _startId.add(_count);
        for (uint256 i = _startId; i < endId; i++) {
            PendingPayment storage payment = pendingPayments[i];
            if (payment.processed || payment.amount == 0) continue;
            if (block.timestamp > payment.requestTimestamp + PENDING_PAYMENT_TIMEOUT) {
                emit PendingPaymentCleaned(i, payment.recipient, payment.amount);
                delete pendingPayments[i];
            }
        }
    }

    function _calculateCryptoAmount(uint256 _fiatAmount, PaymentType _targetToken) internal view returns (uint256) {
        (, int256 usdPrice, , uint256 updatedAt, ) = usdFiatOracle.latestRoundData();
        if (usdPrice <= 0 || block.timestamp > updatedAt + MAX_STALENESS) revert StalePriceFeed();
        uint256 fiatInUsd = _fiatAmount.mul(uint256(usdPrice)).div(10**usdFiatOracle.decimals());

        if (_targetToken == PaymentType.ETH) {
            (, int256 ethPrice, , uint256 ethUpdatedAt, ) = ethUsdPriceFeed.latestRoundData();
            if (ethPrice <= 0 || block.timestamp > ethUpdatedAt + MAX_STALENESS) revert StalePriceFeed();
            return fiatInUsd.mul(10**18).div(uint256(ethPrice));
        } else if (_targetToken == PaymentType.USDC) {
            return fiatInUsd.mul(10**6).div(10**8);
        } else if (_targetToken == PaymentType.SONIC) {
            (, int256 sonicPrice, , uint256 sonicUpdatedAt, ) = sonicUsdPriceFeed.latestRoundData();
            if (sonicPrice <= 0 || block.timestamp > sonicUpdatedAt + MAX_STALENESS) revert StalePriceFeed();
            return fiatInUsd.mul(10**18).div(uint256(sonicPrice));
        }
        revert InvalidStatus();
    }

    function _calculateFiatAmount(uint256 _cryptoAmount, PaymentType _sourceToken) internal view returns (uint256) {
        (, int256 usdPrice, , uint256 updatedAt, ) = usdFiatOracle.latestRoundData();
        if (usdPrice <= 0 || block.timestamp > updatedAt + MAX_STALENESS) revert StalePriceFeed();

        if (_sourceToken == PaymentType.ETH) {
            (, int256 ethPrice, , uint256 ethUpdatedAt, ) = ethUsdPriceFeed.latestRoundData();
            if (ethPrice <= 0 || block.timestamp > ethUpdatedAt + MAX_STALENESS) revert StalePriceFeed();
            return _cryptoAmount.mul(uint256(ethPrice)).div(10**18).mul(10**usdFiatOracle.decimals()).div(uint256(usdPrice));
        } else if (_sourceToken == PaymentType.USDC) {
            return _cryptoAmount.mul(10**8).div(10**6).mul(10**usdFiatOracle.decimals()).div(uint256(usdPrice));
        } else if (_sourceToken == PaymentType.SONIC) {
            (, int256 sonicPrice, , uint256 sonicUpdatedAt, ) = sonicUsdPriceFeed.latestRoundData();
            if (sonicPrice <= 0 || block.timestamp > sonicUpdatedAt + MAX_STALENESS) revert StalePriceFeed();
            return _cryptoAmount.mul(uint256(sonicPrice)).div(10**18).mul(10**usdFiatOracle.decimals()).div(uint256(usdPrice));
        }
        revert InvalidStatus();
    }

    function _calculateDynamicFee(uint256 _baseFee) internal view returns (uint256) {
        (, int256 ethPrice, , uint256 updatedAt, ) = ethUsdPriceFeed.latestRoundData();
        if (ethPrice <= 0 || block.timestamp > updatedAt + MAX_STALENESS) revert StalePriceFeed();
        uint256 adjustmentFactor = uint256(ethPrice).mul(10**18).div(2000 * 10**8);
        uint256 dynamicFee = _baseFee.mul(adjustmentFactor > 10**18 ? adjustmentFactor : 10**18).div(10**18);
        return dynamicFee > MAX_FEE_CAP ? MAX_FEE_CAP : dynamicFee;
    }

    function _verifyMultiOracleConsensus(uint256 _id, uint256 _value, bytes[] calldata _signatures) internal view returns (bool) {
        if (_signatures.length < trustedOracles.length / 2 + 1) return false;
        bytes32 message = keccak256(abi.encode(_id, _value, block.timestamp));
        uint256 validSignatures = 0;

        for (uint256 i = 0; i < _signatures.length; i++) {
            address signer = recoverSigner(message, _signatures[i]);
            for (uint256 j = 0; j < trustedOracles.length; j++) {
                if (signer == trustedOracles[j]) {
                    validSignatures = validSignatures.add(1);
                    break;
                }
            }
        }
        return validSignatures >= trustedOracles.length / 2 + 1;
    }

    function _updateTrustedOracle(address _oldOracle, address _newOracle) internal {
        for (uint256 i = 0; i < trustedOracles.length; i++) {
            if (trustedOracles[i] == _oldOracle) {
                trustedOracles[i] = _newOracle;
                break;
            }
        }
    }

    function _safeTransferETH(address _to, uint256 _amount) internal {
        (bool success, ) = _to.call{value: _amount}("");
        if (!success) revert PaymentFailed();
    }

    function _releasePayment(address _to, uint256 _amount, PaymentType _paymentType) internal {
        if (!_hasSufficientFunds(_amount, _paymentType)) {
            pendingPaymentCounter = pendingPaymentCounter.add(1);
            pendingPayments[pendingPaymentCounter] = PendingPayment(_to, _amount, _paymentType, false, uint48(block.timestamp));
            emit PaymentQueued(pendingPaymentCounter, _to, _amount, _paymentType);
            return;
        }

        if (_paymentType == PaymentType.ETH) {
            _safeTransferETH(_to, _amount);
        } else if (_paymentType == PaymentType.USDC) {
            usdcToken.safeTransfer(_to, _amount);
        } else if (_paymentType == PaymentType.SONIC) {
            sonicToken.safeTransfer(_to, _amount);
        }
    }

    function _hasSufficientFunds(uint256 _amount, PaymentType _paymentType) internal view returns (bool) {
        if (_paymentType == PaymentType.ETH) {
            return address(this).balance >= _amount;
        } else if (_paymentType == PaymentType.USDC) {
            return usdcToken.balanceOf(address(this)) >= _amount;
        } else if (_paymentType == PaymentType.SONIC) {
            return sonicToken.balanceOf(address(this)) >= _amount;
        }
        return false;
    }

    function recoverSigner(bytes32 message, bytes memory signature) internal pure returns (address) {
        bytes32 r;
        bytes32 s;
        uint8 v;
        if (signature.length != 65) revert InvalidStatus();
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        if (v < 27) v += 27;
        if (v != 27 && v != 28) revert InvalidStatus();
        return ecrecover(message, v, r, s);
    }

    modifier onlyRole(bytes32 role) {
        if (!core.hasRole(role, msg.sender)) revert NotAuthorized();
        _;
    }

    modifier onlyDisputeResolution() {
        if (msg.sender != address(disputeResolution)) revert NotAuthorized();
        _;
    }

    modifier whenNotPaused() {
        if (core.paused()) revert ContractPaused();
        _;
    }

    receive() external payable {}
}
