<xaiArtifact artifact_id="f3e9d617-0f9a-4027-92f2-0770dd80421c" artifact_version_id="26515ba9-ea29-48df-8144-51b8b8f7a60e" title="PaymentHandler.sol" contentType="text/solidity">
// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
import {TelemedicineBase} from "./TelemedicineBase.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin
/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {TelemedicineUtils} from "./TelemedicineUtils.sol";
contract PaymentHandler is TelemedicineBase, ReentrancyGuardUpgradeable {
    // Enums
    enum PaymentType { ETH, USDC, SONIC }
    enum OnRampStatus { Pending, Fulfilled, Failed }
    enum OffRampStatus { Pending, Locked, Fulfilled, Failed }
    enum RampType { OnRamp, OffRamp }

// Structs
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

// State Variables
uint256 public onRampFee;
uint256 public offRampFee;
uint256 public onRampCounter;
uint256 public offRampCounter;
mapping(uint256 => OnRampRequest) public onRampRequests;
mapping(uint256 => OffRampRequest) public offRampRequests;

// Events
event OnRampRequested(uint256 indexed requestId, address indexed user, uint256 fiatAmount, PaymentType targetToken, string providerReference);
event OnRampFulfilled(uint256 indexed requestId, address indexed user, uint256 cryptoAmount);
event OnRampFailed(uint256 indexed requestId, address indexed user, string reason);
event OffRampRequested(uint256 indexed requestId, address indexed user, PaymentType sourceToken, uint256 cryptoAmount, string bankDetails);
event OffRampLocked(uint256 indexed requestId, address indexed user, uint256 cryptoAmount);
event OffRampFulfilled(uint256 indexed requestId, address indexed user, uint256 fiatAmount);
event OffRampFailed(uint256 indexed requestId, address indexed user, string reason);
event RampFeeUpdated(RampType indexed rampType, uint256 oldFee, uint256 newFee);

// Initializer
function initialize(
    address _usdcToken,
    address _sonicToken,
    address _ethUsdPriceFeed,
    address _sonicUsdPriceFeed,
    address _entryPoint,
    address _paymaster,
    address _usdFiatOracle,
    address _dataAccessOracle,
    address _onRampProvider,
    address _offRampProvider,
    address[] memory _initialAdmins
) external initializer {
    TelemedicineBase.initialize(
        _usdcToken, _sonicToken, _ethUsdPriceFeed, _sonicUsdPriceFeed,
        _entryPoint, _paymaster, _usdFiatOracle, _dataAccessOracle,
        _onRampProvider, _offRampProvider, _initialAdmins
    );
    __ReentrancyGuard_init();
    onRampFee = 0.001 ether;
    offRampFee = 0.002 ether;
}

// Process payment from a user
function processPayment(PaymentType _type, uint256 _amount) external payable nonReentrant {
    if (_type == PaymentType.ETH) {
        require(msg.value >= _amount, "Insufficient ETH: required amount not sent");
        if (msg.value > _amount) {
            refunds[msg.sender] += msg.value - _amount;
            emit AuditLog(block.timestamp, msg.sender, "ETH Refund Queued");
        }
    } else if (_type == PaymentType.USDC) {
        require(usdcToken.allowance(msg.sender, address(this)) >= _amount, "Insufficient USDC allowance");
        require(usdcToken.transferFrom(msg.sender, address(this), _amount), "USDC transfer failed");
    } else if (_type == PaymentType.SONIC) {
        require(sonicToken.allowance(msg.sender, address(this)) >= _amount, "Insufficient SONIC allowance");
        require(sonicToken.transferFrom(msg.sender, address(this), _amount), "SONIC transfer failed");
    } else {
        revert("Unsupported payment type");
    }
}

// Refund a patient
function refundPatient(address _patient, uint256 _amount, PaymentType _type) external onlyRole(ADMIN_ROLE) nonReentrant {
    if (_amount == 0) return;
    require(reserveFund >= RESERVE_FUND_THRESHOLD, "Reserve fund too low");
    if (_type == PaymentType.ETH) {
        require(address(this).balance >= _amount, "Insufficient ETH balance");
        refunds[_patient] += _amount;
        emit AuditLog(block.timestamp, msg.sender, "ETH Refund Queued");
    } else if (_type == PaymentType.USDC) {
        require(usdcToken.transfer(_patient, _amount), "USDC refund failed");
    } else if (_type == PaymentType.SONIC) {
        require(sonicToken.transfer(_patient, _amount), "SONIC refund failed");
    }
    _checkMinBalance(RESERVE_FUND_THRESHOLD);
}

// Request fiat-to-crypto conversion
function requestOnRamp(uint256 _fiatAmount, PaymentType _targetToken, string calldata _providerReference) external payable onlyRole(PATIENT_ROLE) nonReentrant {
    uint256 dynamicFee = _calculateDynamicFee(onRampFee);
    require(_fiatAmount > 0, "Fiat amount must be positive");
    require(msg.value >= dynamicFee, "Insufficient fee: required amount not sent");
    uint256 cryptoAmount = _calculateCryptoAmount(_fiatAmount, _targetToken);

    onRampCounter += 1;
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

    refunds[onRampProvider] += dynamicFee;
    emit AuditLog(block.timestamp, msg.sender, "ETH Fee Queued for OnRamp Provider");
    emit OnRampRequested(onRampCounter, msg.sender, _fiatAmount, _targetToken, _providerReference);
}

// Fulfill on-ramp request
function fulfillOnRamp(uint256 _requestId, bytes[] calldata _oracleSignatures) external onlyRole(ADMIN_ROLE) nonReentrant {
    OnRampRequest storage request = onRampRequests[_requestId];
    require(request.status == OnRampStatus.Pending, "Request not pending");
    (, , , uint256 updatedAt, ) = usdFiatOracle.latestRoundData();
    require(block.timestamp - updatedAt < 1 hours, "Stale oracle data");
    require(TelemedicineUtils.verifyMultiOracleConsensus(trustedOracles, _requestId, request.cryptoAmount, block.timestamp, _oracleSignatures), "Invalid oracle consensus");

    request.status = OnRampStatus.Fulfilled;
    if (request.targetToken == PaymentType.ETH) {
        require(address(this).balance >= request.cryptoAmount, "Insufficient ETH balance");
        refunds[request.user] += request.cryptoAmount;
        emit AuditLog(block.timestamp, msg.sender, "ETH Refund Queued");
    } else if (request.targetToken == PaymentType.USDC) {
        require(usdcToken.transfer(request.user, request.cryptoAmount), "USDC transfer failed");
    } else if (request.targetToken == PaymentType.SONIC) {
        require(sonicToken.transfer(request.user, request.cryptoAmount), "SONIC transfer failed");
    }
    emit OnRampFulfilled(_requestId, request.user, request.cryptoAmount);
}

// Fail an on-ramp request if timed out
function failOnRamp(uint256 _requestId, string calldata _reason) external onlyRole(ADMIN_ROLE) nonReentrant {
    OnRampRequest storage request = onRampRequests[_requestId];
    require(request.status == OnRampStatus.Pending, "Request not pending");
    require(block.timestamp > request.requestTimestamp + verificationTimeout, "Timeout not reached");
    request.status = OnRampStatus.Failed;
    emit OnRampFailed(_requestId, request.user, _reason);
}

// Request crypto-to-fiat conversion
function requestOffRamp(PaymentType _sourceToken, uint256 _cryptoAmount, string calldata _bankDetails) external payable onlyRole(PATIENT_ROLE) nonReentrant {
    uint256 dynamicFee = _calculateDynamicFee(offRampFee);
    require(_cryptoAmount > 0, "Crypto amount must be positive");
    require(msg.value >= dynamicFee, "Insufficient fee: required amount not sent");
    uint256 fiatAmount = _calculateFiatAmount(_cryptoAmount, _sourceToken);

    if (_sourceToken == PaymentType.ETH) {
        require(msg.value >= _cryptoAmount + dynamicFee, "Insufficient ETH: required amount not sent");
        if (msg.value > _cryptoAmount + dynamicFee) {
            refunds[msg.sender] += msg.value - (_cryptoAmount + dynamicFee);
            emit AuditLog(block.timestamp, msg.sender, "ETH Refund Queued");
        }
    } else if (_sourceToken == PaymentType.USDC) {
        require(usdcToken.transferFrom(msg.sender, address(this), _cryptoAmount), "USDC transfer failed");
    } else if (_sourceToken == PaymentType.SONIC) {
        require(sonicToken.transferFrom(msg.sender, address(this), _cryptoAmount), "SONIC transfer failed");
    }

    offRampCounter += 1;
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

    refunds[offRampProvider] += dynamicFee;
    emit AuditLog(block.timestamp, msg.sender, "ETH Fee Queued for OffRamp Provider");
    emit OffRampRequested(offRampCounter, msg.sender, _sourceToken, _cryptoAmount, _bankDetails);
}

// Lock off-ramp request
function lockOffRamp(uint256 _requestId) external onlyRole(ADMIN_ROLE) nonReentrant {
    OffRampRequest storage request = offRampRequests[_requestId];
    require(request.status == OffRampStatus.Pending, "Request not pending");
    request.status = OffRampStatus.Locked;
    emit OffRampLocked(_requestId, request.user, request.cryptoAmount);
}

// Fulfill off-ramp request
function fulfillOffRamp(uint256 _requestId, bytes[] calldata _oracleSignatures) external onlyRole(ADMIN_ROLE) nonReentrant {
    OffRampRequest storage request = offRampRequests[_requestId];
    require(request.status == OffRampStatus.Locked, "Request not locked");
    (, , , uint256 updatedAt, ) = usdFiatOracle.latestRoundData();
    require(block.timestamp - updatedAt < 1 hours, "Stale oracle data");
    require(TelemedicineUtils.verifyMultiOracleConsensus(trustedOracles, _requestId, request.fiatAmount, block.timestamp, _oracleSignatures), "Invalid oracle consensus");

    request.status = OffRampStatus.Fulfilled;
    emit OffRampFulfilled(_requestId, request.user, request.fiatAmount);
}

// Fail an off-ramp request if timed out
function failOffRamp(uint256 _requestId, string calldata _reason) external onlyRole(ADMIN_ROLE) nonReentrant {
    OffRampRequest storage request = offRampRequests[_requestId];
    require(request.status == OffRampStatus.Pending || request.status == OffRampStatus.Locked, "Request not active");
    require(block.timestamp > request.requestTimestamp + verificationTimeout, "Timeout not reached");
    request.status = OffRampStatus.Failed;
    if (request.sourceToken == PaymentType.ETH) {
        refunds[request.user] += request.cryptoAmount;
        emit AuditLog(block.timestamp, msg.sender, "ETH Refund Queued");
    } else if (request.sourceToken == PaymentType.USDC) {
        require(usdcToken.transfer(request.user, request.cryptoAmount), "USDC refund failed");
    } else if (request.sourceToken == PaymentType.SONIC) {
        require(sonicToken.transfer(request.user, request.cryptoAmount), "SONIC refund failed");
    }
    emit OffRampFailed(_requestId, request.user, _reason);
}

// Set ramp fees
function setRampFee(RampType _rampType, uint256 _newFee) external onlyRole(ADMIN_ROLE) {
    if (_rampType == RampType.OnRamp) {
        uint256 oldFee = onRampFee;
        onRampFee = _newFee;
        emit RampFeeUpdated(RampType.OnRamp, oldFee, _newFee);
    } else {
        uint256 oldFee = offRampFee;
        offRampFee = _newFee;
        emit RampFeeUpdated(RampType.OffRamp, oldFee, _newFee);
    }
}

// Calculate crypto amount from fiat
function _calculateCryptoAmount(uint256 _fiatAmount, PaymentType _targetToken) private view returns (uint256) {
    (, int256 usdPrice, , , ) = usdFiatOracle.latestRoundData();
    require(usdPrice > 0, "Invalid USD price");
    uint256 fiatInUsd = _fiatAmount * uint256(usdPrice) / 10**usdFiatOracle.decimals();

    if (_targetToken == PaymentType.ETH) {
        (, int256 ethPrice, , , ) = ethUsdPriceFeed.latestRoundData();
        require(ethPrice > 0, "Invalid ETH price");
        return fiatInUsd * 10**18 / uint256(ethPrice);
    } else if (_targetToken == PaymentType.USDC) {
        return fiatInUsd * 10**6 / 10**8;
    } else if (_targetToken == PaymentType.SONIC) {
        (, int256 sonicPrice, , , ) = sonicUsdPriceFeed.latestRoundData();
        require(sonicPrice > 0, "Invalid SONIC price");
        return fiatInUsd * 10**18 / uint256(sonicPrice);
    }
    revert("Unsupported target token");
}

// Calculate fiat amount from crypto
function _calculateFiatAmount(uint256 _cryptoAmount, PaymentType _sourceToken) private view returns (uint256) {
    (, int256 usdPrice, , , ) = usdFiatOracle.latestRoundData();
    require(usdPrice > 0, "Invalid USD price");

    if (_sourceToken == PaymentType.ETH) {
        (, int256 ethPrice, , , ) = ethUsdPriceFeed.latestRoundData();
        require(ethPrice > 0, "Invalid ETH price");
        return _cryptoAmount * uint256(ethPrice) / 10**18 * 10**usdFiatOracle.decimals() / uint256(usdPrice);
    } else if (_sourceToken == PaymentType.USDC) {
        return _cryptoAmount * 10**8 / 10**6 * 10**usdFiatOracle.decimals() / uint256(usdPrice);
    } else if (_sourceToken == PaymentType.SONIC) {
        (, int256 sonicPrice, , , ) = sonicUsdPriceFeed.latestRoundData();
        require(sonicPrice > 0, "Invalid SONIC price");
        return _cryptoAmount * uint256(sonicPrice) / 10**18 * 10**usdFiatOracle.decimals() / uint256(usdPrice);
    }
    revert("Unsupported source token");
}

// Calculate dynamic fee (simplified to base fee for now)
function _calculateDynamicFee(uint256 _baseFee) private pure returns (uint256) {
    return _baseFee; // Simplified; can be enhanced later if needed
}

}
</xaiArtifact>

