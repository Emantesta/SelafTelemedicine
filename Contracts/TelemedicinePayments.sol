<xaiArtifact artifact_id="b83c7ce2-14b6-4318-97ca-ad77c01830cb" artifact_version_id="5b5db18b-5ab5-4527-a0a9-510b4542e5b7" title="TelemedicinePayments.sol" contentType="text/solidity">
// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
import {Initializable} from "@openzeppelin
/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin
/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {SafeMathUpgradeable} from "@openzeppelin
/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";
import {IERC20Upgradeable} from "@openzeppelin
/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import {AggregatorV3Interface} from "@chainlink
/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";
import {TelemedicineCore} from "./TelemedicineCore.sol";
contract TelemedicinePayments is Initializable, ReentrancyGuardUpgradeable {
    using SafeMathUpgradeable for uint256;

TelemedicineCore public core;
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

function initialize(
    address _core,
    address _usdcToken,
    address _sonicToken,
    address _ethUsdPriceFeed,
    address _sonicUsdPriceFeed,
    address _usdFiatOracle,
    address _onRampProvider,
    address _offRampProvider
) external initializer {
    __ReentrancyGuard_init();
    core = TelemedicineCore(_core);
    usdcToken = IERC20Upgradeable(_usdcToken);
    sonicToken = IERC20Upgradeable(_sonicToken);
    ethUsdPriceFeed = AggregatorV3Interface(_ethUsdPriceFeed);
    sonicUsdPriceFeed = AggregatorV3Interface(_sonicUsdPriceFeed);
    usdFiatOracle = AggregatorV3Interface(_usdFiatOracle);
    onRampProvider = _onRampProvider;
    offRampProvider = _offRampProvider;
    trustedOracles.push(_ethUsdPriceFeed);
    trustedOracles.push(_sonicUsdPriceFeed);
    trustedOracles.push(_usdFiatOracle);
    onRampFee = 0.001 ether;
    offRampFee = 0.002 ether;
}

function requestOnRamp(uint256 _fiatAmount, PaymentType _targetToken, string calldata _providerReference) external payable onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
    uint256 dynamicFee = _calculateDynamicFee(onRampFee);
    require(_fiatAmount > 0, "Fiat amount must be positive");
    require(msg.value >= dynamicFee, "Insufficient fee");
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

    (bool success, ) = onRampProvider.call{value: msg.value}("");
    require(success, "Fee transfer failed");
    emit OnRampRequested(onRampCounter, msg.sender, _fiatAmount, _targetToken, _providerReference);
}

function fulfillOnRamp(uint256 _requestId, bytes[] calldata _oracleSignatures) external onlyRole(core.ADMIN_ROLE()) nonReentrant whenNotPaused {
    OnRampRequest storage request = onRampRequests[_requestId];
    require(request.status == OnRampStatus.Pending, "Request not pending");
    require(_verifyMultiOracleConsensus(_requestId, request.cryptoAmount, _oracleSignatures), "Invalid oracle consensus");

    request.status = OnRampStatus.Fulfilled;
    if (request.targetToken == PaymentType.ETH) {
        require(address(this).balance >= request.cryptoAmount, "Insufficient ETH balance");
        (bool success, ) = request.user.call{value: request.cryptoAmount}("");
        require(success, "ETH transfer failed");
    } else if (request.targetToken == PaymentType.USDC) {
        require(usdcToken.transfer(request.user, request.cryptoAmount), "USDC transfer failed");
    } else if (request.targetToken == PaymentType.SONIC) {
        require(sonicToken.transfer(request.user, request.cryptoAmount), "SONIC transfer failed");
    }
    emit OnRampFulfilled(_requestId, request.user, request.cryptoAmount);
}

function failOnRamp(uint256 _requestId, string calldata _reason) external onlyRole(core.ADMIN_ROLE()) whenNotPaused {
    OnRampRequest storage request = onRampRequests[_requestId];
    require(request.status == OnRampStatus.Pending, "Request not pending");
    request.status = OnRampStatus.Failed;
    emit OnRampFailed(_requestId, request.user, _reason);
}

function requestOffRamp(PaymentType _sourceToken, uint256 _cryptoAmount, string calldata _bankDetails) external payable onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
    uint256 dynamicFee = _calculateDynamicFee(offRampFee);
    require(_cryptoAmount > 0, "Crypto amount must be positive");
    require(msg.value >= dynamicFee, "Insufficient fee");
    uint256 fiatAmount = _calculateFiatAmount(_cryptoAmount, _sourceToken);

    if (_sourceToken == PaymentType.ETH) {
        require(msg.value >= _cryptoAmount.add(dynamicFee), "Insufficient ETH");
    } else if (_sourceToken == PaymentType.USDC) {
        require(usdcToken.transferFrom(msg.sender, address(this), _cryptoAmount), "USDC transfer failed");
    } else if (_sourceToken == PaymentType.SONIC) {
        require(sonicToken.transferFrom(msg.sender, address(this), _cryptoAmount), "SONIC transfer failed");
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

    (bool success, ) = offRampProvider.call{value: dynamicFee}("");
    require(success, "Fee transfer failed");
    emit OffRampRequested(offRampCounter, msg.sender, _sourceToken, _cryptoAmount, _bankDetails);
}

function lockOffRamp(uint256 _requestId) external onlyRole(core.ADMIN_ROLE()) nonReentrant whenNotPaused {
    OffRampRequest storage request = offRampRequests[_requestId];
    require(request.status == OffRampStatus.Pending, "Request not pending");
    request.status = OffRampStatus.Locked;
    emit OffRampLocked(_requestId, request.user, request.cryptoAmount);
}

function fulfillOffRamp(uint256 _requestId, bytes[] calldata _oracleSignatures) external onlyRole(core.ADMIN_ROLE()) nonReentrant whenNotPaused {
    OffRampRequest storage request = offRampRequests[_requestId];
    require(request.status == OffRampStatus.Locked, "Request not locked");
    require(_verifyMultiOracleConsensus(_requestId, request.fiatAmount, _oracleSignatures), "Invalid oracle consensus");

    request.status = OffRampStatus.Fulfilled;
    emit OffRampFulfilled(_requestId, request.user, request.fiatAmount);
}

function failOffRamp(uint256 _requestId, string calldata _reason) external onlyRole(core.ADMIN_ROLE()) nonReentrant whenNotPaused {
    OffRampRequest storage request = offRampRequests[_requestId];
    require(request.status == OffRampStatus.Pending || request.status == OffRampStatus.Locked, "Request not active");
    request.status = OffRampStatus.Failed;

    if (request.sourceToken == PaymentType.ETH) {
        require(address(this).balance >= request.cryptoAmount, "Insufficient ETH for refund");
        (bool success, ) = request.user.call{value: request.cryptoAmount}("");
        require(success, "ETH refund failed");
    } else if (request.sourceToken == PaymentType.USDC) {
        require(usdcToken.transfer(request.user, request.cryptoAmount), "USDC refund failed");
    } else if (request.sourceToken == PaymentType.SONIC) {
        require(sonicToken.transfer(request.user, request.cryptoAmount), "SONIC refund failed");
    }
    emit OffRampFailed(_requestId, request.user, _reason);
}

function updateOnRampProvider(address _newProvider) external onlyRole(core.ADMIN_ROLE()) {
    require(_newProvider != address(0), "On-ramp provider address cannot be zero");
    address oldProvider = onRampProvider;
    onRampProvider = _newProvider;
    emit OnRampProviderUpdated(oldProvider, _newProvider);
}

function updateOffRampProvider(address _newProvider) external onlyRole(core.ADMIN_ROLE()) {
    require(_newProvider != address(0), "Off-ramp provider address cannot be zero");
    address oldProvider = offRampProvider;
    offRampProvider = _newProvider;
    emit OffRampProviderUpdated(oldProvider, _newProvider);
}

function updateEthUsdPriceFeed(address _newFeed) external onlyRole(core.ADMIN_ROLE()) {
    require(_newFeed != address(0), "ETH/USD price feed address cannot be zero");
    address oldFeed = address(ethUsdPriceFeed);
    ethUsdPriceFeed = AggregatorV3Interface(_newFeed);
    _updateTrustedOracle(oldFeed, _newFeed);
    emit PriceFeedUpdated("ETH/USD", oldFeed, _newFeed);
}

function updateSonicUsdPriceFeed(address _newFeed) external onlyRole(core.ADMIN_ROLE()) {
    require(_newFeed != address(0), "Sonic/USD price feed address cannot be zero");
    address oldFeed = address(sonicUsdPriceFeed);
    sonicUsdPriceFeed = AggregatorV3Interface(_newFeed);
    _updateTrustedOracle(oldFeed, _newFeed);
    emit PriceFeedUpdated("Sonic/USD", oldFeed, _newFeed);
}

function updateUsdFiatOracle(address _newOracle) external onlyRole(core.ADMIN_ROLE()) {
    require(_newOracle != address(0), "USD fiat oracle address cannot be zero");
    address oldOracle = address(usdFiatOracle);
    usdFiatOracle = AggregatorV3Interface(_newOracle);
    _updateTrustedOracle(oldOracle, _newOracle);
    emit PriceFeedUpdated("USD/Fiat", oldOracle, _newOracle);
}

function _processPayment(PaymentType _type, uint256 _amount) internal {
    if (_type == PaymentType.USDC) {
        require(usdcToken.allowance(msg.sender, address(this)) >= _amount, "Insufficient USDC allowance");
        require(usdcToken.transferFrom(msg.sender, address(this), _amount), "USDC transfer failed");
    } else if (_type == PaymentType.SONIC) {
        require(sonicToken.allowance(msg.sender, address(this)) >= _amount, "Insufficient SONIC allowance");
        require(sonicToken.transferFrom(msg.sender, address(this), _amount), "SONIC transfer failed");
    } else {
        revert("Unsupported payment type");
    }
}

function _refundPatient(address _patient, uint256 _amount, PaymentType _type) internal {
    if (_amount == 0) return;
    require(core.getReserveFundBalance() >= core.RESERVE_FUND_THRESHOLD(), "Reserve fund too low");
    if (_type == PaymentType.ETH) {
        require(address(this).balance >= _amount, "Insufficient ETH balance");
        (bool success, ) = _patient.call{value: _amount}("");
        require(success, "ETH refund failed");
    } else if (_type == PaymentType.USDC) {
        require(usdcToken.transfer(_patient, _amount), "USDC refund failed");
    } else if (_type == PaymentType.SONIC) {
        require(sonicToken.transfer(_patient, _amount), "SONIC refund failed");
    }
}

function _calculateCryptoAmount(uint256 _fiatAmount, PaymentType _targetToken) internal view returns (uint256) {
    (, int256 usdPrice, , , ) = usdFiatOracle.latestRoundData();
    require(usdPrice > 0, "Invalid USD price");
    uint256 fiatInUsd = _fiatAmount.mul(uint256(usdPrice)).div(10**usdFiatOracle.decimals());

    if (_targetToken == PaymentType.ETH) {
        (, int256 ethPrice, , , ) = ethUsdPriceFeed.latestRoundData();
        require(ethPrice > 0, "Invalid ETH price");
        return fiatInUsd.mul(10**18).div(uint256(ethPrice));
    } else if (_targetToken == PaymentType.USDC) {
        return fiatInUsd.mul(10**6).div(10**8);
    } else if (_targetToken == PaymentType.SONIC) {
        (, int256 sonicPrice, , , ) = sonicUsdPriceFeed.latestRoundData();
        require(sonicPrice > 0, "Invalid SONIC price");
        return fiatInUsd.mul(10**18).div(uint256(sonicPrice));
    }
    revert("Unsupported target token");
}

function _calculateFiatAmount(uint256 _cryptoAmount, PaymentType _sourceToken) internal view returns (uint256) {
    (, int256 usdPrice, , , ) = usdFiatOracle.latestRoundData();
    require(usdPrice > 0, "Invalid USD price");

    if (_sourceToken == PaymentType.ETH) {
        (, int256 ethPrice, , , ) = ethUsdPriceFeed.latestRoundData();
        require(ethPrice > 0, "Invalid ETH price");
        return _cryptoAmount.mul(uint256(ethPrice)).div(10**18).mul(10**usdFiatOracle.decimals()).div(uint256(usdPrice));
    } else if (_sourceToken == PaymentType.USDC) {
        return _cryptoAmount.mul(10**8).div(10**6).mul(10**usdFiatOracle.decimals()).div(uint256(usdPrice));
    } else if (_sourceToken == PaymentType.SONIC) {
        (, int256 sonicPrice, , , ) = sonicUsdPriceFeed.latestRoundData();
        require(sonicPrice > 0, "Invalid SONIC price");
        return _cryptoAmount.mul(uint256(sonicPrice)).div(10**18).mul(10**usdFiatOracle.decimals()).div(uint256(usdPrice));
    }
    revert("Unsupported source token");
}

function _calculateDynamicFee(uint256 _baseFee) internal view returns (uint256) {
    (, int256 ethPrice, , , ) = ethUsdPriceFeed.latestRoundData();
    require(ethPrice > 0, "Invalid ETH price");
    uint256 adjustmentFactor = uint256(ethPrice).mul(10**18).div(2000 * 10**8);
    return _baseFee.mul(adjustmentFactor > 10**18 ? adjustmentFactor : 10**18).div(10**18);
}

function _verifyMultiOracleConsensus(uint256 _id, uint256 _value, bytes[] calldata _signatures) internal view returns (bool) {
    require(_signatures.length >= trustedOracles.length / 2 + 1, "Insufficient signatures");
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

function recoverSigner(bytes32 message, bytes memory signature) internal pure returns (address) {
    bytes32 r;
    bytes32 s;
    uint8 v;
    if (signature.length != 65) revert("Invalid signature length");
    assembly {
        r := mload(add(signature, 32))
        s := mload(add(signature, 64))
        v := byte(0, mload(add(signature, 96)))
    }
    if (v < 27) v += 27;
    require(v == 27 || v == 28, "Invalid v value");
    return ecrecover(message, v, r, s);
}

modifier onlyRole(bytes32 role) {
    require(core.hasRole(role, msg.sender), "Unauthorized");
    _;
}

modifier whenNotPaused() {
    require(!core.paused(), "Pausable: paused");
    _;
}

}
</xaiArtifact>

