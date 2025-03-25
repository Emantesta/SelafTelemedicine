<xaiArtifact artifact_id="f1fd40f6-2f41-46ac-b99e-7707bb7855de" artifact_version_id="5c1f361c-13cf-4a32-ade2-879b8fdf07d5" title="TelemedicineBase.sol" contentType="text/solidity">
// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
import {Initializable} from "@openzeppelin
/contracts-upgradeable/proxy/utils/Initializable.sol";
import {AccessControlUpgradeable} from "@openzeppelin
/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin
/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {IERC20Upgradeable} from "@openzeppelin
/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import {AggregatorV3Interface} from "@chainlink
/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";
import {IEntryPoint} from "@account
-abstraction/contracts/interfaces/IEntryPoint.sol";
contract TelemedicineBase is Initializable, AccessControlUpgradeable, ReentrancyGuardUpgradeable {
    // Role Definitions
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant DOCTOR_ROLE = keccak256("DOCTOR_ROLE");
    bytes32 public constant PATIENT_ROLE = keccak256("PATIENT_ROLE");
    bytes32 public constant LAB_TECH_ROLE = keccak256("LAB_TECH_ROLE");
    bytes32 public constant PHARMACY_ROLE = keccak256("PHARMACY_ROLE");

// External Contracts
IERC20Upgradeable public usdcToken;
IERC20Upgradeable public sonicToken;
AggregatorV3Interface public ethUsdPriceFeed;
AggregatorV3Interface public sonicUsdPriceFeed;
IEntryPoint public entryPoint;
address public paymaster;
AggregatorV3Interface public usdFiatOracle;
address public dataAccessOracle;
address public onRampProvider;
address public offRampProvider;
address[] public trustedOracles;
address[] public admins;

// Configuration Variables
uint256 public minBookingBuffer;
uint256 public minCancellationBuffer;
uint256 public verificationTimeout;
uint256 public timeLockDelay;
uint256 public requiredApprovals;
uint256 public emergencyDelay;
uint256 public maxEmergencyWithdrawal;
uint256 public emergencyRoleDuration;
uint256 public versionNumber;

// Constants
uint256 public constant MAX_ADMINS = 10;
uint256 public constant MIN_TIMELOCK_DELAY = 2 days;
uint256 public constant RESERVE_FUND_THRESHOLD = 1 ether;

// State Variables
mapping(address => uint256) public nonces;
mapping(address => bool) public trustedPaymasters;
uint256 public reserveFund;
mapping(address => uint256) public refunds; // For safe ETH withdrawals

// Events
event AuditLog(uint256 indexed timestamp, address indexed actor, string action);
event EntryPointUpdated(address indexed oldEntryPoint, address indexed newEntryPoint);
event PaymasterUpdated(address indexed oldPaymaster, address indexed newPaymaster);
event TrustedPaymasterAdded(address indexed paymaster);
event TrustedPaymasterRemoved(address indexed paymaster);
event ReserveFundDeposited(address indexed sender, uint256 amount);
event MinBalanceAlert(address indexed contractAddress, uint256 balance);
event RefundWithdrawn(address indexed user, uint256 amount);

/// @custom:oz-upgrades-unsafe-allow constructor
constructor() {
    _disableInitializers();
}

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
    __AccessControl_init();
    __ReentrancyGuard_init();

    require(_usdcToken != address(0), "USDC token address cannot be zero");
    require(_sonicToken != address(0), "Sonic token address cannot be zero");
    require(_ethUsdPriceFeed != address(0), "ETH/USD price feed address cannot be zero");
    require(_sonicUsdPriceFeed != address(0), "Sonic/USD price feed address cannot be zero");
    require(_entryPoint != address(0), "Entry point address cannot be zero");
    require(_paymaster != address(0), "Paymaster address cannot be zero");
    require(_usdFiatOracle != address(0), "USD fiat oracle address cannot be zero");
    require(_dataAccessOracle != address(0), "Data access oracle address cannot be zero");
    require(_onRampProvider != address(0), "On-ramp provider address cannot be zero");
    require(_offRampProvider != address(0), "Off-ramp provider address cannot be zero");
    require(_initialAdmins.length >= 2 && _initialAdmins.length <= MAX_ADMINS, "Invalid initial admin count");

    _setRoleAdmin(ADMIN_ROLE, ADMIN_ROLE);
    _setRoleAdmin(DOCTOR_ROLE, ADMIN_ROLE);
    _setRoleAdmin(PATIENT_ROLE, ADMIN_ROLE);
    _setRoleAdmin(LAB_TECH_ROLE, ADMIN_ROLE);
    _setRoleAdmin(PHARMACY_ROLE, ADMIN_ROLE);

    for (uint256 i = 0; i < _initialAdmins.length; i++) {
        require(_initialAdmins[i] != address(0), "Admin address cannot be zero");
        _grantRole(ADMIN_ROLE, _initialAdmins[i]);
        admins.push(_initialAdmins[i]);
    }

    usdcToken = IERC20Upgradeable(_usdcToken);
    sonicToken = IERC20Upgradeable(_sonicToken);
    ethUsdPriceFeed = AggregatorV3Interface(_ethUsdPriceFeed);
    sonicUsdPriceFeed = AggregatorV3Interface(_sonicUsdPriceFeed);
    entryPoint = IEntryPoint(_entryPoint);
    paymaster = _paymaster;
    trustedPaymasters[_paymaster] = true;
    usdFiatOracle = AggregatorV3Interface(_usdFiatOracle);
    dataAccessOracle = _dataAccessOracle;
    onRampProvider = _onRampProvider;
    offRampProvider = _offRampProvider;
    trustedOracles.push(_ethUsdPriceFeed);
    trustedOracles.push(_sonicUsdPriceFeed);
    trustedOracles.push(_usdFiatOracle);

    minBookingBuffer = 15 minutes;
    minCancellationBuffer = 1 hours;
    verificationTimeout = 7 days;
    timeLockDelay = MIN_TIMELOCK_DELAY;
    requiredApprovals = _initialAdmins.length / 2 + 1;
    emergencyDelay = 1 hours;
    maxEmergencyWithdrawal = 10 ether;
    emergencyRoleDuration = 1 days;
    versionNumber = 1;

    emit AuditLog(block.timestamp, msg.sender, "Base Contract Initialized");
}

function updateEntryPoint(address _newEntryPoint) external onlyRole(ADMIN_ROLE) {
    require(_newEntryPoint != address(0), "EntryPoint address cannot be zero");
    address oldEntryPoint = address(entryPoint);
    entryPoint = IEntryPoint(_newEntryPoint);
    emit EntryPointUpdated(oldEntryPoint, _newEntryPoint);
    emit AuditLog(block.timestamp, msg.sender, "EntryPoint Updated");
}

function updatePaymaster(address _newPaymaster) external onlyRole(ADMIN_ROLE) {
    require(_newPaymaster != address(0), "Paymaster address cannot be zero");
    address oldPaymaster = paymaster;
    paymaster = _newPaymaster;
    trustedPaymasters[_newPaymaster] = true;
    trustedPaymasters[oldPaymaster] = false;
    emit PaymasterUpdated(oldPaymaster, _newPaymaster);
}

function addTrustedPaymaster(address _paymaster) external onlyRole(ADMIN_ROLE) {
    require(_paymaster != address(0), "Paymaster address cannot be zero");
    require(!trustedPaymasters[_paymaster], "Paymaster already trusted");
    trustedPaymasters[_paymaster] = true;
    emit TrustedPaymasterAdded(_paymaster);
}

function removeTrustedPaymaster(address _paymaster) external onlyRole(ADMIN_ROLE) {
    require(_paymaster != address(0), "Paymaster address cannot be zero");
    require(trustedPaymasters[_paymaster], "Paymaster not trusted");
    require(_paymaster != paymaster, "Cannot remove primary paymaster");
    trustedPaymasters[_paymaster] = false;
    emit TrustedPaymasterRemoved(_paymaster);
}

function withdrawRefund() external nonReentrant {
    uint256 amount = refunds[msg.sender];
    require(amount > 0, "No refund available");
    refunds[msg.sender] = 0;
    (bool success, ) = payable(msg.sender).call{value: amount}("");
    require(success, "Refund transfer failed");
    emit RefundWithdrawn(msg.sender, amount);
}

function _checkMinBalance(uint256 minReserveBalance) internal {
    if (address(this).balance < minReserveBalance) {
        emit MinBalanceAlert(address(this), address(this).balance);
    }
}

receive() external payable {
    reserveFund += msg.value;
    emit ReserveFundDeposited(msg.sender, msg.value);
    _checkMinBalance(RESERVE_FUND_THRESHOLD);
}

}
</xaiArtifact>

