// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
import {Initializable} from "@openzeppelin
/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin
/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {SafeMathUpgradeable} from "@openzeppelin
/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";
import {IEntryPoint} from "@account
-abstraction/contracts/interfaces/IEntryPoint.sol";
import {UserOperation} from "@account
-abstraction/contracts/interfaces/UserOperation.sol";
import {TelemedicineCore} from "./TelemedicineCore.sol";
import {TelemedicineMedical} from "./TelemedicineMedical.sol";
import {TelemedicinePayments} from "./TelemedicinePayments.sol";
contract TelemedicineGovernanceCore is Initializable, ReentrancyGuardUpgradeable {
    using SafeMathUpgradeable for uint256;

TelemedicineCore public core;
TelemedicineMedical public medical;
TelemedicinePayments public payments;

IEntryPoint public entryPoint;
address public paymaster;
address public dataAccessOracle;

uint256 public timeLockDelay;
uint256 public requiredApprovals;
uint256 public constant MIN_TIMELOCK_DELAY = 2 days;

mapping(address => uint256) public nonces;
mapping(address => bool) public trustedPaymasters;
mapping(uint256 => TimeLock) public timeLocks;
uint256 public timeLockCounter;

enum TimeLockAction { WithdrawFunds, AddAdmin, RemoveAdmin, AdjustFee, AdjustMaxEmergencyWithdrawal, UpgradeContract }

struct TimeLock {
    uint256 id;
    TimeLockAction action;
    address target;
    uint256 value;
    bytes data;
    uint256 timestamp;
    mapping(address => bool) approvals;
    uint256 approvalCount;
    bool executed;
    bool cancelled;
}

event PaymasterUpdated(address indexed oldPaymaster, address indexed newPaymaster);
event UserOperationExecuted(address indexed sender, uint256 nonce, bytes32 hash);
event TrustedPaymasterAdded(address indexed paymaster);
event TrustedPaymasterRemoved(address indexed paymaster);
event TimeLockQueued(uint256 indexed id, TimeLockAction action, address target, uint256 value, bytes data, uint256 timestamp);
event TimeLockApproved(uint256 indexed id, address indexed approver);
event TimeLockExecuted(uint256 indexed id);
event TimeLockCancelled(uint256 indexed id, address indexed canceller);
event ConstantUpdated(string indexed name, uint256 newValue);
event DoctorFeeAdjustmentRequested(address indexed doctor, uint256 newFee, uint256 timeLockId);
event GamificationParameterUpdated(string indexed parameter, uint256 newValue);
event EntryPointUpdated(address indexed oldEntryPoint, address indexed newEntryPoint);

/// @custom:oz-upgrades-unsafe-allow constructor
constructor() {
    _disableInitializers();
}

function initialize(
    address _core,
    address _medical,
    address _payments,
    address _entryPoint,
    address _paymaster,
    address _dataAccessOracle
) external initializer {
    __ReentrancyGuard_init();
    core = TelemedicineCore(_core);
    medical = TelemedicineMedical(_medical);
    payments = TelemedicinePayments(_payments);
    entryPoint = IEntryPoint(_entryPoint);
    paymaster = _paymaster;
    dataAccessOracle = _dataAccessOracle;
    trustedPaymasters[_paymaster] = true;
    timeLockDelay = MIN_TIMELOCK_DELAY;
    requiredApprovals = core.admins().length / 2 + 1;
}

function transfer(address payable _to, uint256 _amount) external onlyRole(core.ADMIN_ROLE()) nonReentrant {
    require(_to != address(0), "Invalid recipient");
    require(_amount <= address(this).balance, "Insufficient balance");
    (bool success, ) = _to.call{value: _amount}("");
    require(success, "Transfer failed");
}

function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds) 
    external 
    onlyEntryPoint 
    whenNotPaused 
    returns (uint256 validationData) 
{
    require(nonces[userOp.sender] == userOp.nonce, "Invalid nonce");
    bytes32 messageHash = keccak256(abi.encodePacked("\x19\x01", block.chainid, address(this), userOpHash));
    address signer = recoverSigner(messageHash, userOp.signature);
    require(signer == userOp.sender, "Invalid signature");

    nonces[userOp.sender] = nonces[userOp.sender].add(1);
    if (missingAccountFunds > 0) {
        require(trustedPaymasters[msg.sender], "Caller not trusted paymaster");
        (bool success, ) = paymaster.call{value: missingAccountFunds}("");
        require(success, "Paymaster payment failed");
    }

    emit UserOperationExecuted(userOp.sender, userOp.nonce, userOpHash);
    return 0;
}

function executeUserOp(UserOperation calldata userOp) external onlyEntryPoint nonReentrant whenNotPaused {
    require(
        core.hasRole(core.PATIENT_ROLE(), userOp.sender) || 
        userOp.sender == msg.sender || 
        core.hasRole(core.DOCTOR_ROLE(), userOp.sender),
        "Unauthorized sender"
    );

    (bool success, bytes memory result) = address(this).call(userOp.callData);
    require(success, string(abi.encodePacked("User op failed: ", _getRevertMsg(result))));
    if (userOp.callGasLimit > 0) {
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = userOp;
        entryPoint.handleOps(ops, payable(msg.sender));
    }
}

function updatePaymaster(address _newPaymaster) external onlyRole(core.ADMIN_ROLE()) whenNotPaused {
    require(_newPaymaster != address(0), "Paymaster address cannot be zero");
    address oldPaymaster = paymaster;
    paymaster = _newPaymaster;
    trustedPaymasters[_newPaymaster] = true;
    trustedPaymasters[oldPaymaster] = false;
    emit PaymasterUpdated(oldPaymaster, _newPaymaster);
}

function addTrustedPaymaster(address _paymaster) external onlyRole(core.ADMIN_ROLE()) whenNotPaused {
    require(_paymaster != address(0), "Paymaster address cannot be zero");
    require(!trustedPaymasters[_paymaster], "Paymaster already trusted");
    trustedPaymasters[_paymaster] = true;
    emit TrustedPaymasterAdded(_paymaster);
}

function removeTrustedPaymaster(address _paymaster) external onlyRole(core.ADMIN_ROLE()) whenNotPaused {
    require(_paymaster != address(0), "Paymaster address cannot be zero");
    require(trustedPaymasters[_paymaster], "Paymaster not trusted");
    require(_paymaster != paymaster, "Cannot remove primary paymaster");
    trustedPaymasters[_paymaster] = false;
    emit TrustedPaymasterRemoved(_paymaster);
}

function updateEntryPoint(address _newEntryPoint) external onlyRole(core.ADMIN_ROLE()) {
    require(_newEntryPoint != address(0), "EntryPoint address cannot be zero");
    address oldEntryPoint = address(entryPoint);
    entryPoint = IEntryPoint(_newEntryPoint);
    emit EntryPointUpdated(oldEntryPoint, _newEntryPoint);
}

function updateDataAccessOracle(address _newOracle) external onlyRole(core.ADMIN_ROLE()) {
    require(_newOracle != address(0), "Data access oracle address cannot be zero");
    dataAccessOracle = _newOracle;
    emit ConstantUpdated("dataAccessOracle", uint256(uint160(_newOracle)));
}

function updateRampFee(string calldata _rampType, uint256 _newFee) external onlyRole(core.ADMIN_ROLE()) {
    bytes memory data = abi.encodeWithSignature("setRampFee(string,uint256)", _rampType, _newFee);
    _queueTimeLock(TimeLockAction.AdjustFee, address(payments), _newFee, data);
}

function setRampFee(string calldata _rampType, uint256 _newFee) external onlyRole(core.ADMIN_ROLE()) {
    if (keccak256(abi.encodePacked(_rampType)) == keccak256(abi.encodePacked("onRamp"))) {
        payments.onRampFee = _newFee;
    } else if (keccak256(abi.encodePacked(_rampType)) == keccak256(abi.encodePacked("offRamp"))) {
        payments.offRampFee = _newFee;
    } else {
        revert("Invalid ramp type");
    }
    emit ConstantUpdated(_rampType, _newFee);
}

function setDiscountLevel(uint8 _level, uint256 _percentage) external onlyRole(core.ADMIN_ROLE()) {
    require(_level <= core.maxLevel(), "Level exceeds maxLevel");
    require(_percentage <= 100, "Discount percentage cannot exceed 100");
    core.discountLevels(_level) = _percentage;
    emit GamificationParameterUpdated("discountLevel", _percentage);
}

function setPointsForAction(string calldata _action, uint256 _points) external onlyRole(core.ADMIN_ROLE()) {
    require(_points > 0, "Points must be positive");
    core.pointsForActions(_action) = _points;
    emit GamificationParameterUpdated(_action, _points);
}

function updateMinBookingBuffer(uint256 _newBuffer) external onlyRole(core.ADMIN_ROLE()) {
    require(_newBuffer >= 5 minutes, "Buffer must be at least 5 minutes");
    core.minBookingBuffer = _newBuffer;
    emit ConstantUpdated("minBookingBuffer", _newBuffer);
}

function updateMinCancellationBuffer(uint256 _newBuffer) external onlyRole(core.ADMIN_ROLE()) {
    require(_newBuffer >= 30 minutes, "Buffer must be at least 30 minutes");
    core.minCancellationBuffer = _newBuffer;
    emit ConstantUpdated("minCancellationBuffer", _newBuffer);
}

function updateVerificationTimeout(uint256 _newTimeout) external onlyRole(core.ADMIN_ROLE()) {
    require(_newTimeout >= 1 days, "Timeout must be at least 1 day");
    core.verificationTimeout = _newTimeout;
    emit ConstantUpdated("verificationTimeout", _newTimeout);
}

function updateDataMonetizationReward(uint256 _newReward) external onlyRole(core.ADMIN_ROLE()) {
    require(_newReward > 0, "Reward must be positive");
    require(payments.sonicToken().balanceOf(address(payments)) >= _newReward, "Insufficient SONIC balance");
    core.dataMonetizationReward = _newReward;
    emit ConstantUpdated("dataMonetizationReward", _newReward);
}

function updateAIAnalysisCost(uint256 _newCost) external onlyRole(core.ADMIN_ROLE()) {
    require(_newCost > 0, "Cost must be positive");
    core.aiAnalysisCost = _newCost;
    emit ConstantUpdated("aiAnalysisCost", _newCost);
}

function updateTimeLockDelay(uint256 _newDelay) external onlyRole(core.ADMIN_ROLE()) {
    require(_newDelay >= MIN_TIMELOCK_DELAY, "Delay must be at least 2 days");
    timeLockDelay = _newDelay;
    emit ConstantUpdated("timeLockDelay", _newDelay);
}

function updateRequiredApprovals(uint256 _newApprovals) external onlyRole(core.ADMIN_ROLE()) {
    require(_newApprovals >= 1 && _newApprovals <= core.admins().length, "Invalid approval count");
    requiredApprovals = _newApprovals;
    emit ConstantUpdated("requiredApprovals", _newApprovals);
}

function updatePointsPerLevel(uint256 _newPoints) external onlyRole(core.ADMIN_ROLE()) {
    require(_newPoints > 0, "Points per level must be positive");
    core.pointsPerLevel = _newPoints;
    emit GamificationParameterUpdated("pointsPerLevel", _newPoints);
}

function updateMaxLevel(uint8 _newMax) external onlyRole(core.ADMIN_ROLE()) {
    require(_newMax > 0, "Max level must be positive");
    core.maxLevel = _newMax;
    emit GamificationParameterUpdated("maxLevel", _newMax);
}

function updateDecayRate(uint256 _newRate) external onlyRole(core.ADMIN_ROLE()) {
    require(_newRate > 0, "Decay rate must be positive");
    core.decayRate = _newRate;
    emit GamificationParameterUpdated("decayRate", _newRate);
}

function updateDecayPeriod(uint256 _newPeriod) external onlyRole(core.ADMIN_ROLE()) {
    require(_newPeriod >= 1 days, "Period must be at least 1 day");
    core.decayPeriod = _newPeriod;
    emit GamificationParameterUpdated("decayPeriod", _newPeriod);
}

function updateFreeAnalysisPeriod(uint256 _newPeriod) external onlyRole(core.ADMIN_ROLE()) {
    require(_newPeriod >= 7 days, "Period must be at least 7 days");
    core.freeAnalysisPeriod = _newPeriod;
    emit GamificationParameterUpdated("freeAnalysisPeriod", _newPeriod);
}

function updateMinReserveBalance(uint256 _newMin) external onlyRole(core.ADMIN_ROLE()) {
    require(_newMin >= core.RESERVE_FUND_THRESHOLD(), "Below threshold");
    core.minReserveBalance = _newMin;
    emit ConstantUpdated("minReserveBalance", _newMin);
}

function queueWithdrawFunds(address payable _to, uint256 _amount) external onlyRole(core.ADMIN_ROLE()) {
    require(_to != address(0), "Recipient address cannot be zero");
    require(_amount <= core.getContractBalance().sub(core.getReserveFundBalance()), "Insufficient balance excluding reserve");
    bytes memory data = abi.encodeWithSignature("transfer(address,uint256)", _to, _amount);
    _queueTimeLock(TimeLockAction.WithdrawFunds, _to, _amount, data);
}

function requestFeeAdjustment(uint256 _newFee) external onlyRole(core.DOCTOR_ROLE()) whenNotPaused {
    require(core.doctors(msg.sender).isVerified, "Doctor not verified");
    require(_newFee <= type(uint96).max, "Fee exceeds uint96 maximum");
    bytes memory data = abi.encodeWithSignature("updateDoctorFee(address,uint256)", msg.sender, _newFee);
    uint256 timeLockId = _queueTimeLock(TimeLockAction.AdjustFee, msg.sender, _newFee, data);
    emit DoctorFeeAdjustmentRequested(msg.sender, _newFee, timeLockId);
}

function updateDoctorFee(address _doctor, uint256 _newFee) external onlyRole(core.ADMIN_ROLE()) {
    require(_newFee <= type(uint96).max, "Fee exceeds uint96 maximum");
    core.doctors(_doctor).consultationFee = uint96(_newFee);
}

function queueAddAdmin(address _newAdmin) external onlyRole(core.ADMIN_ROLE()) whenNotPaused {
    require(_newAdmin != address(0), "Admin address cannot be zero");
    require(core.admins().length < core.MAX_ADMINS(), "Max admins reached");
    bytes memory data = abi.encodeWithSignature("grantRole(bytes32,address)", core.ADMIN_ROLE(), _newAdmin);
    _queueTimeLock(TimeLockAction.AddAdmin, _newAdmin, 0, data);
}

function queueRemoveAdmin(address _admin) external onlyRole(core.ADMIN_ROLE()) whenNotPaused {
    require(_admin != address(0), "Admin address cannot be zero");
    require(core.admins().length > 1, "Cannot remove last admin");
    bytes memory data = abi.encodeWithSignature("revokeRole(bytes32,address)", core.ADMIN_ROLE(), _admin);
    _queueTimeLock(TimeLockAction.RemoveAdmin, _admin, 0, data);
}

function approveTimeLock(uint256 _timeLockId) external onlyRole(core.ADMIN_ROLE()) whenNotPaused {
    TimeLock storage tl = timeLocks[_timeLockId];
    require(!tl.executed, "Already executed");
    require(!tl.cancelled, "Cancelled");
    require(!tl.approvals[msg.sender], "Already approved");
    tl.approvals[msg.sender] = true;
    tl.approvalCount = tl.approvalCount.add(1);
    emit TimeLockApproved(_timeLockId, msg.sender);
}

function cancelTimeLock(uint256 _timeLockId) external onlyRole(core.ADMIN_ROLE()) whenNotPaused {
    TimeLock storage tl = timeLocks[_timeLockId];
    require(!tl.executed, "Already executed");
    require(!tl.cancelled, "Already cancelled");
    require(tl.timestamp.add(timeLockDelay) > block.timestamp, "Time lock matured");
    tl.cancelled = true;
    emit TimeLockCancelled(_timeLockId, msg.sender);
}

function executeTimeLock(uint256 _timeLockId) external onlyRole(core.ADMIN_ROLE()) nonReentrant whenNotPaused {
    TimeLock storage tl = timeLocks[_timeLockId];
    require(!tl.executed, "Already executed");
    require(!tl.cancelled, "Cancelled");
    require(tl.approvalCount >= requiredApprovals, "Insufficient approvals");
    require(block.timestamp >= tl.timestamp.add(timeLockDelay), "Not matured");

    tl.executed = true;
    (bool success, bytes memory result) = address(this).call{value: tl.value}(tl.data);
    require(success, string(abi.encodePacked("Execution failed: ", _getRevertMsg(result))));

    if (tl.action == TimeLockAction.AddAdmin) {
        core.grantRole(core.ADMIN_ROLE(), tl.target);
        core.admins().push(tl.target);
    } else if (tl.action == TimeLockAction.RemoveAdmin) {
        address[] memory admins = core.admins();
        for (uint256 i = 0; i < admins.length; i++) {
            if (admins[i] == tl.target) {
                core.admins()[i] = admins[admins.length - 1];
                core.admins().pop();
                core.revokeRole(core.ADMIN_ROLE(), tl.target);
                break;
            }
        }
    }
    emit TimeLockExecuted(_timeLockId);
}

function _queueTimeLock(TimeLockAction _action, address _target, uint256 _value, bytes memory _data) internal returns (uint256) {
    timeLockCounter = timeLockCounter.add(1);
    TimeLock storage tl = timeLocks[timeLockCounter];
    tl.id = timeLockCounter;
    tl.action = _action;
    tl.target = _target;
    tl.value = _value;
    tl.data = _data;
    tl.timestamp = block.timestamp;
    tl.approvals[msg.sender] = true;
    tl.approvalCount = 1;
    emit TimeLockQueued(timeLockCounter, _action, _target, _value, _data, block.timestamp);
    return timeLockCounter;
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

function _getRevertMsg(bytes memory _returnData) internal pure returns (string memory) {
    if (_returnData.length < 68) return "Transaction reverted silently";
    assembly {
        _returnData := add(_returnData, 0x04)
    }
    return abi.decode(_returnData, (string));
}

modifier onlyRole(bytes32 role) {
    require(core.hasRole(role, msg.sender), "Unauthorized");
    _;
}

modifier onlyEntryPoint() {
    require(msg.sender == address(entryPoint), "Only EntryPoint can call");
    _;
}

modifier whenNotPaused() {
    require(!core.paused(), "Pausable: paused");
    _;
}

}

