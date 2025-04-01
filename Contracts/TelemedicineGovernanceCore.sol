// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import {SafeMathUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";
import {IERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {UserOperation} from "@account-abstraction/contracts/interfaces/UserOperation.sol";
import {TelemedicineCore} from "./TelemedicineCore.sol";
import {TelemedicineMedicalCore} from "./TelemedicineMedicalCore.sol";
import {TelemedicineMedicalServices} from "./TelemedicineMedicalServices.sol";
import {TelemedicinePayments} from "./TelemedicinePayments.sol";
import {TelemedicineDisputeResolution} from "./TelemedicineDisputeResolution.sol";

contract TelemedicineGovernanceCore is Initializable, UUPSUpgradeable, ReentrancyGuardUpgradeable, PausableUpgradeable {
    using SafeMathUpgradeable for uint256;

    TelemedicineCore public core;
    TelemedicineMedicalCore public medicalCore;
    TelemedicineMedicalServices public medicalServices;
    TelemedicinePayments public payments;
    TelemedicineDisputeResolution public disputeResolution;

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

    enum TimeLockAction { 
        WithdrawFunds, AddAdmin, RemoveAdmin, AdjustFee, AdjustMaxEmergencyWithdrawal, UpgradeContract, DisputeResolution, 
        UpdateChainlinkConfig, ToggleManualPriceOverride, ReleasePendingPayments, UpdateInvitationConfig, 
        UpdateMultiSigConfig, UpdateLabTechPrice, UpdatePharmacyPrice, UpdateMedicalServiceConfig
    }

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
    event ConfigurationUpdated(string indexed parameter, uint256 value);
    event PaymentReleasedFromQueue(uint256 indexed paymentId, address recipient, uint256 amount);
    event MultiSigConfigUpdated(uint256 requiredSignatures, address[] signers);
    event LabTechPriceUpdated(address indexed labTech, string testTypeIpfsHash, uint256 price, uint48 timestamp);
    event PharmacyPriceUpdated(address indexed pharmacy, string medicationIpfsHash, uint256 price, uint48 timestamp);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address _core,
        address _medicalCore,
        address _medicalServices,
        address _payments,
        address _disputeResolution,
        address _entryPoint,
        address _paymaster,
        address _dataAccessOracle
    ) external initializer {
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        __Pausable_init();

        core = TelemedicineCore(_core);
        medicalCore = TelemedicineMedicalCore(_medicalCore);
        medicalServices = TelemedicineMedicalServices(_medicalServices);
        payments = TelemedicinePayments(_payments);
        disputeResolution = TelemedicineDisputeResolution(_disputeResolution);
        entryPoint = IEntryPoint(_entryPoint);
        paymaster = _paymaster;
        dataAccessOracle = _dataAccessOracle;
        trustedPaymasters[_paymaster] = true;
        timeLockDelay = MIN_TIMELOCK_DELAY;
        requiredApprovals = core.admins().length / 2 + 1; // Majority of admins
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyRole(core.ADMIN_ROLE()) {}

    // Transfer Funds
    function transfer(address payable _to, uint256 _amount) external onlyRole(core.ADMIN_ROLE()) nonReentrant {
        require(_to != address(0), "Invalid recipient");
        require(_amount <= address(this).balance, "Insufficient balance");
        (bool success, ) = _to.call{value: _amount}("");
        require(success, "Transfer failed");
    }

    // Account Abstraction
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

    // Paymaster Management
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

    // TimeLock Functions
    function _queueTimeLock(TimeLockAction _action, address _target, uint256 _value, bytes memory _data) 
        public 
        onlyRole(core.ADMIN_ROLE()) 
        returns (uint256) 
    {
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
        (bool success, bytes memory result) = tl.target.call{value: tl.value}(tl.data);
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
        } else if (tl.action == TimeLockAction.DisputeResolution) {
            // Handled by TelemedicineDisputeResolution
        } else if (tl.action == TimeLockAction.ReleasePendingPayments) {
            emit PaymentReleasedFromQueue(tl.value, tl.target, tl.value);
        } else if (tl.action == TimeLockAction.UpdateLabTechPrice) {
            // Event emitted by TelemedicineMedicalServices
        } else if (tl.action == TimeLockAction.UpdatePharmacyPrice) {
            // Event emitted by TelemedicineMedicalServices
        }
        emit TimeLockExecuted(_timeLockId);
    }

    // Governance Actions
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

    // Dispute Resolution Integration
    function queueResolveDispute(uint256 _disputeId, bool _patientWins, bytes32 _resolutionReason) 
        external 
        onlyRole(core.ADMIN_ROLE()) 
        nonReentrant 
        whenNotPaused 
    {
        require(disputeResolution.disputes(_disputeId).status == TelemedicineDisputeResolution.DisputeStatus.Escalated, "Dispute not escalated");
        require(_resolutionReason != bytes32(0), "Invalid resolution reason");
        bytes memory data = abi.encodeWithSignature("executeResolveDispute(uint256,bool,bytes32)", _disputeId, _patientWins, _resolutionReason);
        _queueTimeLock(TimeLockAction.DisputeResolution, address(disputeResolution), 0, data);
    }

    function executeResolveDispute(uint256 _disputeId, bool _patientWins, bytes32 _resolutionReason) 
        external 
        onlyRole(core.ADMIN_ROLE()) 
        nonReentrant 
        whenNotPaused 
    {
        disputeResolution.executeResolveDispute(_disputeId, _patientWins, _resolutionReason);
    }

    // Configuration Updates with Timelock
    function queueUpdateRampFee(string calldata _rampType, uint256 _newFee) external onlyRole(core.ADMIN_ROLE()) {
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

    function queueUpdateMinBookingBuffer(uint256 _newBuffer) external onlyRole(core.ADMIN_ROLE()) {
        require(_newBuffer >= 5 minutes, "Buffer must be at least 5 minutes");
        bytes memory data = abi.encodeWithSignature("setMinBookingBuffer(uint256)", _newBuffer);
        _queueTimeLock(TimeLockAction.AdjustFee, address(core), _newBuffer, data);
    }

    function setMinBookingBuffer(uint256 _newBuffer) external onlyRole(core.ADMIN_ROLE()) {
        core.minBookingBuffer = _newBuffer;
        emit ConstantUpdated("minBookingBuffer", _newBuffer);
    }

    function queueUpdateMinCancellationBuffer(uint256 _newBuffer) external onlyRole(core.ADMIN_ROLE()) {
        require(_newBuffer >= 30 minutes, "Buffer must be at least 30 minutes");
        bytes memory data = abi.encodeWithSignature("setMinCancellationBuffer(uint256)", _newBuffer);
        _queueTimeLock(TimeLockAction.AdjustFee, address(core), _newBuffer, data);
    }

    function setMinCancellationBuffer(uint256 _newBuffer) external onlyRole(core.ADMIN_ROLE()) {
        core.minCancellationBuffer = _newBuffer;
        emit ConstantUpdated("minCancellationBuffer", _newBuffer);
    }

    function queueUpdateVerificationTimeout(uint256 _newTimeout) external onlyRole(core.ADMIN_ROLE()) {
        require(_newTimeout >= 1 days, "Timeout must be at least 1 day");
        bytes memory data = abi.encodeWithSignature("setVerificationTimeout(uint256)", _newTimeout);
        _queueTimeLock(TimeLockAction.AdjustFee, address(core), _newTimeout, data);
    }

    function setVerificationTimeout(uint256 _newTimeout) external onlyRole(core.ADMIN_ROLE()) {
        core.verificationTimeout = _newTimeout;
        emit ConstantUpdated("verificationTimeout", _newTimeout);
    }

    function queueUpdateDataMonetizationReward(uint256 _newReward) external onlyRole(core.ADMIN_ROLE()) {
        require(_newReward > 0, "Reward must be positive");
        require(payments.sonicToken().balanceOf(address(payments)) >= _newReward, "Insufficient SONIC balance");
        bytes memory data = abi.encodeWithSignature("setDataMonetizationReward(uint256)", _newReward);
        _queueTimeLock(TimeLockAction.AdjustFee, address(core), _newReward, data);
    }

    function setDataMonetizationReward(uint256 _newReward) external onlyRole(core.ADMIN_ROLE()) {
        core.dataMonetizationReward = _newReward;
        emit ConstantUpdated("dataMonetizationReward", _newReward);
    }

    function queueUpdateAIAnalysisCost(uint256 _newCost) external onlyRole(core.ADMIN_ROLE()) {
        require(_newCost > 0, "Cost must be positive");
        bytes memory data = abi.encodeWithSignature("setAIAnalysisCost(uint256)", _newCost);
        _queueTimeLock(TimeLockAction.AdjustFee, address(core), _newCost, data);
    }

    function setAIAnalysisCost(uint256 _newCost) external onlyRole(core.ADMIN_ROLE()) {
        core.aiAnalysisCost = _newCost;
        emit ConstantUpdated("aiAnalysisCost", _newCost);
    }

    function queueUpdatePointsPerLevel(uint256 _newPoints) external onlyRole(core.ADMIN_ROLE()) {
        require(_newPoints > 0, "Points per level must be positive");
        bytes memory data = abi.encodeWithSignature("setPointsPerLevel(uint256)", _newPoints);
        _queueTimeLock(TimeLockAction.AdjustFee, address(core), _newPoints, data);
    }

    function setPointsPerLevel(uint256 _newPoints) external onlyRole(core.ADMIN_ROLE()) {
        core.pointsPerLevel = _newPoints;
        emit GamificationParameterUpdated("pointsPerLevel", _newPoints);
    }

    function queueUpdateMaxLevel(uint8 _newMax) external onlyRole(core.ADMIN_ROLE()) {
        require(_newMax > 0, "Max level must be positive");
        bytes memory data = abi.encodeWithSignature("setMaxLevel(uint8)", _newMax);
        _queueTimeLock(TimeLockAction.AdjustFee, address(core), _newMax, data);
    }

    function setMaxLevel(uint8 _newMax) external onlyRole(core.ADMIN_ROLE()) {
        core.maxLevel = _newMax;
        emit GamificationParameterUpdated("maxLevel", _newMax);
    }

    function queueUpdateDecayRate(uint256 _newRate) external onlyRole(core.ADMIN_ROLE()) {
        require(_newRate > 0, "Decay rate must be positive");
        bytes memory data = abi.encodeWithSignature("setDecayRate(uint256)", _newRate);
        _queueTimeLock(TimeLockAction.AdjustFee, address(core), _newRate, data);
    }

    function setDecayRate(uint256 _newRate) external onlyRole(core.ADMIN_ROLE()) {
        core.decayRate = _newRate;
        emit GamificationParameterUpdated("decayRate", _newRate);
    }

    function queueUpdateDecayPeriod(uint256 _newPeriod) external onlyRole(core.ADMIN_ROLE()) {
        require(_newPeriod >= 1 days, "Period must be at least 1 day");
        bytes memory data = abi.encodeWithSignature("setDecayPeriod(uint256)", _newPeriod);
        _queueTimeLock(TimeLockAction.AdjustFee, address(core), _newPeriod, data);
    }

    function setDecayPeriod(uint256 _newPeriod) external onlyRole(core.ADMIN_ROLE()) {
        core.decayPeriod = _newPeriod;
        emit GamificationParameterUpdated("decayPeriod", _newPeriod);
    }

    function queueUpdateFreeAnalysisPeriod(uint256 _newPeriod) external onlyRole(core.ADMIN_ROLE()) {
        require(_newPeriod >= 7 days, "Period must be at least 7 days");
        bytes memory data = abi.encodeWithSignature("setFreeAnalysisPeriod(uint256)", _newPeriod);
        _queueTimeLock(TimeLockAction.AdjustFee, address(core), _newPeriod, data);
    }

    function setFreeAnalysisPeriod(uint256 _newPeriod) external onlyRole(core.ADMIN_ROLE()) {
        core.freeAnalysisPeriod = _newPeriod;
        emit GamificationParameterUpdated("freeAnalysisPeriod", _newPeriod);
    }

    function queueUpdateMinReserveBalance(uint256 _newMin) external onlyRole(core.ADMIN_ROLE()) {
        require(_newMin >= core.RESERVE_FUND_THRESHOLD(), "Below threshold");
        bytes memory data = abi.encodeWithSignature("setMinReserveBalance(uint256)", _newMin);
        _queueTimeLock(TimeLockAction.AdjustFee, address(core), _newMin, data);
    }

    function setMinReserveBalance(uint256 _newMin) external onlyRole(core.ADMIN_ROLE()) {
        core.minReserveBalance = _newMin;
        emit ConstantUpdated("minReserveBalance", _newMin);
    }

    // TelemedicineMedicalCore Configuration Updates
    function queueUpdateMedicalCoreConfig(string calldata _parameter, uint256 _value) external onlyRole(core.ADMIN_ROLE()) {
        bytes memory data = abi.encodeWithSignature("updateConfiguration(string,uint256)", _parameter, _value);
        _queueTimeLock(TimeLockAction.AdjustFee, address(medicalCore), _value, data);
    }

    function queueUpdateChainlinkConfig(address _newOracle, bytes32 _newJobId, uint256 _newFee) 
        external 
        onlyRole(core.ADMIN_ROLE()) 
    {
        require(_newOracle != address(0), "Oracle address cannot be zero");
        require(_newFee > 0, "Fee must be positive");
        bytes memory data = abi.encodeWithSignature("updateChainlinkConfig(address,bytes32,uint256)", _newOracle, _newJobId, _newFee);
        _queueTimeLock(TimeLockAction.UpdateChainlinkConfig, address(medicalCore), _newFee, data);
    }

    function updateChainlinkConfig(address _newOracle, bytes32 _newJobId, uint256 _newFee) 
        external 
        onlyRole(core.ADMIN_ROLE()) 
    {
        medicalCore.chainlinkOracle = _newOracle;
        medicalCore.priceListJobId = _newJobId;
        medicalCore.chainlinkFee = _newFee;
        emit ConfigurationUpdated("chainlinkConfig", _newFee);
    }

    function queueToggleManualPriceOverride(bool _enabled) external onlyRole(core.ADMIN_ROLE()) {
        bytes memory data = abi.encodeWithSignature("toggleManualPriceOverride(bool)", _enabled);
        _queueTimeLock(TimeLockAction.ToggleManualPriceOverride, address(medicalCore), _enabled ? 1 : 0, data);
    }

    function toggleManualPriceOverride(bool _enabled) external onlyRole(core.ADMIN_ROLE()) {
        medicalCore.toggleManualPriceOverride(_enabled);
        emit ConfigurationUpdated("manualPriceOverride", _enabled ? 1 : 0);
    }

    function queueReleasePendingPayments(uint256 _startId, uint256 _count) external onlyRole(core.ADMIN_ROLE()) {
        bytes memory data = abi.encodeWithSignature("releasePendingPayments(uint256,uint256)", _startId, _count);
        _queueTimeLock(TimeLockAction.ReleasePendingPayments, address(medicalCore), _count, data);
    }

    function queueUpdateInvitationExpirationPeriod(uint48 _newPeriod) external onlyRole(core.ADMIN_ROLE()) {
        require(_newPeriod > 0, "Period must be positive");
        bytes memory data = abi.encodeWithSignature("updateConfiguration(string,uint256)", "invitationExpirationPeriod", _newPeriod);
        _queueTimeLock(TimeLockAction.UpdateInvitationConfig, address(medicalCore), _newPeriod, data);
    }

    // TelemedicineMedicalServices Configuration Updates
    function queueUpdateMedicalServiceConfig(string calldata _parameter, uint256 _value) external onlyRole(core.ADMIN_ROLE()) {
        bytes memory data;
        if (keccak256(abi.encodePacked(_parameter)) == keccak256(abi.encodePacked("requiredSignatures"))) {
            data = abi.encodeWithSignature("updateRequiredSignatures(uint256)", _value);
        } else {
            revert("Invalid parameter");
        }
        _queueTimeLock(TimeLockAction.UpdateMedicalServiceConfig, address(medicalServices), _value, data);
    }

    function updateRequiredSignatures(uint256 _newSignatures) external onlyRole(core.ADMIN_ROLE()) {
        require(_newSignatures > 0 && _newSignatures <= medicalServices.multiSigSigners().length, "Invalid signature count");
        medicalServices.requiredSignatures = _newSignatures;
        emit ConfigurationUpdated("requiredSignatures", _newSignatures);
    }

    function queueUpdateMultiSigConfig(address[] calldata _newSigners, uint256 _newRequiredSignatures) 
        external 
        onlyRole(core.ADMIN_ROLE()) 
    {
        require(_newSigners.length >= _newRequiredSignatures && _newRequiredSignatures > 0, "Invalid multi-sig config");
        bytes memory data = abi.encodeWithSignature("updateMultiSigConfig(address[],uint256)", _newSigners, _newRequiredSignatures);
        _queueTimeLock(TimeLockAction.UpdateMultiSigConfig, address(medicalServices), _newRequiredSignatures, data);
    }

    function updateMultiSigConfig(address[] calldata _newSigners, uint256 _newRequiredSignatures) 
        external 
        onlyRole(core.ADMIN_ROLE()) 
    {
        medicalServices.multiSigSigners = _newSigners;
        medicalServices.requiredSignatures = _newRequiredSignatures;
        emit MultiSigConfigUpdated(_newRequiredSignatures, _newSigners);
    }

    function queueUpdateLabTechPrice(address _labTech, string calldata _testTypeIpfsHash, uint256 _price) 
        external 
        onlyRole(core.ADMIN_ROLE()) 
    {
        require(_labTech != address(0), "Lab tech address cannot be zero");
        require(bytes(_testTypeIpfsHash).length > 0, "Invalid IPFS hash");
        require(_price > 0, "Price must be positive");
        bytes memory data = abi.encodeWithSignature("updateLabTechPrice(string,uint256)", _testTypeIpfsHash, _price);
        _queueTimeLock(TimeLockAction.UpdateLabTechPrice, _labTech, _price, data);
    }

    function queueUpdatePharmacyPrice(address _pharmacy, string calldata _medicationIpfsHash, uint256 _price) 
        external 
        onlyRole(core.ADMIN_ROLE()) 
    {
        require(_pharmacy != address(0), "Pharmacy address cannot be zero");
        require(bytes(_medicationIpfsHash).length > 0, "Invalid IPFS hash");
        require(_price > 0, "Price must be positive");
        bytes memory data = abi.encodeWithSignature("updatePharmacyPrice(string,uint256)", _medicationIpfsHash, _price);
        _queueTimeLock(TimeLockAction.UpdatePharmacyPrice, _pharmacy, _price, data);
    }

    // Additional Configuration Updates
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

    function queueUpdateTimeLockDelay(uint256 _newDelay) external onlyRole(core.ADMIN_ROLE()) {
        require(_newDelay >= MIN_TIMELOCK_DELAY, "Delay must be at least 2 days");
        bytes memory data = abi.encodeWithSignature("setTimeLockDelay(uint256)", _newDelay);
        _queueTimeLock(TimeLockAction.AdjustFee, address(this), _newDelay, data);
    }

    function setTimeLockDelay(uint256 _newDelay) external onlyRole(core.ADMIN_ROLE()) {
        timeLockDelay = _newDelay;
        emit ConstantUpdated("timeLockDelay", _newDelay);
    }

    function queueUpdateRequiredApprovals(uint256 _newApprovals) external onlyRole(core.ADMIN_ROLE()) {
        require(_newApprovals >= 1 && _newApprovals <= core.admins().length, "Invalid approval count");
        bytes memory data = abi.encodeWithSignature("setRequiredApprovals(uint256)", _newApprovals);
        _queueTimeLock(TimeLockAction.AdjustFee, address(this), _newApprovals, data);
    }

    function setRequiredApprovals(uint256 _newApprovals) external onlyRole(core.ADMIN_ROLE()) {
        requiredApprovals = _newApprovals;
        emit ConstantUpdated("requiredApprovals", _newApprovals);
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

    // Utility Functions
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

    // Modifiers
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

    // Fallback
    receive() external payable {}
}
