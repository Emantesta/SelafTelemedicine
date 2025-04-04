// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {SafeMathUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";
import {KeeperCompatibleInterface} from "@chainlink/contracts/src/v0.8/KeeperCompatible.sol";
import {TelemedicineCore} from "./TelemedicineCore.sol";
import {TelemedicinePayments} from "./TelemedicinePayments.sol";
import {TelemedicineGovernanceCore} from "./TelemedicineGovernanceCore.sol";
import {TelemedicineBase} from "./TelemedicineBase.sol";
import {TelemedicineClinicalOperations} from "./TelemedicineClinicalOperations.sol";
import {TelemedicinePaymentOperations} from "./TelemedicinePaymentOperations.sol";

contract TelemedicineEmergency is Initializable, ReentrancyGuardUpgradeable, KeeperCompatibleInterface {
    using SafeMathUpgradeable for uint256;

    // Contract dependencies
    TelemedicineCore public core;
    TelemedicinePayments public payments;
    TelemedicineGovernanceCore public governanceCore;
    TelemedicineBase public base;
    TelemedicineClinicalOperations public clinicalOps;
    TelemedicinePaymentOperations public paymentOps;

    // Configuration
    uint256 public emergencyDelay;
    uint256 public maxEmergencyWithdrawal;
    uint256 public emergencyRoleDuration;

    // State Variables
    mapping(uint256 => EmergencyAction) public emergencyActions;
    mapping(address => uint256) public emergencyRoleExpiration;
    mapping(uint256 => Dispute) public disputes;
    mapping(uint256 => bytes32) public archivedData;
    mapping(address => mapping(uint256 => bool)) public actionApprovals; // Added for replay protection

    uint256 public emergencyActionCounter;
    uint256 public disputeCounter;

    // Enums
    enum EmergencyActionType { Unpause, FundWithdrawal, PrescriptionRevocation, AppointmentCancellation, LabTestCancellation }
    enum DisputeStatus { Open, Resolved, Escalated }

    // Structs
    struct EmergencyAction {
        EmergencyActionType actionType;
        uint256 id;
        address requester;
        uint256 requestTime;
        uint256 approvalCount;
        bool executed;
        string reason;
        uint256 amount; // Added for fund withdrawal
    }

    struct Dispute {
        uint256 id;
        address initiator;
        uint256 relatedId;
        DisputeStatus status;
        string reason;
        uint256 resolutionTimestamp;
    }

    // Custom Errors
    error InvalidActionType();
    error NoRequestExists();
    error AlreadyApproved();
    error AlreadyExecuted();
    error Unauthorized();
    error InvalidId();
    error InvalidStatus();
    error AlreadyStarted();
    error ExceedsMaxWithdrawal();
    error InsufficientBalance();
    error InvalidTarget();
    error PatientNotRegistered();
    error InvalidOracleResponse();
    error DisputeNotOpen();
    error ContractPaused();
    error InvalidMaxWithdrawal();

    // Events
    event EmergencyPaused(address indexed admin, uint256 timestamp, string reason);
    event EmergencyUnpauseRequested(uint256 indexed emergencyId, address indexed requester, string reason);
    event EmergencyUnpaused(address indexed admin, uint256 timestamp, string reason);
    event EmergencyAppointmentCancellationRequested(uint256 indexed emergencyId, address indexed requester, uint256 appointmentId, string reason);
    event EmergencyAppointmentCancelled(uint256 indexed appointmentId, address indexed requester, string reason);
    event EmergencyPrescriptionRevocationRequested(uint256 indexed emergencyId, address indexed requester, uint256 prescriptionId, string reason);
    event EmergencyPrescriptionRevoked(uint256 indexed prescriptionId, address indexed requester, string reason);
    event EmergencyLabTestCancellationRequested(uint256 indexed emergencyId, address indexed requester, uint256 labTestId, string reason);
    event EmergencyLabTestCancelled(uint256 indexed labTestId, address indexed requester, string reason);
    event EmergencyFundWithdrawalRequested(uint256 indexed emergencyId, address indexed requester, uint256 amount, string reason);
    event EmergencyFundWithdrawalApproved(uint256 indexed emergencyId, address indexed approver);
    event EmergencyFundWithdrawn(uint256 indexed emergencyId, address indexed requester, uint256 amount, string reason);
    event EmergencyRoleGranted(address indexed admin, address indexed target, bytes32 role, uint256 expiration, string reason);
    event EmergencyRoleRevoked(address indexed admin, address indexed target, bytes32 role, string reason);
    event EmergencyDataAccessed(address indexed admin, address indexed patient, string justification, bytes oracleResponse);
    event ConstantUpdated(string indexed name, uint256 newValue);
    event DisputeRaised(uint256 indexed disputeId, address indexed initiator, uint256 relatedId, string reason);
    event DisputeResolved(uint256 indexed disputeId, string resolution);
    event DataArchived(uint256 indexed id, bytes32 dataHash);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address _core,
        address _payments,
        address _governanceCore,
        address _base,
        address _clinicalOps,
        address _paymentOps
    ) external initializer {
        __ReentrancyGuard_init();
        core = TelemedicineCore(_core);
        payments = TelemedicinePayments(_payments);
        governanceCore = TelemedicineGovernanceCore(_governanceCore);
        base = TelemedicineBase(_base);
        clinicalOps = TelemedicineClinicalOperations(_clinicalOps);
        paymentOps = TelemedicinePaymentOperations(_paymentOps);
        emergencyDelay = 1 hours;
        maxEmergencyWithdrawal = 10 ether;
        emergencyRoleDuration = 1 days;
    }

    // Emergency Pause/Unpause
    function emergencyPause() external onlyRole(core.ADMIN_ROLE()) {
        core._pause();
        emit EmergencyPaused(msg.sender, block.timestamp, "Emergency pause triggered");
    }

    function requestEmergencyUnpause() external onlyRole(core.ADMIN_ROLE()) {
        emergencyActionCounter = emergencyActionCounter.add(1);
        EmergencyAction storage action = emergencyActions[emergencyActionCounter];
        action.actionType = EmergencyActionType.Unpause;
        action.id = emergencyActionCounter;
        action.requester = msg.sender;
        action.requestTime = block.timestamp;
        action.approvalCount = 1;
        action.reason = "Request to unpause contract";
        actionApprovals[msg.sender][emergencyActionCounter] = true;
        emit EmergencyUnpauseRequested(emergencyActionCounter, msg.sender, action.reason);
    }

    function approveEmergencyUnpause(uint256 _emergencyId) external onlyRole(core.ADMIN_ROLE()) {
        EmergencyAction storage action = emergencyActions[_emergencyId];
        if (action.actionType != EmergencyActionType.Unpause) revert InvalidActionType();
        if (action.requestTime == 0) revert NoRequestExists();
        if (actionApprovals[msg.sender][_emergencyId]) revert AlreadyApproved();
        if (action.executed) revert AlreadyExecuted();

        actionApprovals[msg.sender][_emergencyId] = true;
        action.approvalCount = action.approvalCount.add(1);
        emit EmergencyFundWithdrawalApproved(_emergencyId, msg.sender);

        if (action.approvalCount >= governanceCore.requiredApprovals() && block.timestamp >= action.requestTime.add(emergencyDelay)) {
            core._unpause();
            action.executed = true;
            emit EmergencyUnpaused(msg.sender, block.timestamp, "Contract unpaused");
        }
    }

    // Emergency Appointment Cancellation
    function requestEmergencyCancelAppointment(uint256 _appointmentId, string calldata _reason) external {
        if (_appointmentId > base.appointmentCounter()) revert InvalidId();
        TelemedicineBase.Appointment storage apt = base.appointments(_appointmentId);
        bool isDoctor = false;
        for (uint256 i = 0; i < apt.doctors.length; i++) {
            if (apt.doctors[i] == msg.sender) {
                isDoctor = true;
                break;
            }
        }
        if (!core.hasRole(core.ADMIN_ROLE(), msg.sender) && !(core.hasRole(core.DOCTOR_ROLE(), msg.sender) && isDoctor)) revert Unauthorized();
        if (apt.status != TelemedicineBase.AppointmentStatus.Pending && apt.status != TelemedicineBase.AppointmentStatus.Confirmed) revert InvalidStatus();
        if (apt.scheduledTimestamp <= block.timestamp) revert AlreadyStarted();

        emergencyActionCounter = emergencyActionCounter.add(1);
        EmergencyAction storage action = emergencyActions[emergencyActionCounter];
        action.actionType = EmergencyActionType.AppointmentCancellation;
        action.id = _appointmentId;
        action.requester = msg.sender;
        action.requestTime = block.timestamp;
        action.approvalCount = 1;
        action.reason = _reason;
        actionApprovals[msg.sender][emergencyActionCounter] = true;
        emit EmergencyAppointmentCancellationRequested(emergencyActionCounter, msg.sender, _appointmentId, _reason);
    }

    function approveEmergencyCancelAppointment(uint256 _emergencyId) external onlyRole(core.ADMIN_ROLE()) {
        EmergencyAction storage action = emergencyActions[_emergencyId];
        if (action.actionType != EmergencyActionType.AppointmentCancellation) revert InvalidActionType();
        if (action.requestTime == 0) revert NoRequestExists();
        if (actionApprovals[msg.sender][_emergencyId]) revert AlreadyApproved();
        if (action.executed) revert AlreadyExecuted();

        actionApprovals[msg.sender][_emergencyId] = true;
        action.approvalCount = action.approvalCount.add(1);
        emit EmergencyFundWithdrawalApproved(_emergencyId, msg.sender);

        if (action.approvalCount >= governanceCore.requiredApprovals()) {
            TelemedicineBase.Appointment storage apt = base.appointments(action.id);
            apt.status = TelemedicineBase.AppointmentStatus.Cancelled;
            for (uint256 i = 0; i < apt.doctors.length; i++) {
                base._removePendingAppointment(apt.doctors[i], action.id);
            }
            base.appointmentReminders(action.id).active = false;
            payments._refundPatient(apt.patient, apt.fee, apt.paymentType);
            action.executed = true;
            emit EmergencyAppointmentCancelled(action.id, action.requester, action.reason);
        }
    }

    // Emergency Prescription Revocation
    function requestEmergencyPrescriptionRevocation(uint256 _prescriptionId, string calldata _reason) external {
        if (_prescriptionId > clinicalOps.prescriptionCounter()) revert InvalidId();
        TelemedicineClinicalOperations.Prescription storage pres = clinicalOps.prescriptions(_prescriptionId);
        if (!core.hasRole(core.ADMIN_ROLE(), msg.sender) && !(core.hasRole(core.DOCTOR_ROLE(), msg.sender) && pres.doctor == msg.sender)) revert Unauthorized();
        if (pres.status != TelemedicineClinicalOperations.PrescriptionStatus.Generated && pres.status != TelemedicineClinicalOperations.PrescriptionStatus.Verified) revert InvalidStatus();

        emergencyActionCounter = emergencyActionCounter.add(1);
        EmergencyAction storage action = emergencyActions[emergencyActionCounter];
        action.actionType = EmergencyActionType.PrescriptionRevocation;
        action.id = _prescriptionId;
        action.requester = msg.sender;
        action.requestTime = block.timestamp;
        action.approvalCount = 1;
        action.reason = _reason;
        actionApprovals[msg.sender][emergencyActionCounter] = true;
        emit EmergencyPrescriptionRevocationRequested(emergencyActionCounter, msg.sender, _prescriptionId, _reason);
    }

    function approveEmergencyPrescriptionRevocation(uint256 _emergencyId) external onlyRole(core.ADMIN_ROLE()) {
        EmergencyAction storage action = emergencyActions[_emergencyId];
        if (action.actionType != EmergencyActionType.PrescriptionRevocation) revert InvalidActionType();
        if (action.requestTime == 0) revert NoRequestExists();
        if (actionApprovals[msg.sender][_emergencyId]) revert AlreadyApproved();
        if (action.executed) revert AlreadyExecuted();

        actionApprovals[msg.sender][_emergencyId] = true;
        action.approvalCount = action.approvalCount.add(1);
        emit EmergencyFundWithdrawalApproved(_emergencyId, msg.sender);

        if (action.approvalCount >= governanceCore.requiredApprovals()) {
            TelemedicineClinicalOperations.Prescription storage pres = clinicalOps.prescriptions(action.id);
            pres.status = TelemedicineClinicalOperations.PrescriptionStatus.Revoked;
            if (pres.patientCost > 0 && paymentOps.getPrescriptionPaymentStatus(action.id)) {
                payments._refundPatient(pres.patient, pres.patientCost, pres.paymentType);
            }
            action.executed = true;
            emit EmergencyPrescriptionRevoked(action.id, action.requester, action.reason);
        }
    }

    // Emergency Lab Test Cancellation
    function requestEmergencyCancelLabTest(uint256 _labTestId, string calldata _reason) external {
        if (_labTestId > clinicalOps.labTestCounter()) revert InvalidId();
        TelemedicineClinicalOperations.LabTestOrder storage order = clinicalOps.labTestOrders(_labTestId);
        if (!core.hasRole(core.ADMIN_ROLE(), msg.sender) && !(core.hasRole(core.DOCTOR_ROLE(), msg.sender) && order.doctor == msg.sender)) revert Unauthorized();
        if (order.status != TelemedicineClinicalOperations.LabTestStatus.Requested && order.status != TelemedicineClinicalOperations.LabTestStatus.PaymentPending) revert InvalidStatus();

        emergencyActionCounter = emergencyActionCounter.add(1);
        EmergencyAction storage action = emergencyActions[emergencyActionCounter];
        action.actionType = EmergencyActionType.LabTestCancellation;
        action.id = _labTestId;
        action.requester = msg.sender;
        action.requestTime = block.timestamp;
        action.approvalCount = 1;
        action.reason = _reason;
        actionApprovals[msg.sender][emergencyActionCounter] = true;
        emit EmergencyLabTestCancellationRequested(emergencyActionCounter, msg.sender, _labTestId, _reason);
    }

    function approveEmergencyCancelLabTest(uint256 _emergencyId) external onlyRole(core.ADMIN_ROLE()) {
        EmergencyAction storage action = emergencyActions[_emergencyId];
        if (action.actionType != EmergencyActionType.LabTestCancellation) revert InvalidActionType();
        if (action.requestTime == 0) revert NoRequestExists();
        if (actionApprovals[msg.sender][_emergencyId]) revert AlreadyApproved();
        if (action.executed) revert AlreadyExecuted();

        actionApprovals[msg.sender][_emergencyId] = true;
        action.approvalCount = action.approvalCount.add(1);
        emit EmergencyFundWithdrawalApproved(_emergencyId, msg.sender);

        if (action.approvalCount >= governanceCore.requiredApprovals()) {
            TelemedicineClinicalOperations.LabTestOrder storage order = clinicalOps.labTestOrders(action.id);
            order.status = TelemedicineClinicalOperations.LabTestStatus.Expired;
            if (order.patientCost > 0 && paymentOps.getLabTestPaymentStatus(action.id)) {
                payments._refundPatient(order.patient, order.patientCost, order.paymentType);
            }
            action.executed = true;
            emit EmergencyLabTestCancelled(action.id, action.requester, action.reason);
        }
    }

    // Emergency Fund Withdrawal
    function requestEmergencyFundWithdrawal(uint256 _amount, string calldata _reason) external onlyRole(core.ADMIN_ROLE()) {
        if (_amount > maxEmergencyWithdrawal) revert ExceedsMaxWithdrawal();
        if (_amount > address(this).balance.sub(core.reserveFund())) revert InsufficientBalance();

        emergencyActionCounter = emergencyActionCounter.add(1);
        EmergencyAction storage action = emergencyActions[emergencyActionCounter];
        action.actionType = EmergencyActionType.FundWithdrawal;
        action.id = emergencyActionCounter;
        action.requester = msg.sender;
        action.requestTime = block.timestamp;
        action.approvalCount = 1;
        action.reason = _reason;
        action.amount = _amount;
        actionApprovals[msg.sender][emergencyActionCounter] = true;
        emit EmergencyFundWithdrawalRequested(emergencyActionCounter, msg.sender, _amount, _reason);
    }

    function approveEmergencyFundWithdrawal(uint256 _emergencyId) external onlyRole(core.ADMIN_ROLE()) {
        EmergencyAction storage action = emergencyActions[_emergencyId];
        if (action.actionType != EmergencyActionType.FundWithdrawal) revert InvalidActionType();
        if (action.requestTime == 0) revert NoRequestExists();
        if (actionApprovals[msg.sender][_emergencyId]) revert AlreadyApproved();
        if (action.executed) revert AlreadyExecuted();

        actionApprovals[msg.sender][_emergencyId] = true;
        action.approvalCount = action.approvalCount.add(1);
        emit EmergencyFundWithdrawalApproved(_emergencyId, msg.sender);

        if (action.approvalCount >= governanceCore.requiredApprovals() && block.timestamp >= action.requestTime.add(emergencyDelay)) {
            uint256 amount = _min(action.amount, address(this).balance.sub(core.reserveFund()));
            paymentOps.safeTransferETH(action.requester, amount);
            action.executed = true;
            emit EmergencyFundWithdrawn(_emergencyId, action.requester, amount, action.reason);
        }
    }

    // Configuration Updates
    function queueUpdateMaxEmergencyWithdrawal(uint256 _newMax) external onlyRole(core.ADMIN_ROLE()) {
        if (_newMax == 0) revert InvalidMaxWithdrawal();
        bytes memory data = abi.encodeWithSignature("setMaxEmergencyWithdrawal(uint256)", _newMax);
        governanceCore._queueTimeLock(TelemedicineGovernanceCore.TimeLockAction.AdjustMaxEmergencyWithdrawal, address(this), _newMax, data);
    }

    function setMaxEmergencyWithdrawal(uint256 _newMax) external onlyRole(core.ADMIN_ROLE()) {
        maxEmergencyWithdrawal = _newMax;
        emit ConstantUpdated("maxEmergencyWithdrawal", _newMax);
    }

    // Role Management
    function grantEmergencyRole(address _target, bytes32 _role, string calldata _reason) external onlyRole(core.ADMIN_ROLE()) {
        if (_target == address(0)) revert InvalidTarget();
        uint256 expiration = block.timestamp.add(emergencyRoleDuration);
        core.grantRole(_role, _target);
        emergencyRoleExpiration[_target] = expiration;
        emit EmergencyRoleGranted(msg.sender, _target, _role, expiration, _reason);
    }

    function revokeEmergencyRole(address _target, bytes32 _role, string calldata _reason) external onlyRole(core.ADMIN_ROLE()) {
        if (_target == address(0)) revert InvalidTarget();
        core.revokeRole(_role, _target);
        delete emergencyRoleExpiration[_target];
        emit EmergencyRoleRevoked(msg.sender, _target, _role, _reason);
    }

    // Emergency Data Access
    function accessEmergencyData(address _patient, string calldata _justification, bytes calldata _oracleResponse) external onlyRole(core.ADMIN_ROLE()) {
        if (!core.patients(_patient).isRegistered) revert PatientNotRegistered();
        if (_oracleResponse.length == 0) revert InvalidOracleResponse();
        emit EmergencyDataAccessed(msg.sender, _patient, _justification, _oracleResponse);
    }

    // Dispute Management
    function raiseDispute(uint256 _relatedId, string calldata _reason) external whenNotPaused {
        if (!core.hasRole(core.PATIENT_ROLE(), msg.sender) && !core.hasRole(core.DOCTOR_ROLE(), msg.sender) && !core.hasRole(core.ADMIN_ROLE(), msg.sender)) revert Unauthorized();
        disputeCounter = disputeCounter.add(1);
        Dispute storage dispute = disputes[disputeCounter];
        dispute.id = disputeCounter;
        dispute.initiator = msg.sender;
        dispute.relatedId = _relatedId;
        dispute.status = DisputeStatus.Open;
        dispute.reason = _reason;
        emit DisputeRaised(disputeCounter, msg.sender, _relatedId, _reason);
    }

    function resolveDispute(uint256 _disputeId, string calldata _resolution) external onlyRole(core.ADMIN_ROLE()) {
        Dispute storage dispute = disputes[_disputeId];
        if (dispute.status != DisputeStatus.Open && dispute.status != DisputeStatus.Escalated) revert DisputeNotOpen();
        dispute.status = DisputeStatus.Resolved;
        dispute.resolutionTimestamp = block.timestamp;
        emit DisputeResolved(_disputeId, _resolution);
    }

    // Data Archiving
    function archiveData(uint256 _dataId, bytes32 _dataHash) external onlyRole(core.ADMIN_ROLE()) {
        archivedData[_dataId] = _dataHash;
        emit DataArchived(_dataId, _dataHash);
    }

    // Keeper Functions
    function checkUpkeep(bytes calldata) external view override returns (bool upkeepNeeded, bytes memory performData) {
        address[] memory admins = core.admins();
        for (uint256 i = 0; i < admins.length; i++) {
            if (emergencyRoleExpiration[admins[i]] > 0 && block.timestamp >= emergencyRoleExpiration[admins[i]]) {
                return (true, abi.encode(admins[i]));
            }
        }
        return (false, bytes(""));
    }

    function performUpkeep(bytes calldata performData) external override {
        address target = abi.decode(performData, (address));
        if (emergencyRoleExpiration[target] > 0 && block.timestamp >= emergencyRoleExpiration[target]) {
            core.revokeRole(core.ADMIN_ROLE(), target);
            delete emergencyRoleExpiration[target];
            emit EmergencyRoleRevoked(msg.sender, target, core.ADMIN_ROLE(), "Expired emergency role");
        }
    }

    // Utility Functions
    function _min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    function toString(address account) internal pure returns (string memory) {
        bytes32 value = bytes32(uint256(uint160(account)));
        bytes memory alphabet = "0123456789abcdef";
        bytes memory str = new bytes(42);
        str[0] = "0";
        str[1] = "x";
        for (uint256 i = 0; i < 20; i++) {
            str[2 + i * 2] = alphabet[uint8(value[i + 12] >> 4)];
            str[3 + i * 2] = alphabet[uint8(value[i + 12] & 0x0f)];
        }
        return string(str);
    }

    // Modifiers
    modifier onlyRole(bytes32 role) {
        if (!core.hasRole(role, msg.sender)) revert Unauthorized();
        _;
    }

    modifier whenNotPaused() {
        if (core.paused()) revert ContractPaused();
        _;
    }

    receive() external payable {}
}
