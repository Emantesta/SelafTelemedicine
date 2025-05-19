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

/// @title TelemedicineEmergency
/// @notice Manages emergency operations with timelocks and Chainlink Keepers
/// @dev Non-upgradeable, integrates with core, payments, governance, base, clinical, and payment ops
contract TelemedicineEmergency is Initializable, ReentrancyGuardUpgradeable, KeeperCompatibleInterface {
    using SafeMathUpgradeable for uint256;

    // Immutable Dependencies
    TelemedicineCore public immutable core;
    TelemedicinePayments public immutable payments;
    TelemedicineGovernanceCore public immutable governanceCore;
    TelemedicineBase public immutable base;
    TelemedicineClinicalOperations public immutable clinicalOps;
    TelemedicinePaymentOperations public immutable paymentOps;

    // Configuration
    uint256 public emergencyDelay;
    uint256 public maxEmergencyWithdrawal;
    uint256 public emergencyRoleDuration;

    // Private State Variables
    mapping(uint256 => EmergencyAction) private emergencyActions; // Updated: Private
    mapping(address => uint256) private emergencyRoleExpiration; // Updated: Private
    mapping(uint256 => Dispute) private disputes; // Updated: Private
    mapping(uint256 => bytes32) private archivedData; // Updated: Private
    uint256 private emergencyActionCounter;
    uint256 private disputeCounter;

    // Constants
    uint256 public constant MIN_EMERGENCY_DELAY = 30 minutes; // New: Minimum delay
    uint256 public constant MIN_ROLE_DURATION = 12 hours; // New: Minimum role duration
    uint256 public constant MIN_MAX_WITHDRAWAL = 0.1 ether; // New: Minimum withdrawal
    uint256 public constant MAX_COUNTER = 1_000_000; // New: Counter limit
    uint256 public constant MAX_REASON_LENGTH = 256; // New: Reason length limit
    uint256 public constant MAX_ADMINS_PER_UPKEEP = 50; // New: Pagination limit

    // Enums
    enum EmergencyActionType { Unpause, FundWithdrawal, PrescriptionRevocation, AppointmentCancellation, LabTestCancellation }
    enum DisputeStatus { Open, Resolved, Escalated } // Assumed compatible with TelemedicineDisputeResolution

    // Structs
    struct EmergencyAction {
        EmergencyActionType actionType;
        uint256 id;
        address requester;
        uint256 requestTime;
        address[] approvers; // Updated: Array instead of mapping
        bool executed;
        bytes32 reasonHash; // Updated: Hashed reason
        uint256 amount; // For fund withdrawal
    }

    struct Dispute {
        uint256 id;
        address initiator;
        uint256 relatedId;
        DisputeStatus status;
        bytes32 reasonHash; // Updated: Hashed reason
        uint256 resolutionTimestamp;
    }

    // Custom Errors
    error InvalidAddress();
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
    error InvalidDelay();
    error InvalidDuration();
    error InvalidCounter();
    error InvalidReasonLength();
    error ExternalCallFailed();
    error InvalidApprovalCount();
    error InsufficientApprovals();
    error ActionNotMatured();
    error InvalidAppointmentId();
    error InvalidPrescriptionId();
    error InvalidLabTestId();
    error RoleExpired();

    // Events
    event EmergencyPaused(bytes32 indexed adminHash, uint256 timestamp, bytes32 reasonHash);
    event EmergencyUnpauseRequested(uint256 indexed emergencyId, bytes32 indexed requesterHash, bytes32 reasonHash);
    event EmergencyUnpaused(bytes32 indexed adminHash, uint256 timestamp, bytes32 reasonHash);
    event EmergencyAppointmentCancellationRequested(uint256 indexed emergencyId, bytes32 indexed requesterHash, uint256 appointmentId, bytes32 reasonHash);
    event EmergencyAppointmentCancelled(uint256 indexed appointmentId, bytes32 indexed requesterHash, bytes32 reasonHash);
    event EmergencyPrescriptionRevocationRequested(uint256 indexed emergencyId, bytes32 indexed requesterHash, uint256 prescriptionId, bytes32 reasonHash);
    event EmergencyPrescriptionRevoked(uint256 indexed prescriptionId, bytes32 indexed requesterHash, bytes32 reasonHash);
    event EmergencyLabTestCancellationRequested(uint256 indexed emergencyId, bytes32 indexed requesterHash, uint256 labTestId, bytes32 reasonHash);
    event EmergencyLabTestCancelled(uint256 indexed labTestId, bytes32 indexed requesterHash, bytes32 reasonHash);
    event EmergencyFundWithdrawalRequested(uint256 indexed emergencyId, bytes32 indexed requesterHash, uint256 amount, bytes32 reasonHash);
    event EmergencyActionApproved(uint256 indexed emergencyId, bytes32 indexed approverHash); // Updated: Specific event
    event EmergencyFundWithdrawn(uint256 indexed emergencyId, bytes32 indexed requesterHash, uint256 amount, bytes32 reasonHash);
    event EmergencyRoleGranted(bytes32 indexed adminHash, bytes32 indexed targetHash, bytes32 role, uint256 expiration, bytes32 reasonHash);
    event EmergencyRoleRevoked(bytes32 indexed adminHash, bytes32 indexed targetHash, bytes32 role, bytes32 reasonHash);
    event EmergencyDataAccessed(bytes32 indexed adminHash, bytes32 indexed patientHash, bytes32 justificationHash, bytes32 oracleResponseHash);
    event ConstantUpdated(string indexed name, uint256 newValue);
    event DisputeRaised(uint256 indexed disputeId, bytes32 indexed initiatorHash, uint256 relatedId, bytes32 reasonHash);
    event DisputeResolved(uint256 indexed disputeId, bytes32 resolutionHash);
    event DataArchived(uint256 indexed id, bytes32 dataHash);
    event UpkeepPerformed(address[] targets, bytes32 reasonHash); // New: Upkeep event

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the contract
    /// @param _core Core contract address
    /// @param _payments Payments contract address
    /// @param _governanceCore Governance core contract address
    /// @param _base Base contract address
    /// @param _clinicalOps Clinical operations contract address
    /// @param _paymentOps Payment operations contract address
    function initialize(
        address _core,
        address _payments,
        address _governanceCore,
        address _base,
        address _clinicalOps,
        address _paymentOps
    ) external initializer {
        if (_core == address(0) || _payments == address(0) || _governanceCore == address(0) ||
            _base == address(0) || _clinicalOps == address(0) || _paymentOps == address(0)) revert InvalidAddress();
        if (!_isContract(_core) || !_isContract(_payments) || !_isContract(_governanceCore) ||
            !_isContract(_base) || !_isContract(_clinicalOps) || !_isContract(_paymentOps)) revert InvalidAddress();

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

        try governanceCore.requiredApprovals() returns (uint256 approvals) {
            if (approvals == 0) revert InvalidApprovalCount();
        } catch {
            revert ExternalCallFailed();
        }
    }

    // Emergency Pause/Unpause

    /// @notice Pauses the contract
    function emergencyPause() external onlyConfigAdmin {
        try core._pause() {} catch {
            revert ExternalCallFailed();
        }
        _pause();
        emit EmergencyPaused(keccak256(abi.encode(msg.sender)), block.timestamp, keccak256(abi.encode("Emergency pause triggered")));
    }

    /// @notice Requests emergency unpause
    function requestEmergencyUnpause(string calldata _reason) external onlyConfigAdmin {
        if (bytes(_reason).length > MAX_REASON_LENGTH) revert InvalidReasonLength();
        if (emergencyActionCounter >= MAX_COUNTER) revert InvalidCounter();
        emergencyActionCounter = emergencyActionCounter.add(1);
        EmergencyAction storage action = emergencyActions[emergencyActionCounter];
        action.actionType = EmergencyActionType.Unpause;
        action.id = emergencyActionCounter;
        action.requester = msg.sender;
        action.requestTime = block.timestamp;
        action.approvers.push(msg.sender);
        action.reasonHash = keccak256(abi.encode(_reason));
        emit EmergencyUnpauseRequested(emergencyActionCounter, keccak256(abi.encode(msg.sender)), action.reasonHash);
    }

    /// @notice Approves multiple emergency actions
    /// @param _emergencyIds Emergency action IDs
    function batchApproveEmergencyActions(uint256[] calldata _emergencyIds) external onlyConfigAdmin whenNotPaused {
        uint256 requiredApprovals;
        try governanceCore.requiredApprovals() returns (uint256 approvals) {
            requiredApprovals = approvals;
        } catch {
            revert ExternalCallFailed();
        }
        for (uint256 i = 0; i < _emergencyIds.length; i++) {
            uint256 _emergencyId = _emergencyIds[i];
            EmergencyAction storage action = emergencyActions[_emergencyId];
            if (action.requestTime == 0) revert NoRequestExists();
            if (action.executed) revert AlreadyExecuted();
            bool alreadyApproved;
            for (uint256 j = 0; j < action.approvers.length; j++) {
                if (action.approvers[j] == msg.sender) {
                    alreadyApproved = true;
                    break;
                }
            }
            if (alreadyApproved) revert AlreadyApproved();
            action.approvers.push(msg.sender);
            emit EmergencyActionApproved(_emergencyId, keccak256(abi.encode(msg.sender)));

            if (action.approvers.length >= requiredApprovals && block.timestamp >= action.requestTime.add(emergencyDelay)) {
                if (action.actionType == EmergencyActionType.Unpause) {
                    try core._unpause() {} catch {
                        revert ExternalCallFailed();
                    }
                    _unpause();
                    action.executed = true;
                    emit EmergencyUnpaused(keccak256(abi.encode(msg.sender)), block.timestamp, action.reasonHash);
                }
                // Other action types handled in batchExecuteEmergencyActions
            }
        }
    }

    // Emergency Appointment Cancellation

    /// @notice Requests emergency appointment cancellation
    /// @param _appointmentId Appointment ID
    /// @param _reason Reason
    function requestEmergencyCancelAppointment(uint256 _appointmentId, string calldata _reason) external whenNotPaused {
        if (bytes(_reason).length > MAX_REASON_LENGTH) revert InvalidReasonLength();
        if (emergencyActionCounter >= MAX_COUNTER) revert InvalidCounter();
        try base.appointmentCounter() returns (uint256 counter) {
            if (_appointmentId > counter) revert InvalidAppointmentId();
        } catch {
            revert ExternalCallFailed();
        }
        TelemedicineBase.Appointment storage apt;
        try base.appointments(_appointmentId) returns (TelemedicineBase.Appointment storage appointment) {
            apt = appointment;
        } catch {
            revert ExternalCallFailed();
        }
        bool isDoctor;
        try core.hasRole(core.DOCTOR_ROLE(), msg.sender) returns (bool hasDoctorRole) {
            if (hasDoctorRole) {
                for (uint256 i = 0; i < apt.doctors.length; i++) {
                    if (apt.doctors[i] == msg.sender) {
                        isDoctor = true;
                        break;
                    }
                }
            }
        } catch {
            revert ExternalCallFailed();
        }
        try core.isConfigAdmin(msg.sender) returns (bool isAdmin) {
            if (!isAdmin && !(isDoctor)) revert Unauthorized();
        } catch {
            revert ExternalCallFailed();
        }
        if (apt.status != TelemedicineBase.AppointmentStatus.Pending && apt.status != TelemedicineBase.AppointmentStatus.Confirmed) revert InvalidStatus();
        if (apt.scheduledTimestamp <= block.timestamp) revert AlreadyStarted();

        emergencyActionCounter = emergencyActionCounter.add(1);
        EmergencyAction storage action = emergencyActions[emergencyActionCounter];
        action.actionType = EmergencyActionType.AppointmentCancellation;
        action.id = _appointmentId;
        action.requester = msg.sender;
        action.requestTime = block.timestamp;
        action.approvers.push(msg.sender);
        action.reasonHash = keccak256(abi.encode(_reason));
        emit EmergencyAppointmentCancellationRequested(emergencyActionCounter, keccak256(abi.encode(msg.sender)), _appointmentId, action.reasonHash);
    }

    // Emergency Prescription Revocation

    /// @notice Requests emergency prescription revocation
    /// @param _prescriptionId Prescription ID
    /// @param _reason Reason
    function requestEmergencyPrescriptionRevocation(uint256 _prescriptionId, string calldata _reason) external whenNotPaused {
        if (bytes(_reason).length > MAX_REASON_LENGTH) revert InvalidReasonLength();
        if (emergencyActionCounter >= MAX_COUNTER) revert InvalidCounter();
        try clinicalOps.prescriptionCounter() returns (uint256 counter) {
            if (_prescriptionId > counter) revert InvalidPrescriptionId();
        } catch {
            revert ExternalCallFailed();
        }
        TelemedicineClinicalOperations.Prescription storage pres;
        try clinicalOps.prescriptions(_prescriptionId) returns (TelemedicineClinicalOperations.Prescription storage prescription) {
            pres = prescription;
        } catch {
            revert ExternalCallFailed();
        }
        bool isDoctor;
        try core.hasRole(core.DOCTOR_ROLE(), msg.sender) returns (bool hasDoctorRole) {
            isDoctor = hasDoctorRole && pres.doctor == msg.sender;
        } catch {
            revert ExternalCallFailed();
        }
        try core.isConfigAdmin(msg.sender) returns (bool isAdmin) {
            if (!isAdmin && !isDoctor) revert Unauthorized();
        } catch {
            revert ExternalCallFailed();
        }
        if (pres.status != TelemedicineClinicalOperations.PrescriptionStatus.Generated && pres.status != TelemedicineClinicalOperations.PrescriptionStatus.Verified) revert InvalidStatus();

        emergencyActionCounter = emergencyActionCounter.add(1);
        EmergencyAction storage action = emergencyActions[emergencyActionCounter];
        action.actionType = EmergencyActionType.PrescriptionRevocation;
        action.id = _prescriptionId;
        action.requester = msg.sender;
        action.requestTime = block.timestamp;
        action.approvers.push(msg.sender);
        action.reasonHash = keccak256(abi.encode(_reason));
        emit EmergencyPrescriptionRevocationRequested(emergencyActionCounter, keccak256(abi.encode(msg.sender)), _prescriptionId, action.reasonHash);
    }

    // Emergency Lab Test Cancellation

    /// @notice Requests emergency lab test cancellation
    /// @param _labTestId Lab test ID
    /// @param _reason Reason
    function requestEmergencyCancelLabTest(uint256 _labTestId, string calldata _reason) external whenNotPaused {
        if (bytes(_reason).length > MAX_REASON_LENGTH) revert InvalidReasonLength();
        if (emergencyActionCounter >= MAX_COUNTER) revert InvalidCounter();
        try clinicalOps.labTestCounter() returns (uint256 counter) {
            if (_labTestId > counter) revert InvalidLabTestId();
        } catch {
            revert ExternalCallFailed();
        }
        TelemedicineClinicalOperations.LabTestOrder storage order;
        try clinicalOps.labTestOrders(_labTestId) returns (TelemedicineClinicalOperations.LabTestOrder storage labTest) {
            order = labTest;
        } catch {
            revert ExternalCallFailed();
        }
        bool isDoctor;
        try core.hasRole(core.DOCTOR_ROLE(), msg.sender) returns (bool hasDoctorRole) {
            isDoctor = hasDoctorRole && order.doctor == msg.sender;
        } catch {
            revert ExternalCallFailed();
        }
        try core.isConfigAdmin(msg.sender) returns (bool isAdmin) {
            if (!isAdmin && !isDoctor) revert Unauthorized();
        } catch {
            revert ExternalCallFailed();
        }
        if (order.status != TelemedicineClinicalOperations.LabTestStatus.Requested && order.status != TelemedicineClinicalOperations.LabTestStatus.PaymentPending) revert InvalidStatus();

        emergencyActionCounter = emergencyActionCounter.add(1);
        EmergencyAction storage action = emergencyActions[emergencyActionCounter];
        action.actionType = EmergencyActionType.LabTestCancellation;
        action.id = _labTestId;
        action.requester = msg.sender;
        action.requestTime = block.timestamp;
        action.approvers.push(msg.sender);
        action.reasonHash = keccak256(abi.encode(_reason));
        emit EmergencyLabTestCancellationRequested(emergencyActionCounter, keccak256(abi.encode(msg.sender)), _labTestId, action.reasonHash);
    }

    // Emergency Fund Withdrawal

    /// @notice Requests emergency fund withdrawal
    /// @param _amount Amount
    /// @param _reason Reason
    function requestEmergencyFundWithdrawal(uint256 _amount, string calldata _reason) external onlyConfigAdmin {
        if (bytes(_reason).length > MAX_REASON_LENGTH) revert InvalidReasonLength();
        if (emergencyActionCounter >= MAX_COUNTER) revert InvalidCounter();
        if (_amount > maxEmergencyWithdrawal) revert ExceedsMaxWithdrawal();
        try core.reserveFund() returns (uint256 reserve) {
            if (_amount > address(this).balance.sub(reserve)) revert InsufficientBalance();
        } catch {
            revert ExternalCallFailed();
        }

        emergencyActionCounter = emergencyActionCounter.add(1);
        EmergencyAction storage action = emergencyActions[emergencyActionCounter];
        action.actionType = EmergencyActionType.FundWithdrawal;
        action.id = emergencyActionCounter;
        action.requester = msg.sender;
        action.requestTime = block.timestamp;
        action.approvers.push(msg.sender);
        action.reasonHash = keccak256(abi.encode(_reason));
        action.amount = _amount;
        emit EmergencyFundWithdrawalRequested(emergencyActionCounter, keccak256(abi.encode(msg.sender)), _amount, action.reasonHash);
    }

    // Batch Execution

    /// @notice Executes multiple emergency actions
    /// @param _emergencyIds Emergency action IDs
    function batchExecuteEmergencyActions(uint256[] calldata _emergencyIds) external onlyConfigAdmin nonReentrant whenNotPaused {
        uint256 requiredApprovals;
        try governanceCore.requiredApprovals() returns (uint256 approvals) {
            requiredApprovals = approvals;
        } catch {
            revert ExternalCallFailed();
        }
        for (uint256 i = 0; i < _emergencyIds.length; i++) {
            uint256 _emergencyId = _emergencyIds[i];
            EmergencyAction storage action = emergencyActions[_emergencyId];
            if (action.requestTime == 0) continue;
            if (action.executed) continue;
            if (action.approvers.length < requiredApprovals) revert InsufficientApprovals();
            if (block.timestamp < action.requestTime.add(emergencyDelay)) revert ActionNotMatured();

            action.executed = true;
            if (action.actionType == EmergencyActionType.AppointmentCancellation) {
                TelemedicineBase.Appointment storage apt;
                try base.appointments(action.id) returns (TelemedicineBase.Appointment storage appointment) {
                    apt = appointment;
                } catch {
                    revert ExternalCallFailed();
                }
                apt.status = TelemedicineBase.AppointmentStatus.Cancelled;
                for (uint256 j = 0; j < apt.doctors.length; j++) {
                    try base._removePendingAppointment(apt.doctors[j], action.id) {} catch {
                        revert ExternalCallFailed();
                    }
                }
                try base.appointmentReminders(action.id) returns (TelemedicineBase.AppointmentReminder storage reminder) {
                    reminder.active = false;
                } catch {
                    revert ExternalCallFailed();
                }
                try payments._refundPatient(apt.patient, apt.fee, apt.paymentType) {} catch {
                    revert ExternalCallFailed();
                }
                emit EmergencyAppointmentCancelled(action.id, keccak256(abi.encode(action.requester)), action.reasonHash);
            } else if (action.actionType == EmergencyActionType.PrescriptionRevocation) {
                TelemedicineClinicalOperations.Prescription storage pres;
                try clinicalOps.prescriptions(action.id) returns (TelemedicineClinicalOperations.Prescription storage prescription) {
                    pres = prescription;
                } catch {
                    revert ExternalCallFailed();
                }
                pres.status = TelemedicineClinicalOperations.PrescriptionStatus.Revoked;
                bool paid;
                try paymentOps.getPrescriptionPaymentStatus(action.id) returns (bool status) {
                    paid = status;
                } catch {
                    revert ExternalCallFailed();
                }
                if (pres.patientCost > 0 && paid) {
                    try payments._refundPatient(pres.patient, pres.patientCost, pres.paymentType) {} catch {
                        revert ExternalCallFailed();
                    }
                }
                emit EmergencyPrescriptionRevoked(action.id, keccak256(abi.encode(action.requester)), action.reasonHash);
            } else if (action.actionType == EmergencyActionType.LabTestCancellation) {
                TelemedicineClinicalOperations.LabTestOrder storage order;
                try clinicalOps.labTestOrders(action.id) returns (TelemedicineClinicalOperations.LabTestOrder storage labTest) {
                    order = labTest;
                } catch {
                    revert ExternalCallFailed();
                }
                order.status = TelemedicineClinicalOperations.LabTestStatus.Expired;
                bool paid;
                try paymentOps.getLabTestPaymentStatus(action.id) returns (bool status) {
                    paid = status;
                } catch {
                    revert ExternalCallFailed();
                }
                if (order.patientCost > 0 && paid) {
                    try payments._refundPatient(order.patient, order.patientCost, order.paymentType) {} catch {
                        revert ExternalCallFailed();
                    }
                }
                emit EmergencyLabTestCancelled(action.id, keccak256(abi.encode(action.requester)), action.reasonHash);
            } else if (action.actionType == EmergencyActionType.FundWithdrawal) {
                try core.reserveFund() returns (uint256 reserve) {
                    uint256 amount = _min(action.amount, address(this).balance.sub(reserve));
                    try paymentOps.safeTransferETH(action.requester, amount) {} catch {
                        revert ExternalCallFailed();
                    }
                    emit EmergencyFundWithdrawn(_emergencyId, keccak256(abi.encode(action.requester)), amount, action.reasonHash);
                } catch {
                    revert ExternalCallFailed();
                }
            }
            // Reset approvers
            delete action.approvers;
        }
    }

    // Configuration Updates

    /// @notice Queues max emergency withdrawal update
    /// @param _newMax New max withdrawal
    function queueUpdateMaxEmergencyWithdrawal(uint256 _newMax) external onlyConfigAdmin {
        if (_newMax < MIN_MAX_WITHDRAWAL) revert InvalidMaxWithdrawal();
        bytes memory data = abi.encodeWithSignature("setMaxEmergencyWithdrawal(uint256)", _newMax);
        try governanceCore._queueTimeLock(TelemedicineGovernanceCore.TimeLockAction.AdjustMaxEmergencyWithdrawal, address(this), _newMax, data) {} catch {
            revert ExternalCallFailed();
        }
    }

    /// @notice Sets max emergency withdrawal
    /// @param _newMax New max withdrawal
    function setMaxEmergencyWithdrawal(uint256 _newMax) external onlyConfigAdmin {
        if (_newMax < MIN_MAX_WITHDRAWAL) revert InvalidMaxWithdrawal();
        maxEmergencyWithdrawal = _newMax;
        emit ConstantUpdated("maxEmergencyWithdrawal", _newMax);
    }

    /// @notice Queues emergency delay update
    /// @param _newDelay New delay
    function queueUpdateEmergencyDelay(uint256 _newDelay) external onlyConfigAdmin {
        if (_newDelay < MIN_EMERGENCY_DELAY) revert InvalidDelay();
        bytes memory data = abi.encodeWithSignature("setEmergencyDelay(uint256)", _newDelay);
        try governanceCore._queueTimeLock(TelemedicineGovernanceCore.TimeLockAction.ConfigurationUpdate, address(this), _newDelay, data) {} catch {
            revert ExternalCallFailed();
        }
    }

    /// @notice Sets emergency delay
    /// @param _newDelay New delay
    function setEmergencyDelay(uint256 _newDelay) external onlyConfigAdmin {
        if (_newDelay < MIN_EMERGENCY_DELAY) revert InvalidDelay();
        emergencyDelay = _newDelay;
        emit ConstantUpdated("emergencyDelay", _newDelay);
    }

    /// @notice Queues emergency role duration update
    /// @param _newDuration New duration
    function queueUpdateEmergencyRoleDuration(uint256 _newDuration) external onlyConfigAdmin {
        if (_newDuration < MIN_ROLE_DURATION) revert InvalidDuration();
        bytes memory data = abi.encodeWithSignature("setEmergencyRoleDuration(uint256)", _newDuration);
        try governanceCore._queueTimeLock(TelemedicineGovernanceCore.TimeLockAction.ConfigurationUpdate, address(this), _newDuration, data) {} catch {
            revert ExternalCallFailed();
        }
    }

    /// @notice Sets emergency role duration
    /// @param _newDuration New duration
    function setEmergencyRoleDuration(uint256 _newDuration) external onlyConfigAdmin {
        if (_newDuration < MIN_ROLE_DURATION) revert InvalidDuration();
        emergencyRoleDuration = _newDuration;
        emit ConstantUpdated("emergencyRoleDuration", _newDuration);
    }

    // Role Management

    /// @notice Grants emergency role
    /// @param _target Target address
    /// @param _role Role
    /// @param _reason Reason
    function grantEmergencyRole(address _target, bytes32 _role, string calldata _reason) external onlyConfigAdmin {
        if (_target == address(0)) revert InvalidTarget();
        if (bytes(_reason).length > MAX_REASON_LENGTH) revert InvalidReasonLength();
        uint256 expiration = block.timestamp.add(emergencyRoleDuration);
        try core.grantRole(_role, _target) {} catch {
            revert ExternalCallFailed();
        }
        emergencyRoleExpiration[_target] = expiration;
        emit EmergencyRoleGranted(
            keccak256(abi.encode(msg.sender)),
            keccak256(abi.encode(_target)),
            _role,
            expiration,
            keccak256(abi.encode(_reason))
        );
    }

    /// @notice Revokes emergency role
    /// @param _target Target address
    /// @param _role Role
    /// @param _reason Reason
    function revokeEmergencyRole(address _target, bytes32 _role, string calldata _reason) external onlyConfigAdmin {
        if (_target == address(0)) revert InvalidTarget();
        if (bytes(_reason).length > MAX_REASON_LENGTH) revert InvalidReasonLength();
        try core.revokeRole(_role, _target) {} catch {
            revert ExternalCallFailed();
        }
        delete emergencyRoleExpiration[_target];
        emit EmergencyRoleRevoked(
            keccak256(abi.encode(msg.sender)),
            keccak256(abi.encode(_target)),
            _role,
            keccak256(abi.encode(_reason))
        );
    }

    // Emergency Data Access

    /// @notice Accesses emergency patient data
    /// @param _patient Patient address
    /// @param _justification Justification
    /// @param _oracleResponse Oracle response
    function accessEmergencyData(address _patient, string calldata _justification, bytes calldata _oracleResponse) external onlyConfigAdmin {
        if (_patient == address(0)) revert InvalidAddress();
        if (bytes(_justification).length > MAX_REASON_LENGTH) revert InvalidReasonLength();
        try core.patients(_patient) returns (TelemedicineCore.Patient memory patient) {
            if (!patient.isRegistered) revert PatientNotRegistered();
        } catch {
            revert ExternalCallFailed();
        }
        if (_oracleResponse.length < 32) revert InvalidOracleResponse(); // Basic format check
        emit EmergencyDataAccessed(
            keccak256(abi.encode(msg.sender)),
            keccak256(abi.encode(_patient)),
            keccak256(abi.encode(_justification)),
            keccak256(_oracleResponse)
        );
    }

    // Dispute Management

    /// @notice Raises a dispute
    /// @param _relatedId Related ID (appointment/prescription)
    /// @param _reason Reason
    function raiseDispute(uint256 _relatedId, string calldata _reason) external whenNotPaused {
        if (bytes(_reason).length > MAX_REASON_LENGTH) revert InvalidReasonLength();
        if (disputeCounter >= MAX_COUNTER) revert InvalidCounter();
        bool isAuthorized;
        try core.hasRole(core.PATIENT_ROLE(), msg.sender) returns (bool isPatient) {
            isAuthorized = isPatient;
        } catch {
            revert ExternalCallFailed();
        }
        if (!isAuthorized) {
            try core.hasRole(core.DOCTOR_ROLE(), msg.sender) returns (bool isDoctor) {
                isAuthorized = isDoctor;
            } catch {
                revert ExternalCallFailed();
            }
        }
        if (!isAuthorized) {
            try core.isConfigAdmin(msg.sender) returns (bool isAdmin) {
                isAuthorized = isAdmin;
            } catch {
                revert ExternalCallFailed();
            }
        }
        if (!isAuthorized) revert Unauthorized();

        // Validate relatedId
        if (_relatedId > 0) {
            try base.appointmentCounter() returns (uint256 aptCounter) {
                if (_relatedId <= aptCounter) {
                    // Valid appointment
                } else {
                    try clinicalOps.prescriptionCounter() returns (uint256 presCounter) {
                        if (_relatedId > presCounter) revert InvalidId();
                    } catch {
                        revert ExternalCallFailed();
                    }
                }
            } catch {
                revert ExternalCallFailed();
            }
        }

        disputeCounter = disputeCounter.add(1);
        Dispute storage dispute = disputes[disputeCounter];
        dispute.id = disputeCounter;
        dispute.initiator = msg.sender;
        dispute.relatedId = _relatedId;
        dispute.status = DisputeStatus.Open;
        dispute.reasonHash = keccak256(abi.encode(_reason));
        emit DisputeRaised(disputeCounter, keccak256(abi.encode(msg.sender)), _relatedId, dispute.reasonHash);
    }

    /// @notice Resolves a dispute
    /// @param _disputeId Dispute ID
    /// @param _resolution Resolution
    function resolveDispute(uint256 _disputeId, string calldata _resolution) external onlyConfigAdmin {
        if (bytes(_resolution).length > MAX_REASON_LENGTH) revert InvalidReasonLength();
        Dispute storage dispute = disputes[_disputeId];
        if (dispute.status != DisputeStatus.Open && dispute.status != DisputeStatus.Escalated) revert DisputeNotOpen();
        dispute.status = DisputeStatus.Resolved;
        dispute.resolutionTimestamp = block.timestamp;
        emit DisputeResolved(_disputeId, keccak256(abi.encode(_resolution)));
    }

    // Data Archiving

    /// @notice Archives data
    /// @param _dataId Data ID
    /// @param _dataHash Data hash
    function archiveData(uint256 _dataId, bytes32 _dataHash) external onlyConfigAdmin {
        if (_dataHash == bytes32(0)) revert InvalidParameter();
        archivedData[_dataId] = _dataHash;
        emit DataArchived(_dataId, _dataHash);
    }

    // Keeper Functions

    /// @notice Checks upkeep for expired roles
    /// @param checkData Pagination data (startIndex)
    /// @return upkeepNeeded Upkeep needed flag
    /// @return performData Addresses to revoke
    function checkUpkeep(bytes calldata checkData) external view override returns (bool upkeepNeeded, bytes memory performData) {
        uint256 startIndex = checkData.length > 0 ? abi.decode(checkData, (uint256)) : 0;
        address[] memory admins;
        try core.admins() returns (address[] memory adminList) {
            admins = adminList;
        } catch {
            return (false, bytes(""));
        }
        address[] memory expired = new address[](MAX_ADMINS_PER_UPKEEP);
        uint256 count = 0;
        for (uint256 i = startIndex; i < admins.length && count < MAX_ADMINS_PER_UPKEEP; i++) {
            if (emergencyRoleExpiration[admins[i]] > 0 && block.timestamp >= emergencyRoleExpiration[admins[i]]) {
                expired[count] = admins[i];
                count++;
            }
        }
        if (count > 0) {
            address[] memory result = new address[](count);
            for (uint256 i = 0; i < count; i++) {
                result[i] = expired[i];
            }
            return (true, abi.encode(result, startIndex + MAX_ADMINS_PER_UPKEEP));
        }
        return (false, bytes(""));
    }

    /// @notice Performs upkeep for expired roles
    /// @param performData Addresses to revoke and next startIndex
    function performUpkeep(bytes calldata performData) external override {
        (address[] memory targets, ) = abi.decode(performData, (address[], uint256));
        for (uint256 i = 0; i < targets.length; i++) {
            address target = targets[i];
            if (emergencyRoleExpiration[target] > 0 && block.timestamp >= emergencyRoleExpiration[target]) {
                try core.revokeRole(core.ADMIN_ROLE(), target) {} catch {
                    continue;
                }
                delete emergencyRoleExpiration[target];
                emit EmergencyRoleRevoked(
                    keccak256(abi.encode(msg.sender)),
                    keccak256(abi.encode(target)),
                    core.ADMIN_ROLE(),
                    keccak256(abi.encode("Expired emergency role"))
                );
            }
        }
        emit UpkeepPerformed(targets, keccak256(abi.encode("Role expiration")));
    }

    // Utility Functions

    /// @notice Returns minimum of two numbers
    /// @param a First number
    /// @param b Second number
    /// @return Minimum
    function _min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    /// @notice Checks if an address is a contract
    /// @param addr Address
    /// @return True if contract
    function _isContract(address addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }

    // View Functions

    /// @notice Gets emergency action
    /// @param _emergencyId Emergency action ID
    /// @return Action details
    function getEmergencyAction(uint256 _emergencyId) external view onlyConfigAdmin returns (
        EmergencyActionType actionType,
        uint256 id,
        address requester,
        uint256 requestTime,
        address[] memory approvers,
        bool executed,
        bytes32 reasonHash,
        uint256 amount
    ) {
        EmergencyAction storage action = emergencyActions[_emergencyId];
        return (
            action.actionType,
            action.id,
            action.requester,
            action.requestTime,
            action.approvers,
            action.executed,
            action.reasonHash,
            action.amount
        );
    }

    /// @notice Gets dispute
    /// @param _disputeId Dispute ID
    /// @return Dispute details
    function getDispute(uint256 _disputeId) external view onlyConfigAdmin returns (
        uint256 id,
        address initiator,
        uint256 relatedId,
        DisputeStatus status,
        bytes32 reasonHash,
        uint256 resolutionTimestamp
    ) {
        Dispute storage dispute = disputes[_disputeId];
        return (
            dispute.id,
            dispute.initiator,
            dispute.relatedId,
            dispute.status,
            dispute.reasonHash,
            dispute.resolutionTimestamp
        );
    }

    /// @notice Gets archived data
    /// @param _dataId Data ID
    /// @return Data hash
    function getArchivedData(uint256 _dataId) external view onlyConfigAdmin returns (bytes32) {
        return archivedData[_dataId];
    }

    /// @notice Gets role expiration
    /// @param _target Target address
    /// @return Expiration timestamp
    function getRoleExpiration(address _target) external view onlyConfigAdmin returns (uint256) {
        return emergencyRoleExpiration[_target];
    }

    // Modifiers

    modifier onlyRole(bytes32 role) {
        try core.hasRole(role, msg.sender) returns (bool hasRole) {
            if (!hasRole) revert Unauthorized();
            if (emergencyRoleExpiration[msg.sender] > 0 && block.timestamp >= emergencyRoleExpiration[msg.sender]) revert RoleExpired();
            _;
        } catch {
            revert ExternalCallFailed();
        }
    }

    modifier onlyConfigAdmin() {
        try core.isConfigAdmin(msg.sender) returns (bool isAdmin) {
            if (!isAdmin) revert Unauthorized();
            if (emergencyRoleExpiration[msg.sender] > 0 && block.timestamp >= emergencyRoleExpiration[msg.sender]) revert RoleExpired();
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

    // Fallback
    receive() external payable {}
}
