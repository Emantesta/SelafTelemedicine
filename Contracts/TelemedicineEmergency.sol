<xaiArtifact artifact_id="5add9d2b-0b18-4266-8202-009bd5274209" artifact_version_id="45be63c0-f4f4-425d-b943-54ba3f77eaa5" title="TelemedicineEmergency.sol" contentType="text/solidity">
// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
import {Initializable} from "@openzeppelin
/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin
/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {SafeMathUpgradeable} from "@openzeppelin
/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";
import {KeeperCompatibleInterface} from "@chainlink
/contracts/src/v0.8/KeeperCompatible.sol";
import {TelemedicineCore} from "./TelemedicineCore.sol";
import {TelemedicineMedical} from "./TelemedicineMedical.sol";
import {TelemedicinePayments} from "./TelemedicinePayments.sol";
import {TelemedicineGovernanceCore} from "./TelemedicineGovernanceCore.sol";
contract TelemedicineEmergency is Initializable, ReentrancyGuardUpgradeable, KeeperCompatibleInterface {
    using SafeMathUpgradeable for uint256;

TelemedicineCore public core;
TelemedicineMedical public medical;
TelemedicinePayments public payments;
TelemedicineGovernanceCore public governanceCore;

uint256 public emergencyDelay;
uint256 public maxEmergencyWithdrawal;
uint256 public emergencyRoleDuration;

mapping(uint256 => EmergencyAction) public emergencyActions;
mapping(address => uint256) public emergencyRoleExpiration;
mapping(uint256 => Dispute) public disputes;
mapping(uint256 => bytes32) public archivedData;

uint256 public emergencyActionCounter;
uint256 public disputeCounter;

enum EmergencyActionType { Unpause, FundWithdrawal, PrescriptionRevocation, AppointmentCancellation }
enum DisputeStatus { Open, Resolved, Escalated }

struct EmergencyAction {
    EmergencyActionType actionType;
    uint256 id;
    address requester;
    uint256 requestTime;
    mapping(address => bool) approvals;
    uint256 approvalCount;
    bool executed;
    string reason;
}

struct Dispute {
    uint256 id;
    address initiator;
    uint256 relatedId;
    DisputeStatus status;
    string reason;
    uint256 resolutionTimestamp;
}

event EmergencyPaused(address indexed admin, uint256 timestamp, string reason);
event EmergencyUnpaused(address indexed admin, uint256 timestamp, string reason);
event EmergencyAppointmentCancelled(uint256 indexed appointmentId, address indexed requester, string reason);
event EmergencyPrescriptionRevoked(uint256 indexed prescriptionId, address indexed requester, string reason);
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
    address _medical,
    address _payments,
    address _governanceCore
) external initializer {
    __ReentrancyGuard_init();
    core = TelemedicineCore(_core);
    medical = TelemedicineMedical(_medical);
    payments = TelemedicinePayments(_payments);
    governanceCore = TelemedicineGovernanceCore(_governanceCore);
    emergencyDelay = 1 hours;
    maxEmergencyWithdrawal = 10 ether;
    emergencyRoleDuration = 1 days;
}

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
    action.approvals[msg.sender] = true;
    action.approvalCount = 1;
    action.reason = "Request to unpause contract";
    emit EmergencyFundWithdrawalRequested(emergencyActionCounter, msg.sender, 0, action.reason);
}

function approveEmergencyUnpause(uint256 _emergencyId) external onlyRole(core.ADMIN_ROLE()) {
    EmergencyAction storage action = emergencyActions[_emergencyId];
    require(action.actionType == EmergencyActionType.Unpause, "Invalid action type");
    require(action.requestTime > 0, "No request exists");
    require(!action.approvals[msg.sender], "Already approved");
    require(!action.executed, "Already executed");

    action.approvals[msg.sender] = true;
    action.approvalCount = action.approvalCount.add(1);
    emit EmergencyFundWithdrawalApproved(_emergencyId, msg.sender);

    if (action.approvalCount >= governanceCore.requiredApprovals() && block.timestamp >= action.requestTime.add(emergencyDelay)) {
        core._unpause();
        action.executed = true;
        emit EmergencyUnpaused(msg.sender, block.timestamp, "Contract unpaused");
    }
}

function requestEmergencyCancelAppointment(uint256 _appointmentId, string calldata _reason) external {
    TelemedicineMedical.Appointment storage apt = medical.appointments(_appointmentId);
    require(
        core.hasRole(core.ADMIN_ROLE(), msg.sender) || 
        (core.hasRole(core.DOCTOR_ROLE(), msg.sender) && apt.doctor == msg.sender),
        "Unauthorized"
    );
    require(
        apt.status == TelemedicineMedical.AppointmentStatus.Pending || 
        apt.status == TelemedicineMedical.AppointmentStatus.Confirmed,
        "Cannot cancel: invalid status"
    );
    require(apt.scheduledTimestamp > block.timestamp, "Already started");

    emergencyActionCounter = emergencyActionCounter.add(1);
    EmergencyAction storage action = emergencyActions[emergencyActionCounter];
    action.actionType = EmergencyActionType.AppointmentCancellation;
    action.id = _appointmentId;
    action.requester = msg.sender;
    action.requestTime = block.timestamp;
    action.approvals[msg.sender] = true;
    action.approvalCount = 1;
    action.reason = _reason;
    emit EmergencyFundWithdrawalRequested(emergencyActionCounter, msg.sender, 0, _reason);
}

function approveEmergencyCancelAppointment(uint256 _emergencyId) external onlyRole(core.ADMIN_ROLE()) {
    EmergencyAction storage action = emergencyActions[_emergencyId];
    require(action.actionType == EmergencyActionType.AppointmentCancellation, "Invalid action type");
    require(action.requestTime > 0, "No request exists");
    require(!action.approvals[msg.sender], "Already approved");
    require(!action.executed, "Already executed");

    action.approvals[msg.sender] = true;
    action.approvalCount = action.approvalCount.add(1);
    emit EmergencyFundWithdrawalApproved(_emergencyId, msg.sender);

    if (action.approvalCount >= governanceCore.requiredApprovals()) {
        TelemedicineMedical.Appointment storage apt = medical.appointments(action.id);
        apt.status = TelemedicineMedical.AppointmentStatus.Cancelled;
        medical._removePendingAppointment(apt.doctor, action.id);
        payments._refundPatient(apt.patient, apt.fee, apt.paymentType);
        action.executed = true;
        emit EmergencyAppointmentCancelled(action.id, action.requester, action.reason);
    }
}

function requestEmergencyPrescriptionRevocation(uint256 _prescriptionId, string calldata _reason) external {
    TelemedicineMedical.Prescription storage pres = medical.prescriptions(_prescriptionId);
    require(
        core.hasRole(core.ADMIN_ROLE(), msg.sender) || 
        (core.hasRole(core.DOCTOR_ROLE(), msg.sender) && pres.doctor == msg.sender),
        "Unauthorized"
    );
    require(
        pres.status == TelemedicineMedical.PrescriptionStatus.Generated || 
        pres.status == TelemedicineMedical.PrescriptionStatus.Verified,
        "Cannot revoke: invalid status"
    );

    emergencyActionCounter = emergencyActionCounter.add(1);
    EmergencyAction storage action = emergencyActions[emergencyActionCounter];
    action.actionType = EmergencyActionType.PrescriptionRevocation;
    action.id = _prescriptionId;
    action.requester = msg.sender;
    action.requestTime = block.timestamp;
    action.approvals[msg.sender] = true;
    action.approvalCount = 1;
    action.reason = _reason;
    emit EmergencyFundWithdrawalRequested(emergencyActionCounter, msg.sender, 0, _reason);
}

function approveEmergencyPrescriptionRevocation(uint256 _emergencyId) external onlyRole(core.ADMIN_ROLE()) {
    EmergencyAction storage action = emergencyActions[_emergencyId];
    require(action.actionType == EmergencyActionType.PrescriptionRevocation, "Invalid action type");
    require(action.requestTime > 0, "No request exists");
    require(!action.approvals[msg.sender], "Already approved");
    require(!action.executed, "Already executed");

    action.approvals[msg.sender] = true;
    action.approvalCount = action.approvalCount.add(1);
    emit EmergencyFundWithdrawalApproved(_emergencyId, msg.sender);

    if (action.approvalCount >= governanceCore.requiredApprovals()) {
        TelemedicineMedical.Prescription storage pres = medical.prescriptions(action.id);
        pres.status = TelemedicineMedical.PrescriptionStatus.Revoked;
        action.executed = true;
        emit EmergencyPrescriptionRevoked(action.id, action.requester, action.reason);
    }
}

function requestEmergencyFundWithdrawal(uint256 _amount, string calldata _reason) external onlyRole(core.ADMIN_ROLE()) {
    require(_amount <= maxEmergencyWithdrawal, "Exceeds max emergency withdrawal");
    require(_amount <= core.getContractBalance().sub(core.getReserveFundBalance()), "Insufficient balance excluding reserve");

    emergencyActionCounter = emergencyActionCounter.add(1);
    EmergencyAction storage action = emergencyActions[emergencyActionCounter];
    action.actionType = EmergencyActionType.FundWithdrawal;
    action.id = emergencyActionCounter;
    action.requester = msg.sender;
    action.requestTime = block.timestamp;
    action.approvals[msg.sender] = true;
    action.approvalCount = 1;
    action.reason = _reason;
    emit EmergencyFundWithdrawalRequested(emergencyActionCounter, msg.sender, _amount, _reason);
}

function approveEmergencyFundWithdrawal(uint256 _emergencyId) external onlyRole(core.ADMIN_ROLE()) {
    EmergencyAction storage action = emergencyActions[_emergencyId];
    require(action.actionType == EmergencyActionType.FundWithdrawal, "Invalid action type");
    require(action.requestTime > 0, "No request exists");
    require(!action.approvals[msg.sender], "Already approved");
    require(!action.executed, "Already executed");

    action.approvals[msg.sender] = true;
    action.approvalCount = action.approvalCount.add(1);
    emit EmergencyFundWithdrawalApproved(_emergencyId, msg.sender);

    if (action.approvalCount >= governanceCore.requiredApprovals() && block.timestamp >= action.requestTime.add(emergencyDelay)) {
        uint256 amount = _min(maxEmergencyWithdrawal, core.getContractBalance().sub(core.getReserveFundBalance()));
        (bool success, ) = action.requester.call{value: amount}("");
        require(success, "Withdrawal failed");
        action.executed = true;
        emit EmergencyFundWithdrawn(_emergencyId, action.requester, amount, action.reason);
    }
}

function queueUpdateMaxEmergencyWithdrawal(uint256 _newMax) external onlyRole(core.ADMIN_ROLE()) {
    require(_newMax > 0, "Max withdrawal must be positive");
    bytes memory data = abi.encodeWithSignature("setMaxEmergencyWithdrawal(uint256)", _newMax);
    governanceCore._queueTimeLock(TelemedicineGovernanceCore.TimeLockAction.AdjustMaxEmergencyWithdrawal, address(this), _newMax, data);
}

function setMaxEmergencyWithdrawal(uint256 _newMax) external onlyRole(core.ADMIN_ROLE()) {
    maxEmergencyWithdrawal = _newMax;
    emit ConstantUpdated("maxEmergencyWithdrawal", _newMax);
}

function grantEmergencyRole(address _target, bytes32 _role, string calldata _reason) external onlyRole(core.ADMIN_ROLE()) {
    require(_target != address(0), "Target address cannot be zero");
    uint256 expiration = block.timestamp.add(emergencyRoleDuration);
    core.grantRole(_role, _target);
    emergencyRoleExpiration[_target] = expiration;
    emit EmergencyRoleGranted(msg.sender, _target, _role, expiration, _reason);
}

function revokeEmergencyRole(address _target, bytes32 _role, string calldata _reason) external onlyRole(core.ADMIN_ROLE()) {
    require(_target != address(0), "Target address cannot be zero");
    core.revokeRole(_role, _target);
    delete emergencyRoleExpiration[_target];
    emit EmergencyRoleRevoked(msg.sender, _target, _role, _reason);
}

function accessEmergencyData(address _patient, string calldata _justification, bytes calldata _oracleResponse) external onlyRole(core.ADMIN_ROLE()) {
    require(core.patients(_patient).isRegistered, "Patient not registered");
    // In practice, this would involve an oracle callback; here we simulate verification
    require(_oracleResponse.length > 0, "Invalid oracle response");
    emit EmergencyDataAccessed(msg.sender, _patient, _justification, _oracleResponse);
}

function raiseDispute(uint256 _relatedId, string calldata _reason) external {
    require(
        core.hasRole(core.PATIENT_ROLE(), msg.sender) || 
        core.hasRole(core.DOCTOR_ROLE(), msg.sender) || 
        core.hasRole(core.ADMIN_ROLE(), msg.sender),
        "Unauthorized"
    );
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
    require(dispute.status == DisputeStatus.Open || dispute.status == DisputeStatus.Escalated, "Dispute not open");
    dispute.status = DisputeStatus.Resolved;
    dispute.resolutionTimestamp = block.timestamp;
    emit DisputeResolved(_disputeId, _resolution);
}

function archiveData(uint256 _dataId, bytes32 _dataHash) external onlyRole(core.ADMIN_ROLE()) {
    archivedData[_dataId] = _dataHash;
    emit DataArchived(_dataId, _dataHash);
}

function checkUpkeep(bytes calldata) external view override returns (bool upkeepNeeded, bytes memory performData) {
    // Check for expired emergency roles
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

function _min(uint256 a, uint256 b) internal pure returns (uint256) {
    return a < b ? a : b;
}

function toString(address account) internal pure returns (string memory) {
    return string(abi.encodePacked(account));
}

modifier onlyRole(bytes32 role) {
    require(core.hasRole(role, msg.sender), "Unauthorized");
    _;
}

}
</xaiArtifact>

