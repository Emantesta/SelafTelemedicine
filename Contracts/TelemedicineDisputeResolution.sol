// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import {SafeMathUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";
import {TelemedicineCore} from "./TelemedicineCore.sol";
import {TelemedicineGovernanceCore} from "./TelemedicineGovernanceCore.sol";
import {TelemedicinePayments} from "./TelemedicinePayments.sol";
import {TelemedicineMedicalCore} from "./TelemedicineMedicalCore.sol";
import {LinkTokenInterface} from "@chainlink/contracts/src/v0.8/interfaces/LinkTokenInterface.sol";
import {ChainlinkClient} from "@chainlink/contracts/src/v0.8/ChainlinkClient.sol";

contract TelemedicineDisputeResolution is Initializable, UUPSUpgradeable, ReentrancyGuardUpgradeable, PausableUpgradeable, ChainlinkClient {
    using SafeMathUpgradeable for uint256;
    using Chainlink for Chainlink.Request;

    TelemedicineCore public core;
    TelemedicineGovernanceCore public governance;
    TelemedicinePayments public payments;
    TelemedicineMedicalCore public medical;

    // Chainlink Configuration
    address public chainlinkOracle;
    bytes32 public chainlinkJobId;
    uint256 public chainlinkFee;
    LinkTokenInterface public linkToken;

    // Configuration Variables
    uint256 public disputeSubmissionPeriod;
    uint256 public evidenceSubmissionPeriod;
    uint256 public oracleTimeout;

    // Dispute Counter
    uint256 public disputeCounter;

    // Dispute Data
    mapping(uint256 => Dispute) public disputes;
    mapping(uint256 => mapping(address => bytes32)) public evidenceHashes; // Dispute ID => Party => IPFS Hash
    mapping(bytes32 => uint256) public chainlinkRequestToDisputeId; // Chainlink request ID => Dispute ID

    // Structs
    struct Dispute {
        uint256 id;
        address patient;
        address doctor;
        address labTechnician;
        address pharmacy;
        DisputeType disputeType;
        uint256 prescriptionId; // Links to TelemedicineMedicalCore Prescription
        uint256 patientCost; // Aligned with TelemedicineMedicalCore
        TelemedicinePayments.PaymentType paymentType;
        DisputeStatus status;
        uint48 createdAt;
        uint48 evidenceDeadline;
        bytes32 resolutionReason;
        bool escalated;
    }

    // Enums
    enum DisputeType { Misdiagnosis, LabError, PharmacyError, PaymentIssue }
    enum DisputeStatus { Pending, EvidenceSubmitted, OracleRequested, AutoResolved, Escalated, Resolved, Cancelled }

    // Events
    event DisputeInitiated(
        uint256 indexed disputeId,
        address indexed patient,
        address doctor,
        address labTechnician,
        address pharmacy,
        DisputeType disputeType,
        uint256 prescriptionId
    );
    event EvidenceSubmitted(uint256 indexed disputeId, address indexed submitter, bytes32 evidenceHash);
    event OracleRequestSent(uint256 indexed disputeId, bytes32 indexed requestId);
    event OracleRequestFailed(uint256 indexed disputeId, string reason);
    event DisputeAutoResolved(uint256 indexed disputeId, bytes32 resolutionReason);
    event DisputeEscalated(uint256 indexed disputeId, address indexed admin);
    event DisputeResolved(uint256 indexed disputeId, bytes32 resolutionReason);
    event DisputeCancelled(uint256 indexed disputeId, address indexed canceller);
    event ReplacementOrdered(uint256 indexed disputeId, uint256 newPrescriptionId);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the dispute resolution contract with dependencies and Chainlink configuration
    /// @param _core Address of the TelemedicineCore contract
    /// @param _governance Address of the TelemedicineGovernanceCore contract
    /// @param _payments Address of the TelemedicinePayments contract
    /// @param _medical Address of the TelemedicineMedicalCore contract
    /// @param _chainlinkOracle Address of the Chainlink oracle
    /// @param _chainlinkJobId Job ID for Chainlink requests
    /// @param _linkToken Address of the LINK token contract
    function initialize(
        address _core,
        address _governance,
        address _payments,
        address _medical,
        address _chainlinkOracle,
        bytes32 _chainlinkJobId,
        address _linkToken
    ) external initializer {
        if (_core == address(0) || _governance == address(0) || _payments == address(0) || _medical == address(0) ||
            _chainlinkOracle == address(0) || _linkToken == address(0)) revert("Invalid address");

        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        __Pausable_init();
        __ChainlinkClient_init();

        core = TelemedicineCore(_core);
        governance = TelemedicineGovernanceCore(_governance);
        payments = TelemedicinePayments(_payments);
        medical = TelemedicineMedicalCore(_medical);
        chainlinkOracle = _chainlinkOracle;
        chainlinkJobId = _chainlinkJobId;
        linkToken = LinkTokenInterface(_linkToken);
        setChainlinkToken(_linkToken);

        disputeSubmissionPeriod = 7 days;
        evidenceSubmissionPeriod = 48 hours;
        oracleTimeout = 24 hours;
        chainlinkFee = 0.1 ether; // 0.1 LINK, adjust per network
    }

    /// @notice Authorizes an upgrade to a new implementation
    /// @param newImplementation Address of the new implementation contract
    function _authorizeUpgrade(address newImplementation) internal override onlyRole(core.ADMIN_ROLE()) {}

    /// @notice Initiates a dispute related to a prescription
    /// @param _doctor Address of the doctor involved (if applicable)
    /// @param _labTechnician Address of the lab technician involved (if applicable)
    /// @param _pharmacy Address of the pharmacy involved (if applicable)
    /// @param _disputeType Type of dispute (Misdiagnosis, LabError, PharmacyError, PaymentIssue)
    /// @param _prescriptionId ID of the prescription linked to the dispute
    function initiateDispute(
        address _doctor,
        address _labTechnician,
        address _pharmacy,
        DisputeType _disputeType,
        uint256 _prescriptionId
    ) external onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
        require(
            (_doctor != address(0) && core.hasRole(core.DOCTOR_ROLE(), _doctor)) ||
            (_labTechnician != address(0) && core.hasRole(core.LAB_TECH_ROLE(), _labTechnician)) ||
            (_pharmacy != address(0) && core.hasRole(core.PHARMACY_ROLE(), _pharmacy)),
            "Invalid party address"
        );
        TelemedicineMedicalCore.Prescription memory prescription = medical.prescriptions(_prescriptionId);
        require(_prescriptionId > 0 && prescription.patient == msg.sender, "Invalid prescription");
        require(prescription.patientCost > 0, "No payment to dispute");
        require(block.timestamp <= prescription.disputeWindowEnd, "Dispute window expired");

        disputeCounter = disputeCounter.add(1);
        uint256 disputeId = disputeCounter;

        disputes[disputeId] = Dispute({
            id: disputeId,
            patient: msg.sender,
            doctor: _doctor,
            labTechnician: _labTechnician,
            pharmacy: _pharmacy,
            disputeType: _disputeType,
            prescriptionId: _prescriptionId,
            patientCost: prescription.patientCost,
            paymentType: prescription.paymentType,
            status: DisputeStatus.Pending,
            createdAt: uint48(block.timestamp),
            evidenceDeadline: uint48(block.timestamp.add(evidenceSubmissionPeriod)),
            resolutionReason: bytes32(0),
            escalated: false
        });

        emit DisputeInitiated(disputeId, msg.sender, _doctor, _labTechnician, _pharmacy, _disputeType, _prescriptionId);
    }

    /// @notice Submits evidence for a dispute
    /// @param _disputeId ID of the dispute
    /// @param _evidenceHash IPFS hash of the submitted evidence
    function submitEvidence(uint256 _disputeId, bytes32 _evidenceHash) external nonReentrant whenNotPaused {
        Dispute storage dispute = disputes[_disputeId];
        require(dispute.status == DisputeStatus.Pending, "Dispute not pending");
        require(block.timestamp <= dispute.evidenceDeadline, "Evidence submission period expired");
        require(_evidenceHash != bytes32(0), "Invalid evidence hash");

        bool isValidParty = (msg.sender == dispute.patient && core.hasRole(core.PATIENT_ROLE(), msg.sender)) ||
                           (msg.sender == dispute.doctor && core.hasRole(core.DOCTOR_ROLE(), msg.sender)) ||
                           (msg.sender == dispute.labTechnician && core.hasRole(core.LAB_TECH_ROLE(), msg.sender)) ||
                           (msg.sender == dispute.pharmacy && core.hasRole(core.PHARMACY_ROLE(), msg.sender));
        require(isValidParty, "Unauthorized submitter");

        evidenceHashes[_disputeId][msg.sender] = _evidenceHash;
        emit EvidenceSubmitted(_disputeId, msg.sender, _evidenceHash);

        if (_allEvidenceSubmitted(_disputeId)) {
            dispute.status = DisputeStatus.EvidenceSubmitted;
            _requestOracleVerification(_disputeId);
        }
    }

    /// @notice Requests Chainlink oracle verification for a dispute
    /// @param _disputeId ID of the dispute to verify
    function _requestOracleVerification(uint256 _disputeId) internal {
        Dispute storage dispute = disputes[_disputeId];
        require(dispute.status == DisputeStatus.EvidenceSubmitted, "Not ready for oracle");

        if (linkToken.balanceOf(address(this)) < chainlinkFee) {
            dispute.status = DisputeStatus.Escalated;
            dispute.escalated = true;
            emit OracleRequestFailed(_disputeId, "Insufficient LINK");
            emit DisputeEscalated(_disputeId, address(0));
            return;
        }

        Chainlink.Request memory request = buildChainlinkRequest(chainlinkJobId, address(this), this.fulfillOracleResponse.selector);
        request.add("disputeId", uint2str(_disputeId));
        request.add("prescriptionHash", bytes32ToString(medical.prescriptions(dispute.prescriptionId).prescriptionIpfsHash));
        request.add("patientEvidenceHash", bytes32ToString(evidenceHashes[_disputeId][dispute.patient]));
        request.addString("endpoint", "verifyEvidence");

        bytes32 requestId = sendChainlinkRequestTo(chainlinkOracle, request, chainlinkFee);
        if (requestId == bytes32(0)) {
            dispute.status = DisputeStatus.Escalated;
            dispute.escalated = true;
            emit OracleRequestFailed(_disputeId, "Chainlink request failed");
            emit DisputeEscalated(_disputeId, address(0));
            return;
        }

        chainlinkRequestToDisputeId[requestId] = _disputeId;
        dispute.status = DisputeStatus.OracleRequested;
        emit OracleRequestSent(_disputeId, requestId);
    }

    /// @notice Handles Chainlink oracle response for dispute verification
    /// @param _requestId Chainlink request ID
    /// @param _isMismatch Whether evidence indicates a mismatch
    /// @param _evidenceResultHash Hash of the oracle's evidence result
    function fulfillOracleResponse(bytes32 _requestId, bool _isMismatch, bytes32 _evidenceResultHash) external recordChainlinkFulfillment(_requestId) {
        uint256 disputeId = chainlinkRequestToDisputeId[_requestId];
        Dispute storage dispute = disputes[disputeId];
        require(dispute.status == DisputeStatus.OracleRequested, "Invalid dispute state");
        require(block.timestamp <= dispute.createdAt.add(oracleTimeout), "Oracle timeout exceeded");

        if (_isMismatch && dispute.disputeType == DisputeType.PharmacyError) {
            _autoResolveDispute(disputeId, _evidenceResultHash);
        } else {
            dispute.status = DisputeStatus.Escalated;
            dispute.escalated = true;
            emit DisputeEscalated(disputeId, address(0));
        }
    }

    /// @notice Queues resolution of an escalated dispute with timelock
    /// @param _disputeId ID of the dispute to resolve
    /// @param _patientWins Whether the patient wins the dispute
    /// @param _resolutionReason Reason for the resolution
    function queueResolveDispute(uint256 _disputeId, bool _patientWins, bytes32 _resolutionReason) external onlyRole(core.ADMIN_ROLE()) nonReentrant whenNotPaused {
        Dispute storage dispute = disputes[_disputeId];
        require(dispute.status == DisputeStatus.Escalated, "Dispute not escalated");
        require(_resolutionReason != bytes32(0), "Invalid resolution reason");

        bytes memory data = abi.encodeWithSignature("executeResolveDispute(uint256,bool,bytes32)", _disputeId, _patientWins, _resolutionReason);
        governance._queueTimeLock(
            TelemedicineGovernanceCore.TimeLockAction(6), // Assuming 6 is DisputeResolution action
            address(this),
            0,
            data
        );
    }

    /// @notice Executes resolution of an escalated dispute after timelock
    /// @param _disputeId ID of the dispute to resolve
    /// @param _patientWins Whether the patient wins the dispute
    /// @param _resolutionReason Reason for the resolution
    function executeResolveDispute(uint256 _disputeId, bool _patientWins, bytes32 _resolutionReason) external onlyRole(core.ADMIN_ROLE()) nonReentrant whenNotPaused {
        Dispute storage dispute = disputes[_disputeId];
        require(dispute.status == DisputeStatus.Escalated, "Dispute not escalated");

        dispute.status = DisputeStatus.Resolved;
        dispute.resolutionReason = _resolutionReason;

        if (_patientWins) {
            payments.refundPatient(dispute.patient, dispute.patientCost, dispute.paymentType, dispute.id);
            if (dispute.disputeType == DisputeType.PharmacyError) {
                _orderReplacement(dispute);
            }
        }

        emit DisputeResolved(_disputeId, _resolutionReason);
    }

    /// @notice Cancels a dispute by the patient or admin
    /// @param _disputeId ID of the dispute to cancel
    function cancelDispute(uint256 _disputeId) external nonReentrant whenNotPaused {
        Dispute storage dispute = disputes[_disputeId];
        require(dispute.status == DisputeStatus.Pending || dispute.status == DisputeStatus.EvidenceSubmitted, "Cannot cancel dispute");
        require(msg.sender == dispute.patient || core.hasRole(core.ADMIN_ROLE(), msg.sender), "Unauthorized canceller");

        dispute.status = DisputeStatus.Cancelled;
        emit DisputeCancelled(_disputeId, msg.sender);
    }

    /// @notice Checks if an ID is disputed
    /// @param _id ID of the prescription or other entity to check
    /// @return True if the ID is associated with an active dispute
    function isDisputed(uint256 _id) external view returns (bool) {
        for (uint256 i = 1; i <= disputeCounter; i++) {
            Dispute storage dispute = disputes[i];
            if (dispute.prescriptionId == _id && 
                (dispute.status == DisputeStatus.Pending || 
                 dispute.status == DisputeStatus.EvidenceSubmitted || 
                 dispute.status == DisputeStatus.OracleRequested || 
                 dispute.status == DisputeStatus.Escalated)) {
                return true;
            }
        }
        return false;
    }

    /// @notice Gets the outcome of a resolved dispute
    /// @param _id ID of the prescription or other entity
    /// @return DisputeOutcome enum value (Unresolved, PatientFavored, ProviderFavored, MutualAgreement)
    function getDisputeOutcome(uint256 _id) external view returns (TelemedicineMedicalCore.DisputeOutcome) {
        for (uint256 i = 1; i <= disputeCounter; i++) {
            Dispute storage dispute = disputes[i];
            if (dispute.prescriptionId == _id) {
                if (dispute.status == DisputeStatus.Resolved || dispute.status == DisputeStatus.AutoResolved) {
                    if (dispute.resolutionReason != bytes32(0)) {
                        return TelemedicineMedicalCore.DisputeOutcome.PatientFavored;
                    }
                    return TelemedicineMedicalCore.DisputeOutcome.ProviderFavored;
                } else if (dispute.status == DisputeStatus.Cancelled) {
                    return TelemedicineMedicalCore.DisputeOutcome.MutualAgreement;
                }
                return TelemedicineMedicalCore.DisputeOutcome.Unresolved;
            }
        }
        return TelemedicineMedicalCore.DisputeOutcome.Unresolved;
    }

    // Internal Functions

    /// @notice Checks if all required evidence has been submitted for a dispute
    /// @param _disputeId ID of the dispute
    /// @return True if all parties have submitted evidence
    function _allEvidenceSubmitted(uint256 _disputeId) internal view returns (bool) {
        Dispute storage dispute = disputes[_disputeId];
        return (dispute.patient != address(0) && evidenceHashes[_disputeId][dispute.patient] != bytes32(0)) &&
               (dispute.doctor == address(0) || evidenceHashes[_disputeId][dispute.doctor] != bytes32(0)) &&
               (dispute.labTechnician == address(0) || evidenceHashes[_disputeId][dispute.labTechnician] != bytes32(0)) &&
               (dispute.pharmacy == address(0) || evidenceHashes[_disputeId][dispute.pharmacy] != bytes32(0));
    }

    /// @notice Automatically resolves a dispute based on oracle response
    /// @param _disputeId ID of the dispute to resolve
    /// @param _resolutionReason Reason for the resolution
    function _autoResolveDispute(uint256 _disputeId, bytes32 _resolutionReason) internal {
        Dispute storage dispute = disputes[_disputeId];
        dispute.status = DisputeStatus.AutoResolved;
        dispute.resolutionReason = _resolutionReason;

        payments.refundPatient(dispute.patient, dispute.patientCost, dispute.paymentType, dispute.id);
        if (dispute.disputeType == DisputeType.PharmacyError) {
            _orderReplacement(dispute);
        }

        emit DisputeAutoResolved(_disputeId, _resolutionReason);
    }

    /// @notice Orders a replacement prescription for a pharmacy error
    /// @param _dispute Dispute struct containing details
    function _orderReplacement(Dispute storage _dispute) internal {
        bytes32 operationHash = keccak256(abi.encodePacked(
            "orderReplacementPrescription",
            _dispute.prescriptionId,
            address(this),
            block.timestamp
        ));
        medical.orderReplacementPrescription(_dispute.prescriptionId, operationHash);
        // Note: Multi-sig approval must be handled externally in TelemedicineMedicalCore
    }

    // Admin Configuration Functions with Timelock

    /// @notice Queues an update to the Chainlink oracle address
    /// @param _newOracle New Chainlink oracle address
    function queueUpdateChainlinkOracle(address _newOracle) external onlyRole(core.ADMIN_ROLE()) {
        require(_newOracle != address(0), "Invalid oracle address");
        bytes memory data = abi.encodeWithSignature("executeUpdateChainlinkOracle(address)", _newOracle);
        governance._queueTimeLock(TelemedicineGovernanceCore.TimeLockAction(5), address(this), 0, data);
    }

    /// @notice Executes an update to the Chainlink oracle address
    /// @param _newOracle New Chainlink oracle address
    function executeUpdateChainlinkOracle(address _newOracle) external onlyRole(core.ADMIN_ROLE()) {
        chainlinkOracle = _newOracle;
    }

    /// @notice Queues an update to the dispute submission period
    /// @param _newPeriod New dispute submission period in seconds
    function queueUpdateDisputeSubmissionPeriod(uint256 _newPeriod) external onlyRole(core.ADMIN_ROLE()) {
        require(_newPeriod >= 1 days, "Period too short");
        bytes memory data = abi.encodeWithSignature("executeUpdateDisputeSubmissionPeriod(uint256)", _newPeriod);
        governance._queueTimeLock(TelemedicineGovernanceCore.TimeLockAction(5), address(this), 0, data);
    }

    /// @notice Executes an update to the dispute submission period
    /// @param _newPeriod New dispute submission period in seconds
    function executeUpdateDisputeSubmissionPeriod(uint256 _newPeriod) external onlyRole(core.ADMIN_ROLE()) {
        disputeSubmissionPeriod = _newPeriod;
    }

    /// @notice Queues an update to the evidence submission period
    /// @param _newPeriod New evidence submission period in seconds
    function queueUpdateEvidenceSubmissionPeriod(uint256 _newPeriod) external onlyRole(core.ADMIN_ROLE()) {
        require(_newPeriod >= 12 hours, "Period too short");
        bytes memory data = abi.encodeWithSignature("executeUpdateEvidenceSubmissionPeriod(uint256)", _newPeriod);
        governance._queueTimeLock(TelemedicineGovernanceCore.TimeLockAction(5), address(this), 0, data);
    }

    /// @notice Executes an update to the evidence submission period
    /// @param _newPeriod New evidence submission period in seconds
    function executeUpdateEvidenceSubmissionPeriod(uint256 _newPeriod) external onlyRole(core.ADMIN_ROLE()) {
        evidenceSubmissionPeriod = _newPeriod;
    }

    /// @notice Queues an update to the oracle timeout period
    /// @param _newTimeout New oracle timeout period in seconds
    function queueUpdateOracleTimeout(uint256 _newTimeout) external onlyRole(core.ADMIN_ROLE()) {
        require(_newTimeout >= 6 hours, "Timeout too short");
        bytes memory data = abi.encodeWithSignature("executeUpdateOracleTimeout(uint256)", _newTimeout);
        governance._queueTimeLock(TelemedicineGovernanceCore.TimeLockAction(5), address(this), 0, data);
    }

    /// @notice Executes an update to the oracle timeout period
    /// @param _newTimeout New oracle timeout period in seconds
    function executeUpdateOracleTimeout(uint256 _newTimeout) external onlyRole(core.ADMIN_ROLE()) {
        oracleTimeout = _newTimeout;
    }

    // Utility Functions for Chainlink

    /// @notice Converts a uint256 to a string
    /// @param _i The uint256 value to convert
    /// @return The string representation of the uint256
    function uint2str(uint256 _i) internal pure returns (string memory) {
        if (_i == 0) return "0";
        uint256 j = _i;
        uint256 length;
        while (j != 0) {
            length++;
            j /= 10;
        }
        bytes memory bstr = new bytes(length);
        uint256 k = length;
        while (_i != 0) {
            k = k - 1;
            uint8 temp = uint8(48 + (_i % 10));
            bstr[k] = bytes1(temp);
            _i /= 10;
        }
        return string(bstr);
    }

    /// @notice Converts a bytes32 to a string
    /// @param _bytes32 The bytes32 value to convert
    /// @return The string representation of the bytes32
    function bytes32ToString(bytes32 _bytes32) internal pure returns (string memory) {
        bytes memory bytesArray = new bytes(32);
        for (uint256 i = 0; i < 32; i++) {
            bytesArray[i] = _bytes32[i];
        }
        return string(bytesArray);
    }

    // Modifiers

    /// @notice Restricts access to a specific role
    /// @param role The role required to call the function
    modifier onlyRole(bytes32 role) {
        require(core.hasRole(role, msg.sender), "Unauthorized");
        _;
    }

    /// @notice Ensures the contract is not paused
    modifier whenNotPaused() {
        require(!core.paused(), "Pausable: paused");
        _;
    }
}
