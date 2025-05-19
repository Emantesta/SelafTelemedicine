// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import {SafeMathUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {TelemedicineCore} from "./TelemedicineCore.sol";
import {TelemedicineGovernanceCore} from "./TelemedicineGovernanceCore.sol";
import {TelemedicinePayments} from "./TelemedicinePayments.sol";
import {TelemedicineMedicalCore} from "./TelemedicineMedicalCore.sol";
import {LinkTokenInterface} from "@chainlink/contracts/src/v0.8/interfaces/LinkTokenInterface.sol";
import {ChainlinkClient} from "@chainlink/contracts/src/v0.8/ChainlinkClient.sol";
import {ITelemedicinePayments} from "./Interfaces/ITelemedicinePayments.sol";

/// @title TelemedicineDisputeResolution
/// @notice Manages disputes with Chainlink oracle verification
/// @dev UUPS upgradeable, integrates with core, governance, payments, and medical contracts
contract TelemedicineDisputeResolution is Initializable, UUPSUpgradeable, ReentrancyGuardUpgradeable, PausableUpgradeable, ChainlinkClient {
    using SafeMathUpgradeable for uint256;
    using Chainlink for Chainlink.Request;
    using Strings for uint256;

    // Immutable Dependencies
    TelemedicineCore public immutable core;
    TelemedicineGovernanceCore public immutable governance;
    TelemedicinePayments public immutable payments;
    TelemedicineMedicalCore public immutable medical;

    // Chainlink Configuration
    address public chainlinkOracle;
    bytes32 public chainlinkJobId;
    uint256 public chainlinkFee;
    LinkTokenInterface public linkToken;

    // Configuration Variables
    uint256 public disputeSubmissionPeriod;
    uint256 public evidenceSubmissionPeriod;
    uint256 public oracleTimeout;

    // Counters
    uint256 public disputeCounter;
    uint256 public versionNumber; // New: Track contract version

    // Constants
    uint256 public constant MIN_PATIENT_COST = 0.01 * 10**6; // New: 0.01 USDC (6 decimals)
    uint256 public constant MIN_CHAINLINK_FEE = 0.05 * 10**18; // New: 0.05 LINK
    uint256 public constant MAX_DISPUTES = 1_000_000; // New: Limit disputes
    uint256 public constant MAX_RETRIES = 3; // New: Chainlink retry limit

    // Dispute Data
    mapping(uint256 => Dispute) private disputes; // Updated: Private
    mapping(uint256 => mapping(address => bytes32)) private evidenceHashes; // Updated: Private
    mapping(bytes32 => uint256) private chainlinkRequestToDisputeId; // Updated: Private
    mapping(uint256 => uint256) public prescriptionToDisputeIds; // New: Map prescription to dispute
    mapping(uint256 => uint256) public chainlinkRetryCounts; // New: Track retries

    // Structs
    struct Dispute {
        uint256 id;
        address patient;
        address doctor;
        address labTechnician;
        address pharmacy;
        DisputeType disputeType;
        uint256 prescriptionId;
        uint256 patientCost;
        ITelemedicinePayments.PaymentType paymentType; // Updated: Use interface
        DisputeStatus status;
        uint48 createdAt;
        uint48 evidenceDeadline;
        bytes32 resolutionReason;
        bool escalated;
    }

    struct Resolution {
        bytes32 reasonHash;
        bytes32 descriptionHash; // New: Additional context
    }

    // Enums
    enum DisputeType { Misdiagnosis, LabError, PharmacyError, PaymentIssue }
    enum DisputeStatus { Pending, EvidenceSubmitted, OracleRequested, AutoResolved, Escalated, Resolved, Cancelled }

    // Events
    event DisputeInitiated(
        uint256 indexed disputeId,
        bytes32 indexed patientHash, // Updated: Hashed address
        DisputeType disputeType,
        uint256 prescriptionId
    );
    event EvidenceSubmitted(uint256 indexed disputeId, bytes32 indexed submitterHash, bytes32 evidenceHash);
    event OracleRequestSent(uint256 indexed disputeId, bytes32 indexed requestId);
    event OracleRequestFailed(uint256 indexed disputeId, string reason);
    event DisputeAutoResolved(uint256 indexed disputeId, bytes32 resolutionReason);
    event DisputeEscalated(uint256 indexed disputeId, bytes32 indexed adminHash);
    event DisputeResolved(uint256 indexed disputeId, bytes32 resolutionReason);
    event DisputeCancelled(uint256 indexed disputeId, bytes32 indexed cancellerHash);
    event ReplacementOrdered(uint256 indexed disputeId, uint256 newPrescriptionId);
    event ConfigurationUpdated(string indexed parameter, uint256 value); // New: Unified config event
    event ChainlinkConfigUpdated(string indexed parameter, address value); // New: Chainlink config event

    // Errors
    error InvalidAddress();
    error InvalidDisputeStatus();
    error UnauthorizedSubmitter();
    error EvidencePeriodExpired();
    error InvalidEvidenceHash();
    error InsufficientLink();
    error OracleTimeout();
    error InvalidResolutionReason();
    error ExternalCallFailed();
    error CounterOverflow();
    error InvalidPrescription();
    error DisputeWindowExpired();
    error InvalidParty();
    error InvalidConfiguration();
    error MaxRetriesExceeded();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the contract
    /// @param _core Core contract address
    /// @param _governance Governance contract address
    /// @param _payments Payments contract address
    /// @param _medical Medical contract address
    /// @param _chainlinkOracle Chainlink oracle address
    /// @param _chainlinkJobId Chainlink job ID
    /// @param _linkToken LINK token address
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
            _chainlinkOracle == address(0) || _linkToken == address(0)) revert InvalidAddress();
        // Updated: Validate contracts
        if (!_isContract(_chainlinkOracle) || !_isContract(_linkToken)) revert InvalidAddress();

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
        chainlinkFee = 0.1 * 10**18; // 0.1 LINK
        versionNumber = 1;
    }

    /// @notice Returns the contract version
    /// @return Version number
    function version() external view returns (uint256) {
        return versionNumber;
    }

    /// @notice Authorizes an upgrade
    /// @param newImplementation New implementation address
    function _authorizeUpgrade(address newImplementation) internal override onlyConfigAdmin {
        if (!_isContract(newImplementation)) revert InvalidAddress();
        versionNumber++;
    }

    /// @notice Initiates a dispute
    /// @param _doctor Doctor address
    /// @param _labTechnician Lab technician address
    /// @param _pharmacy Pharmacy address
    /// @param _disputeType Dispute type
    /// @param _prescriptionId Prescription ID
    function initiateDispute(
        address _doctor,
        address _labTechnician,
        address _pharmacy,
        DisputeType _disputeType,
        uint256 _prescriptionId
    ) external onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
        // Updated: Validate parties
        bool validParty;
        if (_doctor != address(0)) {
            try core.hasRole(core.DOCTOR_ROLE(), _doctor) returns (bool hasRole) {
                validParty = validParty || hasRole;
            } catch {
                revert ExternalCallFailed();
            }
        }
        if (_labTechnician != address(0)) {
            try core.hasRole(core.LAB_TECH_ROLE(), _labTechnician) returns (bool hasRole) {
                validParty = validParty || hasRole;
            } catch {
                revert ExternalCallFailed();
            }
        }
        if (_pharmacy != address(0)) {
            try core.hasRole(core.PHARMACY_ROLE(), _pharmacy) returns (bool hasRole) {
                validParty = validParty || hasRole;
            } catch {
                revert ExternalCallFailed();
            }
        }
        if (!validParty) revert InvalidParty();

        // Updated: Fetch prescription with try-catch
        TelemedicineMedicalCore.Prescription memory prescription;
        try medical.prescriptions(_prescriptionId) returns (TelemedicineMedicalCore.Prescription memory p) {
            prescription = p;
        } catch {
            revert ExternalCallFailed();
        }
        if (_prescriptionId == 0 || prescription.patient != msg.sender) revert InvalidPrescription();
        if (prescription.patientCost < MIN_PATIENT_COST) revert InvalidPrescription();
        if (block.timestamp > prescription.disputeWindowEnd) revert DisputeWindowExpired();
        if (prescriptionToDisputeIds[_prescriptionId] != 0) revert InvalidPrescription();

        if (disputeCounter >= MAX_DISPUTES) revert CounterOverflow();
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
        prescriptionToDisputeIds[_prescriptionId] = disputeId;

        emit DisputeInitiated(disputeId, keccak256(abi.encode(msg.sender)), _disputeType, _prescriptionId);
    }

    /// @notice Submits evidence for multiple disputes
    /// @param _disputeIds Dispute IDs
    /// @param _evidenceHashes IPFS evidence hashes
    function batchSubmitEvidence(uint256[] calldata _disputeIds, bytes32[] calldata _evidenceHashes) 
        external 
        nonReentrant 
        whenNotPaused 
    {
        if (_disputeIds.length != _evidenceHashes.length || _disputeIds.length > 100) revert InvalidInput();
        for (uint256 i = 0; i < _disputeIds.length; i++) {
            if (_evidenceHashes[i] == bytes32(0)) revert InvalidEvidenceHash();
            Dispute storage dispute = disputes[_disputeIds[i]];
            if (dispute.status != DisputeStatus.Pending) revert InvalidDisputeStatus();
            if (block.timestamp > dispute.evidenceDeadline) revert EvidencePeriodExpired();

            bool isValidParty;
            try core.hasRole(core.PATIENT_ROLE(), msg.sender) returns (bool isPatient) {
                isValidParty = isValidParty || (isPatient && msg.sender == dispute.patient);
            } catch {
                revert ExternalCallFailed();
            }
            try core.hasRole(core.DOCTOR_ROLE(), msg.sender) returns (bool isDoctor) {
                isValidParty = isValidParty || (isDoctor && msg.sender == dispute.doctor);
            } catch {
                revert ExternalCallFailed();
            }
            try core.hasRole(core.LAB_TECH_ROLE(), msg.sender) returns (bool isLabTech) {
                isValidParty = isValidParty || (isLabTech && msg.sender == dispute.labTechnician);
            } catch {
                revert ExternalCallFailed();
            }
            try core.hasRole(core.PHARMACY_ROLE(), msg.sender) returns (bool isPharmacy) {
                isValidParty = isValidParty || (isPharmacy && msg.sender == dispute.pharmacy);
            } catch {
                revert ExternalCallFailed();
            }
            if (!isValidParty) revert UnauthorizedSubmitter();

            evidenceHashes[_disputeIds[i]][msg.sender] = _evidenceHashes[i];
            emit EvidenceSubmitted(_disputeIds[i], keccak256(abi.encode(msg.sender)), _evidenceHashes[i]);

            if (_allEvidenceSubmitted(_disputeIds[i])) {
                dispute.status = DisputeStatus.EvidenceSubmitted;
                _requestOracleVerification(_disputeIds[i]);
            }
        }
    }

    /// @notice Requests Chainlink oracle verification
    /// @param _disputeId Dispute ID
    function _requestOracleVerification(uint256 _disputeId) internal {
        Dispute storage dispute = disputes[_disputeId];
        if (dispute.status != DisputeStatus.EvidenceSubmitted) revert InvalidDisputeStatus();

        if (linkToken.balanceOf(address(this)) < chainlinkFee) {
            dispute.status = DisputeStatus.Escalated;
            dispute.escalated = true;
            emit OracleRequestFailed(_disputeId, "Insufficient LINK");
            emit DisputeEscalated(_disputeId, bytes32(0));
            return;
        }

        Chainlink.Request memory request = buildChainlinkRequest(chainlinkJobId, address(this), this.fulfillOracleResponse.selector);
        request.add("disputeId", _disputeId.toString());
        request.add("prescriptionHash", bytes32ToString(medical.prescriptions(dispute.prescriptionId).prescriptionIpfsHash));
        request.add("patientEvidenceHash", bytes32ToString(evidenceHashes[_disputeId][dispute.patient]));
        request.addString("endpoint", "verifyEvidence");

        bytes32 requestId;
        try this.sendChainlinkRequestTo(chainlinkOracle, request, chainlinkFee) returns (bytes32 id) {
            requestId = id;
        } catch {
            chainlinkRetryCounts[_disputeId] = chainlinkRetryCounts[_disputeId].add(1);
            if (chainlinkRetryCounts[_disputeId] >= MAX_RETRIES) {
                dispute.status = DisputeStatus.Escalated;
                dispute.escalated = true;
                emit OracleRequestFailed(_disputeId, "Max retries exceeded");
                emit DisputeEscalated(_disputeId, bytes32(0));
                return;
            }
            _requestOracleVerification(_disputeId); // Retry
            return;
        }

        chainlinkRequestToDisputeId[requestId] = _disputeId;
        dispute.status = DisputeStatus.OracleRequested;
        emit OracleRequestSent(_disputeId, requestId);
    }

    /// @notice Handles Chainlink oracle response
    /// @param _requestId Chainlink request ID
    /// @param _isMismatch Evidence mismatch flag
    /// @param _evidenceResultHash Result hash
    function fulfillOracleResponse(bytes32 _requestId, bool _isMismatch, bytes32 _evidenceResultHash) 
        external 
        recordChainlinkFulfillment(_requestId) 
    {
        uint256 disputeId = chainlinkRequestToDisputeId[_requestId];
        Dispute storage dispute = disputes[disputeId];
        if (dispute.status != DisputeStatus.OracleRequested) revert InvalidDisputeStatus();
        if (block.timestamp > dispute.evidenceDeadline.add(oracleTimeout)) revert OracleTimeout();

        if (_isMismatch && dispute.disputeType == DisputeType.PharmacyError) {
            _autoResolveDispute(disputeId, _evidenceResultHash);
        } else {
            dispute.status = DisputeStatus.Escalated;
            dispute.escalated = true;
            emit DisputeEscalated(disputeId, bytes32(0));
        }
    }

    /// @notice Queues dispute resolution
    /// @param _disputeId Dispute ID
    /// @param _patientWins Patient win flag
    /// @param _resolutionReason Resolution reason hash
    function queueResolveDispute(uint256 _disputeId, bool _patientWins, bytes32 _resolutionReason) 
        external 
        onlyGovernanceApprover 
        nonReentrant 
        whenNotPaused 
    {
        Dispute storage dispute = disputes[_disputeId];
        if (dispute.status != DisputeStatus.Escalated) revert InvalidDisputeStatus();
        if (_resolutionReason == bytes32(0)) revert InvalidResolutionReason();

        bytes memory data = abi.encodeWithSignature("executeResolveDispute(uint256,bool,bytes32)", _disputeId, _patientWins, _resolutionReason);
        try governance._queueTimeLock(
            TelemedicineGovernanceCore.TimeLockAction.DisputeResolution, // Updated: Dynamic enum
            address(this),
            0,
            data
        ) {} catch {
            revert ExternalCallFailed();
        }
    }

    /// @notice Executes dispute resolution
    /// @param _disputeId Dispute ID
    /// @param _patientWins Patient win flag
    /// @param _resolutionReason Resolution reason hash
    function executeResolveDispute(uint256 _disputeId, bool _patientWins, bytes32 _resolutionReason) 
        external 
        onlyGovernanceApprover 
        nonReentrant 
        whenNotPaused 
    {
        Dispute storage dispute = disputes[_disputeId];
        if (dispute.status != DisputeStatus.Escalated) revert InvalidDisputeStatus();

        dispute.status = DisputeStatus.Resolved;
        dispute.resolutionReason = _resolutionReason;

        if (_patientWins) {
            try payments.refundPatient(dispute.patient, dispute.patientCost, dispute.paymentType, dispute.id) {} catch {
                revert ExternalCallFailed();
            }
            if (dispute.disputeType == DisputeType.PharmacyError) {
                _orderReplacement(dispute);
            }
        }

        emit DisputeResolved(_disputeId, _resolutionReason);
    }

    /// @notice Cancels a dispute
    /// @param _disputeId Dispute ID
    function cancelDispute(uint256 _disputeId) external nonReentrant whenNotPaused {
        Dispute storage dispute = disputes[_disputeId];
        if (dispute.status != DisputeStatus.Pending && dispute.status != DisputeStatus.EvidenceSubmitted) revert InvalidDisputeStatus();

        bool isAuthorized;
        try core.hasRole(core.ADMIN_ROLE(), msg.sender) returns (bool isAdmin) {
            isAuthorized = isAdmin || msg.sender == dispute.patient;
        } catch {
            revert ExternalCallFailed();
        }
        if (!isAuthorized) revert NotAuthorized();

        dispute.status = DisputeStatus.Cancelled;
        emit DisputeCancelled(_disputeId, keccak256(abi.encode(msg.sender)));
    }

    /// @notice Checks if a prescription is disputed
    /// @param _id Prescription ID
    /// @return True if disputed
    function isDisputed(uint256 _id) external view returns (bool) {
        uint256 disputeId = prescriptionToDisputeIds[_id];
        if (disputeId == 0) return false;
        Dispute storage dispute = disputes[disputeId];
        return dispute.status == DisputeStatus.Pending ||
               dispute.status == DisputeStatus.EvidenceSubmitted ||
               dispute.status == DisputeStatus.OracleRequested ||
               dispute.status == DisputeStatus.Escalated;
    }

    /// @notice Gets dispute outcome
    /// @param _id Prescription ID
    /// @return Dispute outcome
    function getDisputeOutcome(uint256 _id) external view returns (TelemedicineMedicalCore.DisputeOutcome) {
        uint256 disputeId = prescriptionToDisputeIds[_id];
        if (disputeId == 0) return TelemedicineMedicalCore.DisputeOutcome.Unresolved;
        Dispute storage dispute = disputes[disputeId];
        if (dispute.status == DisputeStatus.Resolved || dispute.status == DisputeStatus.AutoResolved) {
            return dispute.resolutionReason != bytes32(0) ? 
                   TelemedicineMedicalCore.DisputeOutcome.PatientFavored : 
                   TelemedicineMedicalCore.DisputeOutcome.ProviderFavored;
        } else if (dispute.status == DisputeStatus.Cancelled) {
            return TelemedicineMedicalCore.DisputeOutcome.MutualAgreement;
        }
        return TelemedicineMedicalCore.DisputeOutcome.Unresolved;
    }

    // Internal Functions

    /// @notice Checks if all evidence is submitted
    /// @param _disputeId Dispute ID
    /// @return True if complete
    function _allEvidenceSubmitted(uint256 _disputeId) internal view returns (bool) {
        Dispute storage dispute = disputes[_disputeId];
        return (dispute.patient != address(0) && evidenceHashes[_disputeId][dispute.patient] != bytes32(0)) &&
               (dispute.doctor == address(0) || evidenceHashes[_disputeId][dispute.doctor] != bytes32(0)) &&
               (dispute.labTechnician == address(0) || evidenceHashes[_disputeId][dispute.labTechnician] != bytes32(0)) &&
               (dispute.pharmacy == address(0) || evidenceHashes[_disputeId][dispute.pharmacy] != bytes32(0));
    }

    /// @notice Auto-resolves a dispute
    /// @param _disputeId Dispute ID
    /// @param _resolutionReason Resolution reason hash
    function _autoResolveDispute(uint256 _disputeId, bytes32 _resolutionReason) internal {
        Dispute storage dispute = disputes[_disputeId];
        dispute.status = DisputeStatus.AutoResolved;
        dispute.resolutionReason = _resolutionReason;

        try payments.refundPatient(dispute.patient, dispute.patientCost, dispute.paymentType, dispute.id) {} catch {
            revert ExternalCallFailed();
        }
        if (dispute.disputeType == DisputeType.PharmacyError) {
            _orderReplacement(dispute);
        }

        emit DisputeAutoResolved(_disputeId, _resolutionReason);
    }

    /// @notice Orders a replacement prescription
    /// @param _dispute Dispute struct
    function _orderReplacement(Dispute storage _dispute) internal {
        bytes32 operationHash = keccak256(abi.encodePacked(
            "orderReplacementPrescription",
            _dispute.prescriptionId,
            address(this),
            block.timestamp
        ));
        try medical.orderReplacementPrescription(_dispute.prescriptionId, operationHash) {} catch {
            revert ExternalCallFailed();
        }
        emit ReplacementOrdered(_dispute.id, _dispute.prescriptionId);
    }

    /// @notice Converts bytes32 to string
    /// @param _bytes32 Bytes32 value
    /// @return String representation
    function bytes32ToString(bytes32 _bytes32) internal pure returns (string memory) {
        bytes memory chars = "0123456789abcdef";
        bytes memory result = new bytes(64);
        for (uint256 i = 0; i < 32; i++) {
            result[i*2] = chars[uint8(_bytes32[i] >> 4)];
            result[i*2+1] = chars[uint8(_bytes32[i] & 0x0f)];
        }
        return string(result);
    }

    // Admin Configuration Functions

    /// @notice Updates configuration parameters
    /// @param _parameter Parameter name
    /// @param _value New value
    function updateConfiguration(string memory _parameter, uint256 _value) external onlyConfigAdmin {
        bytes32 paramHash = keccak256(abi.encodePacked(_parameter));
        bytes memory data;

        if (paramHash == keccak256(abi.encodePacked("disputeSubmissionPeriod"))) {
            if (_value < 1 days) revert InvalidConfiguration();
            data = abi.encodeWithSignature("executeUpdateDisputeSubmissionPeriod(uint256)", _value);
        } else if (paramHash == keccak256(abi.encodePacked("evidenceSubmissionPeriod"))) {
            if (_value < 12 hours) revert InvalidConfiguration();
            data = abi.encodeWithSignature("executeUpdateEvidenceSubmissionPeriod(uint256)", _value);
        } else if (paramHash == keccak256(abi.encodePacked("oracleTimeout"))) {
            if (_value < 6 hours) revert InvalidConfiguration();
            data = abi.encodeWithSignature("executeUpdateOracleTimeout(uint256)", _value);
        } else if (paramHash == keccak256(abi.encodePacked("chainlinkFee"))) {
            if (_value < MIN_CHAINLINK_FEE) revert InvalidConfiguration();
            data = abi.encodeWithSignature("executeUpdateChainlinkFee(uint256)", _value);
        } else {
            revert InvalidConfiguration();
        }

        try governance._queueTimeLock(
            TelemedicineGovernanceCore.TimeLockAction.ConfigurationUpdate,
            address(this),
            0,
            data
        ) {} catch {
            revert ExternalCallFailed();
        }
    }

    /// @notice Updates Chainlink configuration
    /// @param _parameter Parameter name
    /// @param _value New address
    function updateChainlinkConfiguration(string memory _parameter, address _value) external onlyConfigAdmin {
        if (_value == address(0) || !_isContract(_value)) revert InvalidAddress();
        bytes memory data;

        bytes32 paramHash = keccak256(abi.encodePacked(_parameter));
        if (paramHash == keccak256(abi.encodePacked("chainlinkOracle"))) {
            data = abi.encodeWithSignature("executeUpdateChainlinkOracle(address)", _value);
        } else if (paramHash == keccak256(abi.encodePacked("linkToken"))) {
            data = abi.encodeWithSignature("executeUpdateLinkToken(address)", _value);
        } else {
            revert InvalidConfiguration();
        }

        try governance._queueTimeLock(
            TelemedicineGovernanceCore.TimeLockAction.ConfigurationUpdate,
            address(this),
            0,
            data
        ) {} catch {
            revert ExternalCallFailed();
        }
    }

    /// @notice Executes Chainlink oracle update
    /// @param _newOracle New oracle address
    function executeUpdateChainlinkOracle(address _newOracle) external onlyConfigAdmin {
        chainlinkOracle = _newOracle;
        emit ChainlinkConfigUpdated("chainlinkOracle", _newOracle);
    }

    /// @notice Executes LINK token update
    /// @param _newToken New LINK token address
    function executeUpdateLinkToken(address _newToken) external onlyConfigAdmin {
        linkToken = LinkTokenInterface(_newToken);
        setChainlinkToken(_newToken);
        emit ChainlinkConfigUpdated("linkToken", _newToken);
    }

    /// @notice Executes dispute submission period update
    /// @param _newPeriod New period
    function executeUpdateDisputeSubmissionPeriod(uint256 _newPeriod) external onlyConfigAdmin {
        disputeSubmissionPeriod = _newPeriod;
        emit ConfigurationUpdated("disputeSubmissionPeriod", _newPeriod);
    }

    /// @notice Executes evidence submission period update
    /// @param _newPeriod New period
    function executeUpdateEvidenceSubmissionPeriod(uint256 _newPeriod) external onlyConfigAdmin {
        evidenceSubmissionPeriod = _newPeriod;
        emit ConfigurationUpdated("evidenceSubmissionPeriod", _newPeriod);
    }

    /// @notice Executes oracle timeout update
    /// @param _newTimeout New timeout
    function executeUpdateOracleTimeout(uint256 _newTimeout) external onlyConfigAdmin {
        oracleTimeout = _newTimeout;
        emit ConfigurationUpdated("oracleTimeout", _newTimeout);
    }

    /// @notice Executes Chainlink fee update
    /// @param _newFee New fee
    function executeUpdateChainlinkFee(uint256 _newFee) external onlyConfigAdmin {
        chainlinkFee = _newFee;
        emit ConfigurationUpdated("chainlinkFee", _newFee);
    }

    // View Functions

    /// @notice Gets dispute details
    /// @param _disputeId Dispute ID
    /// @return Dispute struct
    function getDispute(uint256 _disputeId) external view onlyRole(core.ADMIN_ROLE()) returns (Dispute memory) {
        return disputes[_disputeId];
    }

    /// @notice Gets evidence hash
    /// @param _disputeId Dispute ID
    /// @param _party Party address
    /// @return Evidence hash
    function getEvidenceHash(uint256 _disputeId, address _party) external view onlyRole(core.ADMIN_ROLE()) returns (bytes32) {
        return evidenceHashes[_disputeId][_party];
    }

    /// @notice Gets Chainlink request dispute ID
    /// @param _requestId Request ID
    /// @return Dispute ID
    function getChainlinkRequestDisputeId(bytes32 _requestId) external view onlyRole(core.ADMIN_ROLE()) returns (uint256) {
        return chainlinkRequestToDisputeId[_requestId];
    }

    // Utility Functions

    /// @notice Checks if an address is a contract
    /// @param addr Address to check
    /// @return True if contract
    function _isContract(address addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }

    // Modifiers

    modifier onlyRole(bytes32 role) {
        try core.hasRole(role, msg.sender) returns (bool hasRole) {
            if (!hasRole) revert NotAuthorized();
            _;
        } catch {
            revert ExternalCallFailed();
        }
    }

    modifier onlyConfigAdmin() {
        try core.isConfigAdmin(msg.sender) returns (bool isAdmin) {
            if (!isAdmin) revert NotAuthorized();
            _;
        } catch {
            revert ExternalCallFailed();
        }
    }

    modifier onlyGovernanceApprover() {
        try core.isGovernanceApprover(msg.sender) returns (bool isApprover) {
            if (!isApprover) revert NotAuthorized();
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

    // Errors for new functionality
    error NotAuthorized();
    error ContractPaused();
    error InvalidInput();

    // Fallback
    receive() external payable {}

    // New: Storage gap
    uint256[50] private __gap;
}
