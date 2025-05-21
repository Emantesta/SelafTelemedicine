// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import {SafeMathUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";
import {IERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import {SafeERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import {TelemedicineCore} from "./TelemedicineCore.sol";
import {TelemedicinePayments} from "./TelemedicinePayments.sol";
import {TelemedicineDisputeResolution} from "./TelemedicineDisputeResolution.sol";
import {TelemedicineMedicalServices} from "./TelemedicineMedicalServices.sol";

/// @title TelemedicineMedicalCore
/// @notice Central contract for managing medical data and core logic for appointments, lab tests, prescriptions, and AI analyses
/// @dev UUPS upgradeable, integrates with TelemedicineCore, Payments, DisputeResolution, and MedicalServices
contract TelemedicineMedicalCore is Initializable, UUPSUpgradeable, ReentrancyGuardUpgradeable, PausableUpgradeable {
    using SafeMathUpgradeable for uint256;
    using SafeERC20Upgradeable for IERC20Upgradeable;

    // Dependencies
    TelemedicineCore public core;
    TelemedicinePayments public payments;
    TelemedicineDisputeResolution public disputeResolution;
    TelemedicineMedicalServices public services;

    // Configuration
    address public chainlinkOracle;
    bytes32 public priceListJobId;
    uint256 public chainlinkFee;
    bool public manualPriceOverride;
    uint256 public versionNumber;
    uint48 public invitationExpirationPeriod;
    uint256 public maxBatchSize;

    // Counters
    uint256 public appointmentCounter;
    uint256 public labTestCounter;
    uint256 public prescriptionCounter;
    uint256 public aiAnalysisCounter;

    // Data Structures
    struct Appointment {
        uint256 id;
        address patient;
        address[] doctors;
        uint48 scheduledTimestamp;
        AppointmentStatus status;
        uint96 fee;
        TelemedicinePayments.PaymentType paymentType;
        bool isVideoCall;
        bool isPriority;
        bytes32 videoCallLinkHash;
        uint48 disputeWindowEnd;
        TelemedicineCore.DisputeOutcome disputeOutcome;
    }

    struct LabTestOrder {
        uint256 id;
        address patient;
        address doctor;
        address labTech;
        LabTestStatus status;
        uint48 orderedTimestamp;
        uint48 completedTimestamp;
        string testTypeIpfsHash;
        string sampleCollectionIpfsHash;
        string resultsIpfsHash;
        uint256 patientCost;
        uint48 disputeWindowEnd;
        TelemedicineCore.DisputeOutcome disputeOutcome;
        uint48 sampleCollectionDeadline;
        uint48 resultsUploadDeadline;
        TelemedicinePayments.PaymentType paymentType;
    }

    struct Prescription {
        uint256 id;
        address patient;
        address doctor;
        bytes32 verificationCodeHash;
        PrescriptionStatus status;
        address pharmacy;
        uint48 generatedTimestamp;
        uint48 expirationTimestamp;
        string medicationIpfsHash;
        string prescriptionIpfsHash;
        uint256 patientCost;
        uint48 disputeWindowEnd;
        TelemedicineCore.DisputeOutcome disputeOutcome;
    }

    struct AISymptomAnalysis {
        uint256 id;
        address patient;
        bool doctorReviewed;
        string symptoms;
        string analysisIpfsHash;
    }

    struct PendingAppointments {
        uint256[] ids;
        mapping(uint256 => uint256) indices;
        uint256 count;
    }

    // New: Patient-to-Completed-Appointments Mapping
    struct CompletedAppointments {
        uint256[] ids;
        uint256 count;
    }

    // Enums
    enum AppointmentStatus { Pending, Confirmed, Completed, Cancelled, Rescheduled, Emergency, Disputed }
    enum LabTestStatus { Requested, PaymentPending, Collected, ResultsUploaded, Reviewed, Disputed, Expired }
    enum PrescriptionStatus { Generated, PaymentPending, Verified, Fulfilled, Revoked, Expired, Disputed }

    // Storage
    mapping(uint256 => Appointment) public appointments;
    mapping(uint256 => LabTestOrder) public labTestOrders;
    mapping(uint256 => Prescription) public prescriptions;
    mapping(uint256 => AISymptomAnalysis) public aiAnalyses;
    mapping(address => PendingAppointments) public doctorPendingAppointments;
    mapping(address => CompletedAppointments) public patientCompletedAppointments; // New: Tracks completed appointments per patient

    // Errors
    error NotAuthorized();
    error ContractPaused();
    error InvalidAddress();
    error InvalidParameter(string message);
    error InvalidIndex();
    error ExternalCallFailed();

    // Events
    event Initialized(address core, address payments, address disputeResolution, address services);
    event ChainlinkConfigUpdated(address oracle, bytes32 jobId, uint256 fee);
    event ManualPriceOverrideToggled(bool enabled);
    event ConfigurationUpdated(string parameter, uint256 value);
    event VersionUpgraded(uint256 newVersion);
    event ReplacementPrescriptionIssued(
        uint256 indexed newPrescriptionId, 
        uint256 indexed originalPrescriptionId, 
        bytes32 operationHash
    );
    event AppointmentCompleted(uint256 indexed appointmentId, address indexed patient); // New: Signals completed appointment

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the contract with external dependencies
    /// @param _core Address of TelemedicineCore
    /// @param _payments Address of TelemedicinePayments
    /// @param _disputeResolution Address of TelemedicineDisputeResolution
    /// @param _services Address of TelemedicineMedicalServices
    /// @param _chainlinkOracle Chainlink oracle address
    /// @param _priceListJobId Chainlink job ID
    /// @param _chainlinkFee Chainlink fee
    function initialize(
        address _core,
        address _payments,
        address _disputeResolution,
        address _services,
        address _chainlinkOracle,
        bytes32 _priceListJobId,
        uint256 _chainlinkFee
    ) external initializer {
        if (_core == address(0) || _payments == address(0) || _disputeResolution == address(0) || 
            _services == address(0) || _chainlinkOracle == address(0))
            revert InvalidAddress();

        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        __Pausable_init();

        core = TelemedicineCore(_core);
        payments = TelemedicinePayments(_payments);
        disputeResolution = TelemedicineDisputeResolution(_disputeResolution);
        services = TelemedicineMedicalServices(_services);
        chainlinkOracle = _chainlinkOracle;
        priceListJobId = _priceListJobId;
        chainlinkFee = _chainlinkFee;
        manualPriceOverride = false;
        invitationExpirationPeriod = 30 days;
        maxBatchSize = 50;
        versionNumber = 1;

        emit Initialized(_core, _payments, _disputeResolution, _services);
        emit ChainlinkConfigUpdated(_chainlinkOracle, _priceListJobId, _chainlinkFee);
        emit ConfigurationUpdated("invitationExpirationPeriod", 30 days);
        emit ConfigurationUpdated("maxBatchSize", 50);
    }

    /// @notice Authorizes contract upgrades (admin only)
    function _authorizeUpgrade(address newImplementation) internal override onlyRole(core.ADMIN_ROLE()) {
        versionNumber = versionNumber.add(1);
        emit VersionUpgraded(versionNumber);
    }

    /// @notice Orders a replacement prescription for a pharmacy dispute
    /// @param _originalPrescriptionId Original prescription ID
    /// @param _operationHash Operation hash for verification
    /// @param _newPharmacy Address of the new pharmacy
    /// @return New prescription ID
    function orderReplacementPrescription(
        uint256 _originalPrescriptionId, 
        bytes32 _operationHash, 
        address _newPharmacy
    ) 
        external 
        onlyAuthorizedContract 
        whenNotPaused 
        returns (uint256) 
    {
        if (_originalPrescriptionId == 0 || _originalPrescriptionId > prescriptionCounter) 
            revert InvalidIndex();

        Prescription storage original = prescriptions[_originalPrescriptionId];
        if (original.status != PrescriptionStatus.Disputed) 
            revert InvalidParameter("Original prescription must be in Disputed status");
        if (original.disputeOutcome != TelemedicineCore.DisputeOutcome.Unresolved) 
            revert InvalidParameter("Replacement already processed or dispute resolved");
        if (_newPharmacy == address(0)) 
            revert InvalidAddress("New pharmacy address cannot be zero");
        if (_newPharmacy == original.pharmacy) 
            revert InvalidParameter("New pharmacy cannot be the same as the original");

        try core.hasRole(core.PHARMACY_ROLE(), _newPharmacy) returns (bool hasRole) {
            if (!hasRole) revert InvalidParameter("New pharmacy is not authorized");
        } catch {
            revert ExternalCallFailed();
        }

        prescriptionCounter = prescriptionCounter.add(1);
        uint256 newPrescriptionId = prescriptionCounter;

        prescriptions[newPrescriptionId] = Prescription({
            id: newPrescriptionId,
            patient: original.patient,
            doctor: original.doctor,
            verificationCodeHash: bytes32(0),
            status: PrescriptionStatus.Generated,
            pharmacy: _newPharmacy,
            generatedTimestamp: uint48(block.timestamp),
            expirationTimestamp: uint48(block.timestamp.add(core.verificationTimeout())),
            medicationIpfsHash: original.medicationIpfsHash,
            prescriptionIpfsHash: original.prescriptionIpfsHash,
            patientCost: original.patientCost,
            disputeWindowEnd: uint48(block.timestamp.add(core.disputeWindow())),
            disputeOutcome: TelemedicineCore.DisputeOutcome.Unresolved
        });

        original.status = PrescriptionStatus.Revoked;
        original.disputeOutcome = TelemedicineCore.DisputeOutcome.ProviderFavored;

        emit ReplacementPrescriptionIssued(newPrescriptionId, _originalPrescriptionId, _operationHash);
        return newPrescriptionId;
    }

    /// @notice Updates appointment status and dispute outcome, records completed appointments
    /// @param _appointmentId Appointment ID
    /// @param _status New status
    /// @param _disputeOutcome Dispute outcome
    function updateAppointmentStatus(
        uint256 _appointmentId,
        AppointmentStatus _status,
        TelemedicineCore.DisputeOutcome _disputeOutcome
    ) external onlyAuthorizedContract {
        if (_appointmentId == 0 || _appointmentId > appointmentCounter) revert InvalidIndex();
        Appointment storage apt = appointments[_appointmentId];
        if (_status == AppointmentStatus.Completed && apt.status != AppointmentStatus.Completed) {
            CompletedAppointments storage completed = patientCompletedAppointments[apt.patient];
            completed.ids.push(_appointmentId);
            completed.count = completed.count.add(1);
            emit AppointmentCompleted(_appointmentId, apt.patient);
        }
        apt.status = _status;
        apt.disputeOutcome = _disputeOutcome;
    }

    /// @notice Retrieves completed appointment IDs for a patient
    /// @param _patient Patient address
    /// @return Array of completed appointment IDs
    function getPatientCompletedAppointments(address _patient) external view returns (uint256[] memory) {
        if (_patient == address(0)) revert InvalidAddress();
        return patientCompletedAppointments[_patient].ids;
    }

    /// @notice Updates Chainlink configuration
    /// @param _newOracle New oracle address
    /// @param _newJobId New job ID
    /// @param _newFee New fee
    function updateChainlinkConfig(address _newOracle, bytes32 _newJobId, uint256 _newFee) 
        external 
        onlyRole(core.ADMIN_ROLE()) 
    {
        if (_newOracle == address(0) || _newJobId == bytes32(0) || _newFee == 0) 
            revert InvalidParameter("Invalid Chainlink configuration parameters");
        chainlinkOracle = _newOracle;
        priceListJobId = _newJobId;
        chainlinkFee = _newFee;
        emit ChainlinkConfigUpdated(_newOracle, _newJobId, _newFee);
    }

    /// @notice Toggles manual price override
    /// @param _enabled Whether to enable manual pricing
    function toggleManualPriceOverride(bool _enabled) external onlyRole(core.ADMIN_ROLE()) {
        manualPriceOverride = _enabled;
        emit ManualPriceOverrideToggled(_enabled);
    }

    /// @notice Updates configuration parameters
    /// @param _parameter Parameter name
    /// @param _value New value
    function updateConfiguration(string calldata _parameter, uint256 _value) 
        external 
        onlyRole(core.ADMIN_ROLE()) 
    {
        bytes32 paramHash = keccak256(abi.encodePacked(_parameter));
        if (paramHash == keccak256(abi.encodePacked("invitationExpirationPeriod"))) {
            if (_value < 7 days) revert InvalidParameter("Expiration period too short");
            invitationExpirationPeriod = uint48(_value);
        } else if (paramHash == keccak256(abi.encodePacked("maxBatchSize"))) {
            if (_value == 0 || _value > 100) revert InvalidParameter("Invalid batch size");
            maxBatchSize = _value;
        } else {
            revert InvalidParameter("Unknown configuration parameter");
        }
        emit ConfigurationUpdated(_parameter, _value);
    }

    // View Functions for Data Access

    /// @notice Retrieves appointment details
    /// @param _appointmentId Appointment ID
    /// @return Appointment struct
    function getAppointment(uint256 _appointmentId) external view returns (Appointment memory) {
        if (_appointmentId == 0 || _appointmentId > appointmentCounter) revert InvalidIndex();
        return appointments[_appointmentId];
    }

    /// @notice Retrieves lab test order details
    /// @param _labTestId Lab test ID
    /// @return LabTestOrder struct
    function getLabTestOrder(uint256 _labTestId) external view returns (LabTestOrder memory) {
        if (_labTestId == 0 || _labTestId > labTestCounter) revert InvalidIndex();
        return labTestOrders[_labTestId];
    }

    /// @notice Retrieves prescription details
    /// @param _prescriptionId Prescription ID
    /// @return Prescription struct
    function getPrescription(uint256 _prescriptionId) external view returns (Prescription memory) {
        if (_prescriptionId == 0 || _prescriptionId > prescriptionCounter) revert InvalidIndex();
        return prescriptions[_prescriptionId];
    }

    /// @notice Retrieves AI symptom analysis details
    /// @param _analysisId Analysis ID
    /// @return AISymptomAnalysis struct
    function getAIAnalysis(uint256 _analysisId) external view returns (AISymptomAnalysis memory) {
        if (_analysisId == 0 || _analysisId > aiAnalysisCounter) revert InvalidIndex();
        return aiAnalyses[_analysisId];
    }

    /// @notice Retrieves pending appointments for a doctor
    /// @param _doctor Doctor address
    /// @return Array of pending appointment IDs
    function getDoctorPendingAppointments(address _doctor) external view returns (uint256[] memory) {
        if (_doctor == address(0)) revert InvalidAddress();
        return doctorPendingAppointments[_doctor].ids;
    }

    // State Modification Functions (Restricted)

    /// @notice Updates lab test order status and dispute outcome
    /// @param _labTestId Lab test ID
    /// @param _status New status
    /// @param _disputeOutcome Dispute outcome
    function updateLabTestStatus(
        uint256 _labTestId,
        LabTestStatus _status,
        TelemedicineCore.DisputeOutcome _disputeOutcome
    ) external onlyAuthorizedContract {
        if (_labTestId == 0 || _labTestId > labTestCounter) revert InvalidIndex();
        LabTestOrder storage order = labTestOrders[_labTestId];
        order.status = _status;
        order.disputeOutcome = _disputeOutcome;
    }

    /// @notice Updates prescription status and dispute outcome
    /// @param _prescriptionId Prescription ID
    /// @param _status New status
    /// @param _disputeOutcome Dispute outcome
    function updatePrescriptionStatus(
        uint256 _prescriptionId,
        PrescriptionStatus _status,
        TelemedicineCore.DisputeOutcome _disputeOutcome
    ) external onlyAuthorizedContract {
        if (_prescriptionId == 0 || _prescriptionId > prescriptionCounter) revert InvalidIndex();
        Prescription storage prescription = prescriptions[_prescriptionId];
        prescription.status = _status;
        prescription.disputeOutcome = _disputeOutcome;
    }

    // Internal Utility Functions

    /// @notice Checks if the caller is an authorized contract
    function _isAuthorizedContract() internal view returns (bool) {
        return msg.sender == address(core) ||
               msg.sender == address(payments) ||
               msg.sender == address(disputeResolution) ||
               msg.sender == address(services) ||
               core.hasRole(core.ADMIN_ROLE(), msg.sender);
    }

    // Modifiers

    /// @notice Restricts access to a specific role
    /// @param role The role required
    modifier onlyRole(bytes32 role) {
        try core.hasRole(role, msg.sender) returns (bool hasRole) {
            if (!hasRole) revert NotAuthorized();
            _;
        } catch {
            revert ExternalCallFailed();
        }
    }

    /// @notice Restricts access to authorized contracts
    modifier onlyAuthorizedContract() {
        if (!_isAuthorizedContract()) revert NotAuthorized();
        _;
    }

    /// @notice Ensures the contract is not paused
    modifier whenNotPaused() {
        try core.paused() returns (bool isPaused) {
            if (isPaused) revert ContractPaused();
            _;
        } catch {
            revert ExternalCallFailed();
        }
    }

    // Fallback
    receive() external payable {}

    // Storage gap for future upgrades
    uint256[50] private __gap;
}
