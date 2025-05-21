// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import {SafeMathUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";
import {SafeERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import {TelemedicineCore} from "./TelemedicineCore.sol";
import {TelemedicinePayments} from "./TelemedicinePayments.sol";
import {TelemedicineDisputeResolution} from "./TelemedicineDisputeResolution.sol";
import {TelemedicineBase} from "./TelemedicineBase.sol";
import {TelemedicinePaymentOperations} from "./TelemedicinePaymentOperations.sol";
import {TelemedicineMedicalCore} from "./TelemedicineMedicalCore.sol";

/// @title TelemedicineClinicalOperations
/// @notice Manages lab tests, prescriptions, and AI symptom analysis for a telemedicine platform
/// @dev Upgradeable, integrates with core, payments, dispute resolution, base, payment operations, and medical core
contract TelemedicineClinicalOperations is Initializable, ReentrancyGuardUpgradeable, PausableUpgradeable {
    using SafeMathUpgradeable for uint256;
    using SafeERC20Upgradeable for IERC20Upgradeable;

    // Immutable Dependencies
    TelemedicineCore public immutable core;
    TelemedicinePayments public immutable payments;
    TelemedicineDisputeResolution public immutable disputeResolution;
    TelemedicineBase public immutable base;
    TelemedicinePaymentOperations public immutable paymentOps;
    TelemedicineMedicalCore public immutable medicalCore;

    // Private State Variables
    mapping(uint256 => LabTestOrder) private labTestOrders;
    mapping(uint256 => Prescription) private prescriptions;
    mapping(uint256 => AISymptomAnalysis) private aiAnalyses;
    uint256 private labTestCounter;
    uint256 private prescriptionCounter;
    uint256 private aiAnalysisCounter;

    // Constants
    uint256 public constant MAX_COUNTER = 1_000_000;
    uint256 public constant MAX_STRING_LENGTH = 256;
    uint64 public constant MIN_SAMPLE_DEADLINE = 1 hours;
    uint64 public constant MIN_RESULTS_DEADLINE = 1 days;
    uint64 public constant MAX_DISPUTE_WINDOW = 7 days;
    uint64 public constant REVIEW_DEADLINE = 15 minutes;
    bytes32 private immutable SALT;

    // Enums
    enum LabTestStatus { Requested, PaymentPending, Collected, ResultsUploaded, Reviewed, Disputed, Expired }
    enum PrescriptionStatus { Generated, PaymentPending, Verified, Fulfilled, Revoked, Expired, Disputed }
    enum DisputeOutcome { Unresolved, PatientFavored, ProviderFavored, MutualAgreement }
    enum AISymptomAnalysisStatus { Pending, Reviewed, Expired }

    // Structs
    struct LabTestOrder {
        uint32 id;
        address patient;
        address doctor;
        address labTech;
        LabTestStatus status;
        uint64 orderedTimestamp;
        uint64 completedTimestamp;
        bytes32 testTypeHash;
        bytes32 sampleCollectionHash;
        bytes32 resultsHash;
        uint256 patientCost;
        uint64 disputeWindowEnd;
        DisputeOutcome disputeOutcome;
        uint64 sampleCollectionDeadline;
        uint64 resultsUploadDeadline;
        TelemedicinePayments.PaymentType paymentType;
    }

    struct Prescription {
        uint32 id;
        address patient;
        address doctor;
        bytes32 verificationCodeHash;
        PrescriptionStatus status;
        address pharmacy;
        uint64 generatedTimestamp;
        uint64 expirationTimestamp;
        bytes32 medicationHash;
        bytes32 prescriptionHash;
        uint256 patientCost;
        uint64 disputeWindowEnd;
        DisputeOutcome disputeOutcome;
    }

    struct AISymptomAnalysis {
        uint32 id;
        address patient;
        bool doctorReviewed;
        AISymptomAnalysisStatus status;
        bytes32 symptomsHash;
        bytes32 analysisHash;
        uint64 reviewDeadline;
        uint96 pointsEarned;
    }

    // Custom Errors
    error InvalidAddress();
    error NotAuthorized();
    error ContractPaused();
    error InvalidStatus();
    error InvalidTimestamp();
    error InsufficientFunds();
    error InvalidId();
    error InvalidParameter();
    error MultiSigNotApproved();
    error DeadlineMissed();
    error NoLabTechAvailable();
    error PaymentNotConfirmed();
    error ExternalCallFailed();
    error InvalidCounter();
    error InvalidDeadline();
    error InvalidOutcome();
    error InvalidPaymentStatus();
    error AnalysisNotReviewed();
    error NoRecentAppointment();

    // Events
    event LabTestOrdered(uint32 indexed testId, bytes32 indexed patientHash, bytes32 indexed doctorHash, bytes32 testTypeHash, uint64 orderedAt);
    event LabTestCollected(uint32 indexed testId, bytes32 ipfsHash);
    event LabTestUploaded(uint32 indexed testId, bytes32 ipfsHash);
    event LabTestReviewed(uint32 indexed testId);
    event LabTestReordered(uint32 indexed originalTestId, uint32 indexed newTestId, bytes32 newLabTechHash, bytes32 patientHash);
    event PrescriptionIssued(uint32 indexed prescriptionId, bytes32 indexed patientHash, bytes32 indexed doctorHash, bytes32 verificationCodeHash, uint64 issuedAt);
    event PrescriptionVerified(uint32 indexed prescriptionId, bytes32 pharmacyHash);
    event PrescriptionFulfilled(uint32 indexed prescriptionId);
    event PrescriptionExpired(uint32 indexed prescriptionId);
    event AISymptomAnalyzed(uint32 indexed id, bytes32 indexed patientHash);
    event AISymptomAnalysisReviewed(uint32 indexed id, bytes32 indexed patientHash, bytes32 analysisHash);
    event AISymptomAnalysisExpired(uint32 indexed id, bytes32 indexed patientHash, uint96 pointsRefunded);
    event PrescriptionDetailsSet(uint32 indexed prescriptionId, bytes32 prescriptionHash);
    event LabTestDisputeWindowStarted(uint32 indexed testId, bytes32 patientHash, uint64 disputeWindowEnd);
    event PrescriptionDisputeWindowStarted(uint32 indexed prescriptionId, bytes32 patientHash, uint64 disputeWindowEnd);
    event ReplacementPrescriptionOrdered(uint32 indexed originalPrescriptionId, uint32 indexed newPrescriptionId);
    event DisputeOutcomeUpdated(uint32 indexed id, DisputeOutcome outcome);
    event LabTestRefunded(uint32 indexed testId, address patient, uint256 amount);
    event LabTestPaymentConfirmed(uint32 indexed testId, uint256 amount);
    event PrescriptionPaymentConfirmed(uint32 indexed prescriptionId, uint256 amount);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
        SALT = keccak256(abi.encode(block.chainid, address(this)));
    }

    /// @notice Initializes the contract with dependencies
    /// @param _core Core contract address
    /// @param _payments Payments contract address
    /// @param _disputeResolution Dispute resolution contract address
    /// @param _base Base contract address
    /// @param _paymentOps Payment operations contract address
    /// @param _medicalCore Medical core contract address
    function initialize(
        address _core,
        address _payments,
        address _disputeResolution,
        address _base,
        address _paymentOps,
        address _medicalCore
    ) external initializer {
        if (_core == address(0) || _payments == address(0) || _disputeResolution == address(0) ||
            _base == address(0) || _paymentOps == address(0) || _medicalCore == address(0)) revert InvalidAddress();
        if (!_isContract(_core) || !_isContract(_payments) || !_isContract(_disputeResolution) ||
            !_isContract(_base) || !_isContract(_paymentOps) || !_isContract(_medicalCore)) revert InvalidAddress();

        __ReentrancyGuard_init();
        __Pausable_init();

        core = TelemedicineCore(_core);
        payments = TelemedicinePayments(_payments);
        disputeResolution = TelemedicineDisputeResolution(_disputeResolution);
        base = TelemedicineBase(_base);
        paymentOps = TelemedicinePaymentOperations(_paymentOps);
        medicalCore = TelemedicineMedicalCore(_medicalCore);
    }

    // Lab Test Management

    /// @notice Orders a lab test for a patient
    /// @param _patient Patient address
    /// @param _testTypeIpfsHash IPFS hash of test type
    /// @param _locality Locality for lab tech selection
    function orderLabTest(address _patient, string calldata _testTypeIpfsHash, string calldata _locality)
        external payable onlyRole(core.DOCTOR_ROLE()) nonReentrant whenNotPaused {
        if (_patient == address(0)) revert InvalidAddress();
        if (bytes(_testTypeIpfsHash).length > MAX_STRING_LENGTH || bytes(_locality).length > MAX_STRING_LENGTH) revert InvalidParameter();
        if (labTestCounter >= MAX_COUNTER) revert InvalidCounter();

        TelemedicineCore.Patient memory patient = core.patients(_patient);
        if (!patient.isRegistered) revert NotAuthorized();

        address selectedLabTech = paymentOps.selectBestLabTech(_testTypeIpfsHash, _locality);
        if (selectedLabTech == address(0)) revert NoLabTechAvailable();

        (uint256 price, bool isValid, uint48 sampleDeadline, uint48 resultsDeadline) = paymentOps.getLabTestDetails(selectedLabTech, _testTypeIpfsHash);
        if (sampleDeadline < MIN_SAMPLE_DEADLINE || resultsDeadline < MIN_RESULTS_DEADLINE) revert InvalidDeadline();

        unchecked { labTestCounter++; }
        uint32 newTestId = uint32(labTestCounter);
        LabTestOrder storage order = labTestOrders[newTestId];
        order.id = newTestId;
        order.patient = _patient;
        order.doctor = msg.sender;
        order.labTech = selectedLabTech;
        order.status = LabTestStatus.Requested;
        order.orderedTimestamp = uint64(block.timestamp);
        order.testTypeHash = keccak256(abi.encode(_testTypeIpfsHash));
        order.sampleCollectionDeadline = uint64(sampleDeadline);
        order.resultsUploadDeadline = uint64(resultsDeadline);
        order.paymentType = TelemedicinePayments.PaymentType.ETH;

        if (!isValid || price == 0) {
            paymentOps.requestLabTestPrice(selectedLabTech, _testTypeIpfsHash, newTestId);
        } else {
            uint256 percentageDenominator = base.PERCENTAGE_DENOMINATOR();
            order.patientCost = price.mul(120).div(percentageDenominator);
            if (msg.value < order.patientCost) revert InsufficientFunds();
            paymentOps.setLabTestPayment(newTestId, true);
            if (msg.value > order.patientCost) {
                _safeRefund(msg.sender, msg.value.sub(order.patientCost));
            }
        }

        emit LabTestOrdered(newTestId, keccak256(abi.encode(_patient)), keccak256(abi.encode(msg.sender)), order.testTypeHash, order.orderedTimestamp);
        try paymentOps.monetizeData(_patient) {} catch {}
    }

    /// @notice Collects a lab test sample
    /// @param _labTestId Lab test ID
    /// @param _ipfsHash IPFS hash of sample collection details
    function collectSample(uint32 _labTestId, string calldata _ipfsHash)
        external onlyRole(core.LAB_TECH_ROLE()) nonReentrant whenNotPaused {
        if (_labTestId == 0 || _labTestId > labTestCounter) revert InvalidId();
        if (bytes(_ipfsHash).length > MAX_STRING_LENGTH) revert InvalidParameter();
        LabTestOrder storage order = labTestOrders[_labTestId];
        if (order.status != LabTestStatus.Requested) revert InvalidStatus();
        if (order.labTech != msg.sender) revert NotAuthorized();
        if (block.timestamp > order.orderedTimestamp.add(order.sampleCollectionDeadline)) revert DeadlineMissed();
        if (!paymentOps.getLabTestPaymentStatus(_labTestId)) revert PaymentNotConfirmed();

        order.sampleCollectionHash = keccak256(abi.encode(_ipfsHash));
        order.status = LabTestStatus.Collected;
        emit LabTestCollected(_labTestId, order.sampleCollectionHash);
    }

    /// @notice Uploads lab test results
    /// @param _labTestId Lab test ID
    /// @param _resultsIpfsHash IPFS hash of results
    function uploadLabResults(uint32 _labTestId, string calldata _resultsIpfsHash)
        external onlyRole(core.LAB_TECH_ROLE()) nonReentrant whenNotPaused {
        if (_labTestId == 0 || _labTestId > labTestCounter) revert InvalidId();
        if (bytes(_resultsIpfsHash).length > MAX_STRING_LENGTH) revert InvalidParameter();
        LabTestOrder storage order = labTestOrders[_labTestId];
        if (order.labTech != msg.sender) revert NotAuthorized();
        if (order.status != LabTestStatus.Collected) revert InvalidStatus();
        if (block.timestamp > order.orderedTimestamp.add(order.resultsUploadDeadline)) revert DeadlineMissed();
        if (!paymentOps.getLabTestPaymentStatus(_labTestId)) revert PaymentNotConfirmed();

        order.resultsHash = keccak256(abi.encode(_resultsIpfsHash));
        order.status = LabTestStatus.ResultsUploaded;
        uint64 disputeWindow = uint64(base.disputeWindow());
        if (disputeWindow > MAX_DISPUTE_WINDOW) revert InvalidParameter();
        order.disputeWindowEnd = uint64(block.timestamp).add(disputeWindow);
        emit LabTestUploaded(_labTestId, order.resultsHash);
        emit LabTestDisputeWindowStarted(_labTestId, keccak256(abi.encode(order.patient)), order.disputeWindowEnd);
        try paymentOps.monetizeData(order.patient) {} catch {}
    }

    /// @notice Checks deadlines for multiple lab tests and reorders if necessary
    /// @param _labTestIds Array of lab test IDs
    function batchCheckLabTestDeadlines(uint32[] calldata _labTestIds) external nonReentrant whenNotPaused {
        for (uint256 i = 0; i < _labTestIds.length; i++) {
            uint32 _labTestId = _labTestIds[i];
            if (_labTestId == 0 || _labTestId > labTestCounter) continue;
            LabTestOrder storage order = labTestOrders[_labTestId];
            if (order.status == LabTestStatus.Reviewed || order.status == LabTestStatus.Disputed || order.status == LabTestStatus.Expired) continue;

            bool missedDeadline;
            if (order.status == LabTestStatus.Requested && block.timestamp > order.orderedTimestamp.add(order.sampleCollectionDeadline)) {
                missedDeadline = true;
            } else if (order.status == LabTestStatus.Collected && block.timestamp > order.orderedTimestamp.add(order.resultsUploadDeadline)) {
                missedDeadline = true;
            } else if (order.status == LabTestStatus.PaymentPending && block.timestamp > paymentOps.getLabTestPaymentDeadline(_labTestId)) {
                missedDeadline = true;
            }

            if (missedDeadline) {
                string memory locality = paymentOps.getLabTechLocality(order.labTech);
                address newLabTech = paymentOps.selectBestLabTech(string(abi.encode(order.testTypeHash)), locality);
                if (newLabTech == order.labTech || newLabTech == address(0)) continue;

                (uint256 price, bool isValid, uint48 sampleDeadline, uint48 resultsDeadline) = paymentOps.getLabTestDetails(newLabTech, string(abi.encode(order.testTypeHash)));
                if (!isValid) continue;

                if (order.patientCost > 0 && paymentOps.getLabTestPaymentStatus(_labTestId)) {
                    payments._refundPatient(order.patient, order.patientCost, order.paymentType);
                    emit LabTestRefunded(_labTestId, order.patient, order.patientCost);
                }

                order.status = LabTestStatus.Expired;
                unchecked { labTestCounter++; }
                if (labTestCounter >= MAX_COUNTER) continue;
                uint32 newTestId = uint32(labTestCounter);
                uint256 percentageDenominator = base.PERCENTAGE_DENOMINATOR();
                uint256 patientCost = price.mul(120).div(percentageDenominator);

                labTestOrders[newTestId] = LabTestOrder({
                    id: newTestId,
                    patient: order.patient,
                    doctor: order.doctor,
                    labTech: newLabTech,
                    status: LabTestStatus.Requested,
                    orderedTimestamp: uint64(block.timestamp),
                    completedTimestamp: 0,
                    testTypeHash: order.testTypeHash,
                    sampleCollectionHash: bytes32(0),
                    resultsHash: bytes32(0),
                    patientCost: patientCost,
                    disputeWindowEnd: 0,
                    disputeOutcome: DisputeOutcome.Unresolved,
                    sampleCollectionDeadline: uint64(sampleDeadline),
                    resultsUploadDeadline: uint64(resultsDeadline),
                    paymentType: order.paymentType
                });

                if (!isValid || price == 0) {
                    paymentOps.requestLabTestPrice(newLabTech, string(abi.encode(order.testTypeHash)), newTestId);
                } else {
                    paymentOps.setLabTestPayment(newTestId, true);
                    emit LabTestPaymentConfirmed(newTestId, patientCost);
                }

                emit LabTestOrdered(newTestId, keccak256(abi.encode(order.patient)), keccak256(abi.encode(order.doctor)), order.testTypeHash, uint64(block.timestamp));
                emit LabTestReordered(_labTestId, newTestId, keccak256(abi.encode(newLabTech)), keccak256(abi.encode(order.patient)));
                try paymentOps.monetizeData(order.patient) {} catch {}
            }
        }
    }

    /// @notice Reviews lab results and issues a prescription
    /// @param _labTestId Lab test ID
    /// @param _medicationIpfsHash IPFS hash of medication
    /// @param _prescriptionIpfsHash IPFS hash of prescription
    /// @param _pharmacy Pharmacy address
    /// @param _locality Locality for pharmacy validation
    function reviewLabResults(uint32 _labTestId, string calldata _medicationIpfsHash, string calldata _prescriptionIpfsHash, address _pharmacy, string calldata _locality)
        external payable onlyRole(core.DOCTOR_ROLE()) nonReentrant whenNotPaused {
        if (_labTestId == 0 || _labTestId > labTestCounter) revert InvalidId();
        if (_pharmacy == address(0)) revert InvalidAddress();
        if (bytes(_medicationIpfsHash).length > MAX_STRING_LENGTH || bytes(_prescriptionIpfsHash).length > MAX_STRING_LENGTH || bytes(_locality).length > MAX_STRING_LENGTH) revert InvalidParameter();
        LabTestOrder storage order = labTestOrders[_labTestId];
        if (order.doctor != msg.sender) revert NotAuthorized();
        if (order.status != LabTestStatus.ResultsUploaded) revert InvalidStatus();
        bool isPharmacyValid = paymentOps.isPharmacyRegistered(_pharmacy) || paymentOps.hasPharmacyInLocality(_locality);
        if (!isPharmacyValid) revert NotAuthorized();

        (uint256 price, bool isValid) = paymentOps.getPharmacyPrice(_pharmacy, _medicationIpfsHash);

        order.status = LabTestStatus.Reviewed;
        order.completedTimestamp = uint64(block.timestamp);

        unchecked { prescriptionCounter++; }
        if (prescriptionCounter >= MAX_COUNTER) revert InvalidCounter();
        uint32 newPrescriptionId = uint32(prescriptionCounter);
        bytes32 verificationCodeHash = keccak256(abi.encodePacked(newPrescriptionId, msg.sender, block.timestamp, SALT));

        Prescription storage prescription = prescriptions[newPrescriptionId];
        prescription.id = newPrescriptionId;
        prescription.patient = order.patient;
        prescription.doctor = msg.sender;
        prescription.verificationCodeHash = verificationCodeHash;
        prescription.status = PrescriptionStatus.Generated;
        prescription.pharmacy = _pharmacy;
        prescription.generatedTimestamp = uint64(block.timestamp);
        prescription.expirationTimestamp = uint64(block.timestamp.add(30 days));
        prescription.medicationHash = keccak256(abi.encode(_medicationIpfsHash));

        if (!isValid || price == 0) {
            paymentOps.requestPrescriptionPrice(_pharmacy, _medicationIpfsHash, newPrescriptionId);
        } else {
            uint256 percentageDenominator = base.PERCENTAGE_DENOMINATOR();
            prescription.patientCost = price.mul(120).div(percentageDenominator);
            if (msg.value < prescription.patientCost) revert InsufficientFunds();
            prescription.prescriptionHash = keccak256(abi.encode(_prescriptionIpfsHash));
            paymentOps.setPrescriptionPayment(newPrescriptionId, true);
            emit PrescriptionPaymentConfirmed(newPrescriptionId, prescription.patientCost);
            if (msg.value > prescription.patientCost) {
                _safeRefund(msg.sender, msg.value.sub(prescription.patientCost));
            }
        }

        emit PrescriptionIssued(newPrescriptionId, keccak256(abi.encode(order.patient)), keccak256(abi.encode(msg.sender)), verificationCodeHash, uint64(block.timestamp));
        try paymentOps.monetizeData(order.patient) {} catch {}
    }

    /// @notice Sets prescription details by patient
    /// @param _prescriptionId Prescription ID
    /// @param _prescriptionIpfsHash IPFS hash of prescription
    function setPrescriptionDetails(uint32 _prescriptionId, string calldata _prescriptionIpfsHash)
        external onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
        if (_prescriptionId == 0 || _prescriptionId > prescriptionCounter) revert InvalidId();
        if (bytes(_prescriptionIpfsHash).length > MAX_STRING_LENGTH) revert InvalidParameter();
        Prescription storage prescription = prescriptions[_prescriptionId];
        if (prescription.patient != msg.sender) revert NotAuthorized();
        if (prescription.status != PrescriptionStatus.Generated) revert InvalidStatus();
        if (!paymentOps.getPrescriptionPaymentStatus(_prescriptionId)) revert PaymentNotConfirmed();
        if (prescription.prescriptionHash != bytes32(0)) revert InvalidStatus();

        prescription.prescriptionHash = keccak256(abi.encode(_prescriptionIpfsHash));
        emit PrescriptionDetailsSet(_prescriptionId, prescription.prescriptionHash);
    }

    /// @notice Checks deadlines for multiple prescriptions
    /// @param _prescriptionIds Array of prescription IDs
    function batchCheckPrescriptionDeadlines(uint32[] calldata _prescriptionIds) external nonReentrant whenNotPaused {
        for (uint256 i = 0; i < _prescriptionIds.length; i++) {
            uint32 _prescriptionId = _prescriptionIds[i];
            if (_prescriptionId == 0 || _prescriptionId > prescriptionCounter) continue;
            Prescription storage prescription = prescriptions[_prescriptionId];
            if (prescription.status == PrescriptionStatus.Fulfilled ||
                prescription.status == PrescriptionStatus.Revoked ||
                prescription.status == PrescriptionStatus.Expired ||
                prescription.status == PrescriptionStatus.Disputed) continue;

            if (prescription.status == PrescriptionStatus.PaymentPending && block.timestamp > paymentOps.getPrescriptionPaymentDeadline(_prescriptionId)) {
                prescription.status = PrescriptionStatus.Expired;
                emit PrescriptionExpired(_prescriptionId);
            } else if ((prescription.status == PrescriptionStatus.Generated || prescription.status == PrescriptionStatus.Verified) &&
                       block.timestamp > prescription.expirationTimestamp) {
                prescription.status = PrescriptionStatus.Expired;
                emit PrescriptionExpired(_prescriptionId);
            }
        }
    }

    /// @notice Verifies a prescription by pharmacy
    /// @param _prescriptionId Prescription ID
    /// @param _verificationCodeHash Verification code hash
    function verifyPrescription(uint32 _prescriptionId, bytes32 _verificationCodeHash)
        external onlyRole(core.PHARMACY_ROLE()) nonReentrant whenNotPaused {
        if (_prescriptionId == 0 || _prescriptionId > prescriptionCounter) revert InvalidId();
        Prescription storage prescription = prescriptions[_prescriptionId];
        if (prescription.pharmacy != msg.sender) revert NotAuthorized();
        if (prescription.status != PrescriptionStatus.Generated) revert InvalidStatus();
        if (prescription.verificationCodeHash != _verificationCodeHash) revert NotAuthorized();
        if (block.timestamp > prescription.expirationTimestamp) revert InvalidTimestamp();
        if (!paymentOps.getPrescriptionPaymentStatus(_prescriptionId)) revert PaymentNotConfirmed();
        if (prescription.prescriptionHash == bytes32(0)) revert InvalidParameter();

        prescription.status = PrescriptionStatus.Verified;
        emit PrescriptionVerified(_prescriptionId, keccak256(abi.encode(msg.sender)));
    }

    /// @notice Fulfills a prescription by pharmacy
    /// @param _prescriptionId Prescription ID
    function fulfillPrescription(uint32 _prescriptionId)
        external onlyRole(core.PHARMACY_ROLE()) nonReentrant whenNotPaused {
        if (_prescriptionId == 0 || _prescriptionId > prescriptionCounter) revert InvalidId();
        Prescription storage prescription = prescriptions[_prescriptionId];
        if (prescription.pharmacy != msg.sender) revert NotAuthorized();
        if (prescription.status != PrescriptionStatus.Verified) revert InvalidStatus();
        if (block.timestamp > prescription.expirationTimestamp) revert InvalidTimestamp();
        if (!paymentOps.getPrescriptionPaymentStatus(_prescriptionId)) revert PaymentNotConfirmed();

        prescription.status = PrescriptionStatus.Fulfilled;
        uint64 disputeWindow = uint64(base.disputeWindow());
        if (disputeWindow > MAX_DISPUTE_WINDOW) revert InvalidParameter();
        prescription.disputeWindowEnd = uint64(block.timestamp).add(disputeWindow);
        emit PrescriptionFulfilled(_prescriptionId);
        emit PrescriptionDisputeWindowStarted(_prescriptionId, keccak256(abi.encode(prescription.patient)), prescription.disputeWindowEnd);
    }

    /// @notice Orders a replacement prescription after dispute
    /// @param _originalPrescriptionId Original prescription ID
    /// @param _operationHash Multi-sig operation hash
    function orderReplacementPrescription(uint32 _originalPrescriptionId, bytes32 _operationHash)
        external onlyDisputeResolution nonReentrant whenNotPaused onlyMultiSig(_operationHash) {
        if (_originalPrescriptionId == 0 || _originalPrescriptionId > prescriptionCounter) revert InvalidId();
        Prescription storage original = prescriptions[_originalPrescriptionId];
        if (original.status != PrescriptionStatus.Fulfilled) revert InvalidStatus();
        if (original.pharmacy == address(0)) revert InvalidAddress();
        TelemedicineCore.Patient memory patient = core.patients(original.patient);
        if (!patient.isRegistered) revert NotAuthorized();

        unchecked { prescriptionCounter++; }
        if (prescriptionCounter >= MAX_COUNTER) revert InvalidCounter();
        uint32 newPrescriptionId = uint32(prescriptionCounter);
        bytes32 newVerificationCodeHash = keccak256(abi.encodePacked(newPrescriptionId, original.doctor, block.timestamp, SALT));

        prescriptions[newPrescriptionId] = Prescription({
            id: newPrescriptionId,
            patient: original.patient,
            doctor: original.doctor,
            verificationCodeHash: newVerificationCodeHash,
            status: PrescriptionStatus.Generated,
            pharmacy: original.pharmacy,
            generatedTimestamp: uint64(block.timestamp),
            expirationTimestamp: uint64(block.timestamp.add(30 days)),
            medicationHash: original.medicationHash,
            prescriptionHash: original.prescriptionHash,
            patientCost: original.patientCost,
            disputeWindowEnd: 0,
            disputeOutcome: DisputeOutcome.Unresolved
        });
        paymentOps.setPrescriptionPayment(newPrescriptionId, true);

        emit PrescriptionIssued(newPrescriptionId, keccak256(abi.encode(original.patient)), keccak256(abi.encode(original.doctor)), newVerificationCodeHash, uint64(block.timestamp));
        emit ReplacementPrescriptionOrdered(_originalPrescriptionId, newPrescriptionId);
    }

    /// @notice Requests an AI symptom analysis, tied to a recent appointment
    /// @param _symptoms Symptoms description
    function requestAISymptomAnalysis(string calldata _symptoms)
        external onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
        if (bytes(_symptoms).length > MAX_STRING_LENGTH) revert InvalidParameter();
        if (aiAnalysisCounter >= MAX_COUNTER) revert InvalidCounter();

        // Check for recent appointment
        (uint256 appointmentId, uint64 appointmentTimestamp, bool isCompleted) = getRecentAppointment(msg.sender);
        if (appointmentId == 0 || !isCompleted || block.timestamp > appointmentTimestamp.add(medicalCore.recentAppointmentWindow())) {
            revert NoRecentAppointment();
        }

        core.decayPoints(msg.sender);
        TelemedicineCore.Patient storage patient = core.patients(msg.sender);
        uint256 maxLevel = core.maxLevel();
        uint256 freeAnalysisPeriod = core.freeAnalysisPeriod();
        bool isFree = patient.gamification.currentLevel == maxLevel &&
                      block.timestamp >= patient.lastFreeAnalysisTimestamp.add(freeAnalysisPeriod);

        unchecked { aiAnalysisCounter++; }
        uint32 newAnalysisId = uint32(aiAnalysisCounter);
        uint96 points = uint96(core.pointsForActions("aiAnalysis"));
        aiAnalyses[newAnalysisId] = AISymptomAnalysis({
            id: newAnalysisId,
            patient: msg.sender,
            doctorReviewed: false,
            status: AISymptomAnalysisStatus.Pending,
            symptomsHash: keccak256(abi.encode(_symptoms)),
            analysisHash: bytes32(0),
            reviewDeadline: uint64(block.timestamp.add(REVIEW_DEADLINE)),
            pointsEarned: points
        });

        patient.gamification.mediPoints = patient.gamification.mediPoints.add(points);
        patient.lastActivityTimestamp = uint64(block.timestamp);

        if (!isFree) {
            uint256 aiCost = core.aiAnalysisCost();
            uint256 aiFund = core.getAIFundBalance();
            if (aiFund < aiCost) revert InsufficientFunds();
            core.aiAnalysisFund = aiFund.sub(aiCost);
        } else {
            patient.lastFreeAnalysisTimestamp = uint64(block.timestamp);
            try paymentOps.notifyDataRewardClaimed(msg.sender, 0) {} catch {}
        }

        core._levelUp(msg.sender);
        emit AISymptomAnalyzed(newAnalysisId, keccak256(abi.encode(msg.sender)));
        try paymentOps.monetizeData(msg.sender) {} catch {}
    }

    /// @notice Reviews an AI symptom analysis by a doctor
    /// @param _aiAnalysisId AI analysis ID
    /// @param _analysisIpfsHash IPFS hash of reviewed analysis
    function reviewAISymptomAnalysis(uint32 _aiAnalysisId, string calldata _analysisIpfsHash)
        external onlyRole(core.DOCTOR_ROLE()) nonReentrant whenNotPaused {
        if (_aiAnalysisId == 0 || _aiAnalysisId > aiAnalysisCounter) revert InvalidId();
        if (bytes(_analysisIpfsHash).length > MAX_STRING_LENGTH) revert InvalidParameter();
        AISymptomAnalysis storage analysis = aiAnalyses[_aiAnalysisId];
        if (analysis.doctorReviewed || analysis.status != AISymptomAnalysisStatus.Pending) revert InvalidStatus();
        if (block.timestamp > analysis.reviewDeadline) revert DeadlineMissed();

        analysis.analysisHash = keccak256(abi.encode(_analysisIpfsHash));
        analysis.doctorReviewed = true;
        analysis.status = AISymptomAnalysisStatus.Reviewed;
        emit AISymptomAnalysisReviewed(_aiAnalysisId, keccak256(abi.encode(analysis.patient)), analysis.analysisHash);
    }

    /// @notice Checks deadlines for AI analysis reviews and refunds points if expired
    /// @param _aiAnalysisIds Array of AI analysis IDs
    function batchCheckAIReviewDeadlines(uint32[] calldata _aiAnalysisIds) external nonReentrant whenNotPaused {
        for (uint256 i = 0; i < _aiAnalysisIds.length; i++) {
            uint32 _aiAnalysisId = _aiAnalysisIds[i];
            if (_aiAnalysisId == 0 || _aiAnalysisId > aiAnalysisCounter) continue;
            AISymptomAnalysis storage analysis = aiAnalyses[_aiAnalysisId];
            if (analysis.status != AISymptomAnalysisStatus.Pending) continue;
            if (block.timestamp <= analysis.reviewDeadline) continue;

            analysis.status = AISymptomAnalysisStatus.Expired;
            TelemedicineCore.Patient storage patient = core.patients(analysis.patient);
            if (patient.gamification.mediPoints >= analysis.pointsEarned) {
                patient.gamification.mediPoints = patient.gamification.mediPoints.sub(analysis.pointsEarned);
            }
            emit AISymptomAnalysisExpired(_aiAnalysisId, keccak256(abi.encode(analysis.patient)), analysis.pointsEarned);
        }
    }

    /// @notice Updates dispute outcome for lab test or prescription
    /// @param _id Lab test or prescription ID
    /// @param _isLabTest True if lab test
    /// @param _outcome Dispute outcome
    function updateDisputeOutcome(uint32 _id, bool _isLabTest, DisputeOutcome _outcome)
        external onlyDisputeResolution nonReentrant whenNotPaused {
        if (_id == 0 || (_isLabTest && _id > labTestCounter) || (!_isLabTest && _id > prescriptionCounter)) revert InvalidId();
        if (_outcome == DisputeOutcome.Unresolved) revert InvalidOutcome();
        if (_isLabTest) {
            LabTestOrder storage order = labTestOrders[_id];
            if (order.status != LabTestStatus.Disputed) revert InvalidStatus();
            order.disputeOutcome = _outcome;
            order.status = LabTestStatus.Reviewed;
        } else {
            Prescription storage prescription = prescriptions[_id];
            if (prescription.status != PrescriptionStatus.Disputed) revert InvalidStatus();
            prescription.disputeOutcome = _outcome;
            prescription.status = PrescriptionStatus.Fulfilled;
        }
        emit DisputeOutcomeUpdated(_id, _outcome);
    }

    // Utility Functions

    /// @notice Safely refunds ETH to recipient
    /// @param _recipient Recipient address
    /// @param _amount Amount to refund
    function _safeRefund(address _recipient, uint256 _amount) internal {
        if (_amount == 0 || _recipient == address(0)) return;
        paymentOps.safeTransferETH(_recipient, _amount);
    }

    /// @notice Checks if an address is a contract
    /// @param addr Address to check
    /// @return True if address is a contract
    function _isContract(address addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }

    /// @notice Retrieves the most recent completed appointment for a patient
    /// @param _patient Patient address
    /// @return appointmentId Appointment ID
    /// @return timestamp Appointment timestamp
    /// @return isCompleted Whether the appointment is completed
    function getRecentAppointment(address _patient) internal view returns (uint256 appointmentId, uint64 timestamp, bool isCompleted) {
        if (_patient == address(0)) revert InvalidAddress();
        uint256[] memory completedIds = medicalCore.getPatientCompletedAppointments(_patient);
        if (completedIds.length == 0) return (0, 0, false);

        uint256 latestId = 0;
        uint64 latestTimestamp = 0;
        for (uint256 i = 0; i < completedIds.length; i++) {
            TelemedicineMedicalCore.Appointment memory apt = medicalCore.getAppointment(completedIds[i]);
            if (apt.status == TelemedicineMedicalCore.AppointmentStatus.Completed &&
                block.timestamp <= apt.scheduledTimestamp.add(medicalCore.recentAppointmentWindow()) &&
                apt.scheduledTimestamp > latestTimestamp) {
                latestId = apt.id;
                latestTimestamp = apt.scheduledTimestamp;
            }
        }

        if (latestId == 0) return (0, 0, false);
        return (latestId, latestTimestamp, true);
    }

    // View Functions

    /// @notice Retrieves lab test order details
    /// @param _labTestId Lab test ID
    /// @return Order details
    function getLabTestOrder(uint32 _labTestId) external view onlyConfigAdmin returns (
        uint32 id,
        address patient,
        address doctor,
        address labTech,
        LabTestStatus status,
        uint64 orderedTimestamp,
        uint64 completedTimestamp,
        bytes32 testTypeHash,
        bytes32 sampleCollectionHash,
        bytes32 resultsHash,
        uint256 patientCost,
        uint64 disputeWindowEnd,
        DisputeOutcome disputeOutcome,
        uint64 sampleCollectionDeadline,
        uint64 resultsUploadDeadline,
        TelemedicinePayments.PaymentType paymentType
    ) {
        LabTestOrder storage order = labTestOrders[_labTestId];
        return (
            order.id,
            order.patient,
            order.doctor,
            order.labTech,
            order.status,
            order.orderedTimestamp,
            order.completedTimestamp,
            order.testTypeHash,
            order.sampleCollectionHash,
            order.resultsHash,
            order.patientCost,
            order.disputeWindowEnd,
            order.disputeOutcome,
            order.sampleCollectionDeadline,
            order.resultsUploadDeadline,
            order.paymentType
        );
    }

    /// @notice Retrieves prescription details
    /// @param _prescriptionId Prescription ID
    /// @return Prescription details
    function getPrescription(uint32 _prescriptionId) external view onlyConfigAdmin returns (
        uint32 id,
        address patient,
        address doctor,
        bytes32 verificationCodeHash,
        PrescriptionStatus status,
        address pharmacy,
        uint64 generatedTimestamp,
        uint64 expirationTimestamp,
        bytes32 medicationHash,
        bytes32 prescriptionHash,
        uint256 patientCost,
        uint64 disputeWindowEnd,
        DisputeOutcome disputeOutcome
    ) {
        Prescription storage prescription = prescriptions[_prescriptionId];
        return (
            prescription.id,
            prescription.patient,
            prescription.doctor,
            prescription.verificationCodeHash,
            prescription.status,
            prescription.pharmacy,
            prescription.generatedTimestamp,
            prescription.expirationTimestamp,
            prescription.medicationHash,
            prescription.prescriptionHash,
            prescription.patientCost,
            prescription.disputeWindowEnd,
            prescription.disputeOutcome
        );
    }

    /// @notice Retrieves AI symptom analysis details
    /// @param _aiAnalysisId AI analysis ID
    /// @return id Analysis ID
    /// @return patient Patient address
    /// @return doctorReviewed Doctor review status
    /// @return status Analysis status
    /// @return symptomsHash Hashed symptoms
    /// @return analysisHash Hashed analysis (restricted for patients until reviewed)
    /// @return reviewDeadline Deadline for doctor review
    /// @return pointsEarned Points earned for the analysis
    function getAISymptomAnalysis(uint32 _aiAnalysisId) external view returns (
        uint32 id,
        address patient,
        bool doctorReviewed,
        AISymptomAnalysisStatus status,
        bytes32 symptomsHash,
        bytes32 analysisHash,
        uint64 reviewDeadline,
        uint96 pointsEarned
    ) {
        if (_aiAnalysisId == 0 || _aiAnalysisId > aiAnalysisCounter) revert InvalidId();
        AISymptomAnalysis storage analysis = aiAnalyses[_aiAnalysisId];

        if (msg.sender == analysis.patient && !analysis.doctorReviewed) {
            revert AnalysisNotReviewed();
        }

        bool isAuthorized = core.isConfigAdmin(msg.sender) ||
                           core.hasRole(core.DOCTOR_ROLE(), msg.sender) ||
                           msg.sender == analysis.patient;
        if (!isAuthorized) revert NotAuthorized();

        return (
            analysis.id,
            analysis.patient,
            analysis.doctorReviewed,
            analysis.status,
            analysis.symptomsHash,
            analysis.doctorReviewed ? analysis.analysisHash : bytes32(0),
            analysis.reviewDeadline,
            analysis.pointsEarned
        );
    }

    // Modifiers

    modifier onlyRole(bytes32 role) {
        if (!core.hasRole(role, msg.sender)) revert NotAuthorized();
        _;
    }

    modifier onlyDisputeResolution() {
        if (msg.sender != address(disputeResolution)) revert NotAuthorized();
        _;
    }

    modifier onlyConfigAdmin() {
        if (!core.isConfigAdmin(msg.sender)) revert NotAuthorized();
        _;
    }

    modifier whenNotPaused() {
        bool corePaused = core.paused();
        if (corePaused != paused()) {
            corePaused ? _pause() : _unpause();
        }
        if (paused()) revert ContractPaused();
        _;
    }

    modifier onlyMultiSig(bytes32 _operationHash) {
        uint256 nonce = base.nonces(msg.sender);
        bytes32 expectedHash = keccak256(abi.encodePacked(
            "orderReplacementPrescription",
            msg.sender,
            nonce,
            block.timestamp
        ));
        if (_operationHash != expectedHash || !paymentOps.checkMultiSigApproval(_operationHash)) revert MultiSigNotApproved();
        base.nonces(msg.sender) = nonce.add(1);
        _;
    }

    // Fallback
    receive() external payable {}

    // Storage Gap for Future Upgrades
    uint256[50] private __gap;
}
