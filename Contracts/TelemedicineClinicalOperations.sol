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

/// @title TelemedicineClinicalOperations
/// @notice Manages lab tests, prescriptions, and AI symptom analysis
/// @dev Upgradeable, integrates with core, payments, dispute resolution, base, and payment ops
contract TelemedicineClinicalOperations is Initializable, ReentrancyGuardUpgradeable, PausableUpgradeable {
    using SafeMathUpgradeable for uint256;
    using SafeERC20Upgradeable for IERC20Upgradeable;

    // Immutable Dependencies
    TelemedicineCore public immutable core;
    TelemedicinePayments public immutable payments;
    TelemedicineDisputeResolution public immutable disputeResolution;
    TelemedicineBase public immutable base;
    TelemedicinePaymentOperations public immutable paymentOps;

    // Private State Variables
    mapping(uint256 => LabTestOrder) private labTestOrders; // Updated: Private
    mapping(uint256 => Prescription) private prescriptions; // Updated: Private
    mapping(uint256 => AISymptomAnalysis) private aiAnalyses; // Updated: Private
    uint256 private labTestCounter;
    uint256 private prescriptionCounter;
    uint256 private aiAnalysisCounter;

    // Constants
    uint256 public constant MAX_COUNTER = 1_000_000; // New: Counter limit
    uint256 public constant MAX_STRING_LENGTH = 256; // New: String length limit
    uint64 public constant MIN_SAMPLE_DEADLINE = 1 hours; // New: Minimum sample deadline
    uint64 public constant MIN_RESULTS_DEADLINE = 1 days; // New: Minimum results deadline
    uint64 public constant MAX_DISPUTE_WINDOW = 7 days; // New: Maximum dispute window
    bytes32 private immutable SALT; // New: For verification code

    // Enums
    enum LabTestStatus { Requested, PaymentPending, Collected, ResultsUploaded, Reviewed, Disputed, Expired }
    enum PrescriptionStatus { Generated, PaymentPending, Verified, Fulfilled, Revoked, Expired, Disputed }
    enum DisputeOutcome { Unresolved, PatientFavored, ProviderFavored, MutualAgreement } // Assumed compatible with TelemedicineDisputeResolution

    // Structs
    struct LabTestOrder {
        uint32 id; // Updated: uint32
        address patient;
        address doctor;
        address labTech;
        LabTestStatus status;
        uint64 orderedTimestamp; // Updated: uint64
        uint64 completedTimestamp; // Updated: uint64
        bytes32 testTypeHash; // Updated: Hashed
        bytes32 sampleCollectionHash; // Updated: Hashed
        bytes32 resultsHash; // Updated: Hashed
        uint256 patientCost;
        uint64 disputeWindowEnd; // Updated: uint64
        DisputeOutcome disputeOutcome;
        uint64 sampleCollectionDeadline; // Updated: uint64
        uint64 resultsUploadDeadline; // Updated: uint64
        TelemedicinePayments.PaymentType paymentType;
    }

    struct Prescription {
        uint32 id; // Updated: uint32
        address patient;
        address doctor;
        bytes32 verificationCodeHash;
        PrescriptionStatus status;
        address pharmacy;
        uint64 generatedTimestamp; // Updated: uint64
        uint64 expirationTimestamp; // Updated: uint64
        bytes32 medicationHash; // Updated: Hashed
        bytes32 prescriptionHash; // Updated: Hashed
        uint256 patientCost;
        uint64 disputeWindowEnd; // Updated: uint64
        DisputeOutcome disputeOutcome;
    }

    struct AISymptomAnalysis {
        uint32 id; // Updated: uint32
        address patient;
        bool doctorReviewed;
        bytes32 symptomsHash; // Updated: Hashed
        bytes32 analysisHash; // Updated: Hashed
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
    event PrescriptionDetailsSet(uint32 indexed prescriptionId, bytes32 prescriptionHash);
    event LabTestDisputeWindowStarted(uint32 indexed testId, bytes32 patientHash, uint64 disputeWindowEnd);
    event PrescriptionDisputeWindowStarted(uint32 indexed prescriptionId, bytes32 patientHash, uint64 disputeWindowEnd);
    event ReplacementPrescriptionOrdered(uint32 indexed originalPrescriptionId, uint32 indexed newPrescriptionId);
    event DisputeOutcomeUpdated(uint32 indexed id, DisputeOutcome outcome); // New: Dispute outcome update

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
        SALT = keccak256(abi.encode(block.chainid, address(this))); // New: Immutable salt
    }

    /// @notice Initializes the contract
    /// @param _core Core contract address
    /// @param _payments Payments contract address
    /// @param _disputeResolution Dispute resolution contract address
    /// @param _base Base contract address
    /// @param _paymentOps Payment operations contract address
    function initialize(
        address _core,
        address _payments,
        address _disputeResolution,
        address _base,
        address _paymentOps
    ) external initializer {
        if (_core == address(0) || _payments == address(0) || _disputeResolution == address(0) ||
            _base == address(0) || _paymentOps == address(0)) revert InvalidAddress();
        if (!_isContract(_core) || !_isContract(_payments) || !_isContract(_disputeResolution) ||
            !_isContract(_base) || !_isContract(_paymentOps)) revert InvalidAddress();

        __ReentrancyGuard_init();
        __Pausable_init();

        core = TelemedicineCore(_core);
        payments = TelemedicinePayments(_payments);
        disputeResolution = TelemedicineDisputeResolution(_disputeResolution);
        base = TelemedicineBase(_base);
        paymentOps = TelemedicinePaymentOperations(_paymentOps);
    }

    // Lab Test Management

    /// @notice Orders a lab test
    /// @param _patient Patient address
    /// @param _testTypeIpfsHash Test type IPFS hash
    /// @param _locality Locality
    function orderLabTest(address _patient, string calldata _testTypeIpfsHash, string calldata _locality)
        external payable onlyRole(core.DOCTOR_ROLE()) nonReentrant whenNotPaused {
        if (_patient == address(0)) revert InvalidAddress();
        if (bytes(_testTypeIpfsHash).length > MAX_STRING_LENGTH || bytes(_locality).length > MAX_STRING_LENGTH) revert InvalidParameter();
        if (labTestCounter >= MAX_COUNTER) revert InvalidCounter();
        try core.patients(_patient) returns (TelemedicineCore.Patient memory patient) {
            if (!patient.isRegistered) revert NotAuthorized();
        } catch {
            revert ExternalCallFailed();
        }

        address selectedLabTech;
        try paymentOps.selectBestLabTech(_testTypeIpfsHash, _locality) returns (address labTech) {
            selectedLabTech = labTech;
        } catch {
            revert ExternalCallFailed();
        }
        if (selectedLabTech == address(0)) revert NoLabTechAvailable();

        uint256 price;
        bool isValid;
        uint64 sampleDeadline;
        uint64 resultsDeadline;
        try paymentOps.getLabTestDetails(selectedLabTech, _testTypeIpfsHash) returns (uint256 p, bool v, uint48 s, uint48 r) {
            price = p;
            isValid = v;
            sampleDeadline = uint64(s);
            resultsDeadline = uint64(r);
        } catch {
            revert ExternalCallFailed();
        }
        if (sampleDeadline < MIN_SAMPLE_DEADLINE || resultsDeadline < MIN_RESULTS_DEADLINE) revert InvalidDeadline();

        labTestCounter = labTestCounter.add(1);
        uint32 newTestId = uint32(labTestCounter);
        LabTestOrder storage order = labTestOrders[newTestId];
        order.id = newTestId;
        order.patient = _patient;
        order.doctor = msg.sender;
        order.labTech = selectedLabTech;
        order.status = LabTestStatus.Requested;
        order.orderedTimestamp = uint64(block.timestamp);
        order.testTypeHash = keccak256(abi.encode(_testTypeIpfsHash));
        order.sampleCollectionDeadline = sampleDeadline;
        order.resultsUploadDeadline = resultsDeadline;
        order.paymentType = TelemedicinePayments.PaymentType.ETH;

        if (!isValid || price == 0) {
            try paymentOps.requestLabTestPrice(selectedLabTech, _testTypeIpfsHash, newTestId) {} catch {
                revert ExternalCallFailed();
            }
        } else {
            uint256 percentageDenominator;
            try base.PERCENTAGE_DENOMINATOR() returns (uint256 denom) {
                percentageDenominator = denom;
            } catch {
                revert ExternalCallFailed();
            }
            order.patientCost = price.mul(120).div(percentageDenominator);
            if (msg.value < order.patientCost) revert InsufficientFunds();
            try paymentOps.setLabTestPayment(newTestId, true) {} catch {
                revert ExternalCallFailed();
            }
            if (msg.value > order.patientCost) {
                uint256 refund = msg.value.sub(order.patientCost);
                _safeRefund(msg.sender, refund);
            }
        }

        emit LabTestOrdered(newTestId, keccak256(abi.encode(_patient)), keccak256(abi.encode(msg.sender)), order.testTypeHash, order.orderedTimestamp);
        try paymentOps.monetizeData(_patient) {} catch {
            // Non-critical, continue
        }
    }

    /// @notice Collects lab test sample
    /// @param _labTestId Lab test ID
    /// @param _ipfsHash Sample collection IPFS hash
    function collectSample(uint32 _labTestId, string calldata _ipfsHash)
        external onlyRole(core.LAB_TECH_ROLE()) nonReentrant whenNotPaused {
        if (_labTestId == 0 || _labTestId > labTestCounter) revert InvalidId();
        if (bytes(_ipfsHash).length > MAX_STRING_LENGTH) revert InvalidParameter();
        LabTestOrder storage order = labTestOrders[_labTestId];
        if (order.status != LabTestStatus.Requested) revert InvalidStatus();
        if (order.labTech != msg.sender) revert NotAuthorized();
        if (block.timestamp > order.orderedTimestamp.add(order.sampleCollectionDeadline)) revert DeadlineMissed();
        bool paid;
        try paymentOps.getLabTestPaymentStatus(_labTestId) returns (bool status) {
            paid = status;
        } catch {
            revert ExternalCallFailed();
        }
        if (!paid) revert PaymentNotConfirmed();

        order.sampleCollectionHash = keccak256(abi.encode(_ipfsHash));
        order.status = LabTestStatus.Collected;
        emit LabTestCollected(_labTestId, order.sampleCollectionHash);
    }

    /// @notice Uploads lab test results
    /// @param _labTestId Lab test ID
    /// @param _resultsIpfsHash Results IPFS hash
    function uploadLabResults(uint32 _labTestId, string calldata _resultsIpfsHash)
        external onlyRole(core.LAB_TECH_ROLE()) nonReentrant whenNotPaused {
        if (_labTestId == 0 || _labTestId > labTestCounter) revert InvalidId();
        if (bytes(_resultsIpfsHash).length > MAX_STRING_LENGTH) revert InvalidParameter();
        LabTestOrder storage order = labTestOrders[_labTestId];
        if (order.labTech != msg.sender) revert NotAuthorized();
        if (order.status != LabTestStatus.Collected) revert InvalidStatus();
        if (block.timestamp > order.orderedTimestamp.add(order.resultsUploadDeadline)) revert DeadlineMissed();
        bool paid;
        try paymentOps.getLabTestPaymentStatus(_labTestId) returns (bool status) {
            paid = status;
        } catch {
            revert ExternalCallFailed();
        }
        if (!paid) revert PaymentNotConfirmed();

        order.resultsHash = keccak256(abi.encode(_resultsIpfsHash));
        order.status = LabTestStatus.ResultsUploaded;
        uint64 disputeWindow;
        try base.disputeWindow() returns (uint256 window) {
            disputeWindow = uint64(window);
        } catch {
            revert ExternalCallFailed();
        }
        if (disputeWindow > MAX_DISPUTE_WINDOW) revert InvalidParameter();
        order.disputeWindowEnd = uint64(block.timestamp).add(disputeWindow);
        emit LabTestUploaded(_labTestId, order.resultsHash);
        emit LabTestDisputeWindowStarted(_labTestId, keccak256(abi.encode(order.patient)), order.disputeWindowEnd);
        try paymentOps.monetizeData(order.patient) {} catch {
            // Non-critical, continue
        }
    }

    /// @notice Checks deadlines for multiple lab tests
    /// @param _labTestIds Lab test IDs
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
            } else if (order.status == LabTestStatus.PaymentPending) {
                uint64 deadline;
                try paymentOps.getLabTestPaymentDeadline(_labTestId) returns (uint256 d) {
                    deadline = uint64(d);
                } catch {
                    continue;
                }
                if (block.timestamp > deadline) missedDeadline = true;
            }

            if (missedDeadline) {
                string memory locality;
                try paymentOps.getLabTechLocality(order.labTech) returns (string memory loc) {
                    locality = loc;
                } catch {
                    continue;
                }
                address newLabTech;
                try paymentOps.selectBestLabTech(string(abi.encode(order.testTypeHash)), locality) returns (address labTech) {
                    newLabTech = labTech;
                } catch {
                    continue;
                }
                if (newLabTech == order.labTech || newLabTech == address(0)) continue;

                uint256 price;
                bool isValid;
                uint64 sampleDeadline;
                uint64 resultsDeadline;
                try paymentOps.getLabTestDetails(newLabTech, string(abi.encode(order.testTypeHash))) returns (uint256 p, bool v, uint48 s, uint48 r) {
                    price = p;
                    isValid = v;
                    sampleDeadline = uint64(s);
                    resultsDeadline = uint64(r);
                } catch {
                    continue;
                }
                if (!isValid) continue;

                if (order.patientCost > 0) {
                    bool paid;
                    try paymentOps.getLabTestPaymentStatus(_labTestId) returns (bool status) {
                        paid = status;
                    } catch {
                        continue;
                    }
                    if (paid) {
                        try payments._refundPatient(order.patient, order.patientCost, order.paymentType) {} catch {
                            continue;
                        }
                        emit LabTestRefunded(_labTestId, order.patient, order.patientCost);
                    }
                }

                order.status = LabTestStatus.Expired;
                labTestCounter = labTestCounter.add(1);
                if (labTestCounter >= MAX_COUNTER) continue;
                uint32 newTestId = uint32(labTestCounter);
                uint256 percentageDenominator;
                try base.PERCENTAGE_DENOMINATOR() returns (uint256 denom) {
                    percentageDenominator = denom;
                } catch {
                    continue;
                }
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
                    sampleCollectionDeadline: sampleDeadline,
                    resultsUploadDeadline: resultsDeadline,
                    paymentType: order.paymentType
                });

                if (!isValid || price == 0) {
                    try paymentOps.requestLabTestPrice(newLabTech, string(abi.encode(order.testTypeHash)), newTestId) {} catch {
                        continue;
                    }
                } else {
                    try paymentOps.setLabTestPayment(newTestId, true) {} catch {
                        continue;
                    }
                    emit LabTestPaymentConfirmed(newTestId, patientCost);
                }

                emit LabTestOrdered(newTestId, keccak256(abi.encode(order.patient)), keccak256(abi.encode(order.doctor)), order.testTypeHash, uint64(block.timestamp));
                emit LabTestReordered(_labTestId, newTestId, keccak256(abi.encode(newLabTech)), keccak256(abi.encode(order.patient)));
                try paymentOps.monetizeData(order.patient) {} catch {
                    // Non-critical, continue
                }
            }
        }
    }

    /// @notice Reviews lab results and issues prescription
    /// @param _labTestId Lab test ID
    /// @param _medicationIpfsHash Medication IPFS hash
    /// @param _prescriptionIpfsHash Prescription IPFS hash
    /// @param _pharmacy Pharmacy address
    /// @param _locality Locality
    function reviewLabResults(uint32 _labTestId, string calldata _medicationIpfsHash, string calldata _prescriptionIpfsHash, address _pharmacy, string calldata _locality)
        external payable onlyRole(core.DOCTOR_ROLE()) nonReentrant whenNotPaused {
        if (_labTestId == 0 || _labTestId > labTestCounter) revert InvalidId();
        if (_pharmacy == address(0)) revert InvalidAddress();
        if (bytes(_medicationIpfsHash).length > MAX_STRING_LENGTH || bytes(_prescriptionIpfsHash).length > MAX_STRING_LENGTH || bytes(_locality).length > MAX_STRING_LENGTH) revert InvalidParameter();
        LabTestOrder storage order = labTestOrders[_labTestId];
        if (order.doctor != msg.sender) revert NotAuthorized();
        if (order.status != LabTestStatus.ResultsUploaded) revert InvalidStatus();
        bool isPharmacyValid;
        try paymentOps.isPharmacyRegistered(_pharmacy) returns (bool registered) {
            isPharmacyValid = registered;
        } catch {
            revert ExternalCallFailed();
        }
        if (!isPharmacyValid) {
            try paymentOps.hasPharmacyInLocality(_locality) returns (bool hasPharmacy) {
                isPharmacyValid = hasPharmacy;
            } catch {
                revert ExternalCallFailed();
            }
        }
        if (!isPharmacyValid) revert NotAuthorized();

        uint256 price;
        bool isValid;
        try paymentOps.getPharmacyPrice(_pharmacy, _medicationIpfsHash) returns (uint256 p, bool v) {
            price = p;
            isValid = v;
        } catch {
            revert ExternalCallFailed();
        }

        order.status = LabTestStatus.Reviewed;
        order.completedTimestamp = uint64(block.timestamp);

        prescriptionCounter = prescriptionCounter.add(1);
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
            try paymentOps.requestPrescriptionPrice(_pharmacy, _medicationIpfsHash, newPrescriptionId) {} catch {
                revert ExternalCallFailed();
            }
        } else {
            uint256 percentageDenominator;
            try base.PERCENTAGE_DENOMINATOR() returns (uint256 denom) {
                percentageDenominator = denom;
            } catch {
                revert ExternalCallFailed();
            }
            prescription.patientCost = price.mul(120).div(percentageDenominator);
            if (msg.value < prescription.patientCost) revert InsufficientFunds();
            prescription.prescriptionHash = keccak256(abi.encode(_prescriptionIpfsHash));
            try paymentOps.setPrescriptionPayment(newPrescriptionId, true) {} catch {
                revert ExternalCallFailed();
            }
            emit PrescriptionPaymentConfirmed(newPrescriptionId, prescription.patientCost);
            if (msg.value > prescription.patientCost) {
                uint256 refund = msg.value.sub(prescription.patientCost);
                _safeRefund(msg.sender, refund);
            }
        }

        emit PrescriptionIssued(newPrescriptionId, keccak256(abi.encode(order.patient)), keccak256(abi.encode(msg.sender)), verificationCodeHash, uint64(block.timestamp));
        try paymentOps.monetizeData(order.patient) {} catch {
            // Non-critical, continue
        }
    }

    /// @notice Sets prescription details
    /// @param _prescriptionId Prescription ID
    /// @param _prescriptionIpfsHash Prescription IPFS hash
    function setPrescriptionDetails(uint32 _prescriptionId, string calldata _prescriptionIpfsHash)
        external onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
        if (_prescriptionId == 0 || _prescriptionId > prescriptionCounter) revert InvalidId();
        if (bytes(_prescriptionIpfsHash).length > MAX_STRING_LENGTH) revert InvalidParameter();
        Prescription storage prescription = prescriptions[_prescriptionId];
        if (prescription.patient != msg.sender) revert NotAuthorized();
        if (prescription.status != PrescriptionStatus.Generated) revert InvalidStatus();
        bool paid;
        try paymentOps.getPrescriptionPaymentStatus(_prescriptionId) returns (bool status) {
            paid = status;
        } catch {
            revert ExternalCallFailed();
        }
        if (!paid) revert PaymentNotConfirmed();
        if (prescription.prescriptionHash != bytes32(0)) revert InvalidStatus();

        prescription.prescriptionHash = keccak256(abi.encode(_prescriptionIpfsHash));
        emit PrescriptionDetailsSet(_prescriptionId, prescription.prescriptionHash);
    }

    /// @notice Checks deadlines for multiple prescriptions
    /// @param _prescriptionIds Prescription IDs
    function batchCheckPrescriptionDeadlines(uint32[] calldata _prescriptionIds) external nonReentrant whenNotPaused {
        for (uint256 i = 0; i < _prescriptionIds.length; i++) {
            uint32 _prescriptionId = _prescriptionIds[i];
            if (_prescriptionId == 0 || _prescriptionId > prescriptionCounter) continue;
            Prescription storage prescription = prescriptions[_prescriptionId];
            if (prescription.status == PrescriptionStatus.Fulfilled ||
                prescription.status == PrescriptionStatus.Revoked ||
                prescription.status == PrescriptionStatus.Expired ||
                prescription.status == PrescriptionStatus.Disputed) continue;

            if (prescription.status == PrescriptionStatus.PaymentPending) {
                uint64 deadline;
                try paymentOps.getPrescriptionPaymentDeadline(_prescriptionId) returns (uint256 d) {
                    deadline = uint64(d);
                } catch {
                    continue;
                }
                if (block.timestamp > deadline) {
                    prescription.status = PrescriptionStatus.Expired;
                    emit PrescriptionExpired(_prescriptionId);
                }
            } else if ((prescription.status == PrescriptionStatus.Generated || prescription.status == PrescriptionStatus.Verified) &&
                       block.timestamp > prescription.expirationTimestamp) {
                prescription.status = PrescriptionStatus.Expired;
                emit PrescriptionExpired(_prescriptionId);
            }
        }
    }

    /// @notice Verifies a prescription
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
        bool paid;
        try paymentOps.getPrescriptionPaymentStatus(_prescriptionId) returns (bool status) {
            paid = status;
        } catch {
            revert ExternalCallFailed();
        }
        if (!paid) revert PaymentNotConfirmed();
        if (prescription.prescriptionHash == bytes32(0)) revert InvalidParameter();

        prescription.status = PrescriptionStatus.Verified;
        emit PrescriptionVerified(_prescriptionId, keccak256(abi.encode(msg.sender)));
    }

    /// @notice Fulfills a prescription
    /// @param _prescriptionId Prescription ID
    function fulfillPrescription(uint32 _prescriptionId)
        external onlyRole(core.PHARMACY_ROLE()) nonReentrant whenNotPaused {
        if (_prescriptionId == 0 || _prescriptionId > prescriptionCounter) revert InvalidId();
        Prescription storage prescription = prescriptions[_prescriptionId];
        if (prescription.pharmacy != msg.sender) revert NotAuthorized();
        if (prescription.status != PrescriptionStatus.Verified) revert InvalidStatus();
        if (block.timestamp > prescription.expirationTimestamp) revert InvalidTimestamp();
        bool paid;
        try paymentOps.getPrescriptionPaymentStatus(_prescriptionId) returns (bool status) {
            paid = status;
        } catch {
            revert ExternalCallFailed();
        }
        if (!paid) revert PaymentNotConfirmed();

        prescription.status = PrescriptionStatus.Fulfilled;
        uint64 disputeWindow;
        try base.disputeWindow() returns (uint256 window) {
            disputeWindow = uint64(window);
        } catch {
            revert ExternalCallFailed();
        }
        if (disputeWindow > MAX_DISPUTE_WINDOW) revert InvalidParameter();
        prescription.disputeWindowEnd = uint64(block.timestamp).add(disputeWindow);
        emit PrescriptionFulfilled(_prescriptionId);
        emit PrescriptionDisputeWindowStarted(_prescriptionId, keccak256(abi.encode(prescription.patient)), prescription.disputeWindowEnd);
    }

    /// @notice Orders a replacement prescription
    /// @param _originalPrescriptionId Original prescription ID
    /// @param _operationHash Operation hash
    function orderReplacementPrescription(uint32 _originalPrescriptionId, bytes32 _operationHash)
        external onlyDisputeResolution nonReentrant whenNotPaused onlyMultiSig(_operationHash) {
        if (_originalPrescriptionId == 0 || _originalPrescriptionId > prescriptionCounter) revert InvalidId();
        Prescription storage original = prescriptions[_originalPrescriptionId];
        if (original.status != PrescriptionStatus.Fulfilled) revert InvalidStatus();
        if (original.pharmacy == address(0)) revert InvalidAddress();
        try core.patients(original.patient) returns (TelemedicineCore.Patient memory patient) {
            if (!patient.isRegistered) revert NotAuthorized();
        } catch {
            revert ExternalCallFailed();
        }

        prescriptionCounter = prescriptionCounter.add(1);
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
        try paymentOps.setPrescriptionPayment(newPrescriptionId, true) {} catch {
            revert ExternalCallFailed();
        }

        emit PrescriptionIssued(newPrescriptionId, keccak256(abi.encode(original.patient)), keccak256(abi.encode(original.doctor)), newVerificationCodeHash, uint64(block.timestamp));
        emit ReplacementPrescriptionOrdered(_originalPrescriptionId, newPrescriptionId);
    }

    /// @notice Requests AI symptom analysis
    /// @param _symptoms Symptoms
    function requestAISymptomAnalysis(string calldata _symptoms)
        external onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
        if (bytes(_symptoms).length > MAX_STRING_LENGTH) revert InvalidParameter();
        if (aiAnalysisCounter >= MAX_COUNTER) revert InvalidCounter();
        try core.decayPoints(msg.sender) {} catch {
            revert ExternalCallFailed();
        }
        TelemedicineCore.Patient storage patient;
        try core.patients(msg.sender) returns (TelemedicineCore.Patient storage p) {
            patient = p;
        } catch {
            revert ExternalCallFailed();
        }
        uint256 maxLevel;
        try core.maxLevel() returns (uint256 level) {
            maxLevel = level;
        } catch {
            revert ExternalCallFailed();
        }
        uint256 freeAnalysisPeriod;
        try core.freeAnalysisPeriod() returns (uint256 period) {
            freeAnalysisPeriod = period;
        } catch {
            revert ExternalCallFailed();
        }
        bool isFree = patient.gamification.currentLevel == maxLevel &&
                      block.timestamp >= patient.lastFreeAnalysisTimestamp.add(freeAnalysisPeriod);

        aiAnalysisCounter = aiAnalysisCounter.add(1);
        uint32 newAnalysisId = uint32(aiAnalysisCounter);
        aiAnalyses[newAnalysisId] = AISymptomAnalysis(newAnalysisId, msg.sender, false, keccak256(abi.encode(_symptoms)), bytes32(0));
        uint96 points;
        try core.pointsForActions("aiAnalysis") returns (uint256 p) {
            points = uint96(p);
        } catch {
            revert ExternalCallFailed();
        }
        patient.gamification.mediPoints = patient.gamification.mediPoints.add(points);
        patient.lastActivityTimestamp = uint64(block.timestamp);

        if (!isFree) {
            uint256 aiCost;
            try core.aiAnalysisCost() returns (uint256 cost) {
                aiCost = cost;
            } catch {
                revert ExternalCallFailed();
            }
            uint256 aiFund;
            try core.getAIFundBalance() returns (uint256 fund) {
                aiFund = fund;
            } catch {
                revert ExternalCallFailed();
            }
            if (aiFund < aiCost) revert InsufficientFunds();
            core.aiAnalysisFund = aiFund.sub(aiCost);
        } else {
            patient.lastFreeAnalysisTimestamp = uint64(block.timestamp);
            try paymentOps.notifyDataRewardClaimed(msg.sender, 0) {} catch {
                // Non-critical, continue
            }
        }

        try core._levelUp(msg.sender) {} catch {
            revert ExternalCallFailed();
        }
        emit AISymptomAnalyzed(newAnalysisId, keccak256(abi.encode(msg.sender)));
        try paymentOps.monetizeData(msg.sender) {} catch {
            // Non-critical, continue
        }
    }

    /// @notice Reviews AI symptom analysis
    /// @param _aiAnalysisId AI analysis ID
    /// @param _analysisIpfsHash Analysis IPFS hash
    function reviewAISymptomAnalysis(uint32 _aiAnalysisId, string calldata _analysisIpfsHash)
        external onlyRole(core.DOCTOR_ROLE()) nonReentrant whenNotPaused {
        if (_aiAnalysisId == 0 || _aiAnalysisId > aiAnalysisCounter) revert InvalidId();
        if (bytes(_analysisIpfsHash).length > MAX_STRING_LENGTH) revert InvalidParameter();
        AISymptomAnalysis storage analysis = aiAnalyses[_aiAnalysisId];
        if (analysis.doctorReviewed) revert InvalidStatus();

        analysis.analysisHash = keccak256(abi.encode(_analysisIpfsHash));
        analysis.doctorReviewed = true;
    }

    /// @notice Updates dispute outcome
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

    // Events from paymentOps
    event LabTestRefunded(uint32 indexed testId, address patient, uint256 amount);
    event LabTestPaymentConfirmed(uint32 indexed testId, uint256 amount);
    event PrescriptionPaymentConfirmed(uint32 indexed prescriptionId, uint256 amount);

    // Utility Functions

    /// @notice Safely refunds ETH
    /// @param _recipient Recipient address
    /// @param _amount Amount
    function _safeRefund(address _recipient, uint256 _amount) internal {
        if (_amount == 0 || _recipient == address(0)) return;
        try paymentOps.safeTransferETH(_recipient, _amount) {} catch {
            revert ExternalCallFailed();
        }
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

    /// @notice Gets lab test order
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

    /// @notice Gets prescription
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

    /// @notice Gets AI symptom analysis
    /// @param _aiAnalysisId AI analysis ID
    /// @return Analysis details
    function getAISymptomAnalysis(uint32 _aiAnalysisId) external view onlyConfigAdmin returns (
        uint32 id,
        address patient,
        bool doctorReviewed,
        bytes32 symptomsHash,
        bytes32 analysisHash
    ) {
        AISymptomAnalysis storage analysis = aiAnalyses[_aiAnalysisId];
        return (
            analysis.id,
            analysis.patient,
            analysis.doctorReviewed,
            analysis.symptomsHash,
            analysis.analysisHash
        );
    }

    // Modifiers

    modifier onlyRole(bytes32 role) {
        try core.hasRole(role, msg.sender) returns (bool hasRole) {
            if (!hasRole) revert NotAuthorized();
        } catch {
            revert ExternalCallFailed();
        }
        _;
    }

    modifier onlyDisputeResolution() {
        if (msg.sender != address(disputeResolution)) revert NotAuthorized();
        _;
    }

    modifier onlyConfigAdmin() {
        try core.isConfigAdmin(msg.sender) returns (bool isAdmin) {
            if (!isAdmin) revert NotAuthorized();
        } catch {
            revert ExternalCallFailed();
        }
        _;
    }

    modifier whenNotPaused() {
        try core.paused() returns (bool corePaused) {
            if (corePaused != paused()) {
                corePaused ? _pause() : _unpause();
            }
            if (paused()) revert ContractPaused();
        } catch {
            revert ExternalCallFailed();
        }
        _;
    }

    modifier onlyMultiSig(bytes32 _operationHash) {
        uint256 nonce;
        try base.nonces(msg.sender) returns (uint256 n) {
            nonce = n;
        } catch {
            revert ExternalCallFailed();
        }
        bytes32 expectedHash = keccak256(abi.encodePacked(
            "orderReplacementPrescription",
            msg.sender,
            nonce,
            block.timestamp
        ));
        if (_operationHash != expectedHash) revert MultiSigNotApproved();
        try paymentOps.checkMultiSigApproval(_operationHash) returns (bool approved) {
            if (!approved) revert MultiSigNotApproved();
        } catch {
            revert ExternalCallFailed();
        }
        try base.nonces(msg.sender) returns (uint256) {
            base.nonces(msg.sender) = nonce.add(1);
        } catch {
            revert ExternalCallFailed();
        }
        _;
    }

    // Fallback
    receive() external payable {}
}
