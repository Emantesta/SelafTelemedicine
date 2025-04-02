// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {SafeMathUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";
import {SafeERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import {TelemedicineCore} from "./TelemedicineCore.sol";
import {TelemedicinePayments} from "./TelemedicinePayments.sol";
import {TelemedicineDisputeResolution} from "./TelemedicineDisputeResolution.sol";
import {TelemedicineBase} from "./TelemedicineBase.sol";
import {TelemedicinePaymentOperations} from "./TelemedicinePaymentOperations.sol";

contract TelemedicineClinicalOperations is Initializable, ReentrancyGuardUpgradeable {
    using SafeMathUpgradeable for uint256;
    using SafeERC20Upgradeable for IERC20Upgradeable;

    // Custom Errors
    error NotAuthorized();
    error ContractPaused();
    error InvalidAddress();
    error InvalidStatus();
    error InvalidTimestamp();
    error InsufficientFunds();
    error InvalidIndex();
    error InvalidIpfsHash();
    error MultiSigNotApproved();
    error DeadlineMissed();
    error NoLabTechAvailable();
    error PaymentNotConfirmed();

    // Contract dependencies
    TelemedicineCore public core;
    TelemedicinePayments public payments;
    TelemedicineDisputeResolution public disputeResolution;
    TelemedicineBase public base;
    TelemedicinePaymentOperations public paymentOps;

    // State Variables
    mapping(uint256 => LabTestOrder) public labTestOrders;
    mapping(uint256 => Prescription) public prescriptions;
    mapping(uint256 => AISymptomAnalysis) public aiAnalyses;

    uint256 public labTestCounter;
    uint256 public prescriptionCounter;
    uint256 public aiAnalysisCounter;

    // Enums
    enum LabTestStatus { Requested, PaymentPending, Collected, ResultsUploaded, Reviewed, Disputed, Expired }
    enum PrescriptionStatus { Generated, PaymentPending, Verified, Fulfilled, Revoked, Expired, Disputed }
    enum DisputeOutcome { Unresolved, PatientFavored, ProviderFavored, MutualAgreement }

    // Structs
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
        DisputeOutcome disputeOutcome;
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
        DisputeOutcome disputeOutcome;
    }

    struct AISymptomAnalysis {
        uint256 id;
        address patient;
        bool doctorReviewed;
        string symptoms;
        string analysisIpfsHash;
    }

    // Events
    event LabTestOrdered(uint256 indexed testId, address patient, address doctor, string testTypeIpfsHash, uint48 orderedAt);
    event LabTestCollected(uint256 indexed testId, string ipfsHash);
    event LabTestUploaded(uint256 indexed testId, string ipfsHash);
    event LabTestReviewed(uint256 indexed testId);
    event LabTestReordered(uint256 indexed originalTestId, uint256 indexed newTestId, address newLabTech, address patient);
    event PrescriptionIssued(uint256 indexed prescriptionId, address patient, address doctor, bytes32 verificationCodeHash, uint48 issuedAt);
    event PrescriptionVerified(uint256 indexed prescriptionId, address pharmacy);
    event PrescriptionFulfilled(uint256 indexed prescriptionId);
    event PrescriptionExpired(uint256 indexed prescriptionId);
    event AISymptomAnalyzed(uint256 indexed id, address indexed patient);
    event PrescriptionDetailsSet(uint256 indexed prescriptionId, string prescriptionIpfsHash);
    event LabTestDisputeWindowStarted(uint256 indexed testId, address patient, uint48 disputeWindowEnd);
    event PrescriptionDisputeWindowStarted(uint256 indexed prescriptionId, address patient, uint48 disputeWindowEnd);
    event ReplacementPrescriptionOrdered(uint256 indexed originalPrescriptionId, uint256 indexed newPrescriptionId);

    function initialize(
        address _core,
        address _payments,
        address _disputeResolution,
        address _base,
        address _paymentOps
    ) external initializer {
        if (_core == address(0) || _payments == address(0) || _disputeResolution == address(0) || 
            _base == address(0) || _paymentOps == address(0)) revert InvalidAddress();

        __ReentrancyGuard_init();
        core = TelemedicineCore(_core);
        payments = TelemedicinePayments(_payments);
        disputeResolution = TelemedicineDisputeResolution(_disputeResolution);
        base = TelemedicineBase(_base);
        paymentOps = TelemedicinePaymentOperations(_paymentOps);

        labTestCounter = 0;
        prescriptionCounter = 0;
        aiAnalysisCounter = 0;
    }

    function orderLabTest(address _patient, string calldata _testTypeIpfsHash, string calldata _locality)
        external payable onlyRole(core.DOCTOR_ROLE()) nonReentrant whenNotPaused {
        if (_patient == address(0)) revert InvalidAddress();
        if (!core.patients(_patient).isRegistered) revert NotAuthorized();
        if (bytes(_testTypeIpfsHash).length == 0 || bytes(_locality).length == 0) revert InvalidIpfsHash();

        address selectedLabTech = paymentOps.selectBestLabTech(_testTypeIpfsHash, _locality);
        if (selectedLabTech == address(0)) revert NoLabTechAvailable();

        (uint256 price, bool isValid, uint48 sampleDeadline, uint48 resultsDeadline) = paymentOps.getLabTestDetails(selectedLabTech, _testTypeIpfsHash);
        labTestCounter = labTestCounter + 1;
        uint256 newTestId = labTestCounter;

        LabTestOrder storage order = labTestOrders[newTestId];
        order.id = newTestId;
        order.patient = _patient;
        order.doctor = msg.sender;
        order.labTech = selectedLabTech;
        order.status = LabTestStatus.Requested;
        order.orderedTimestamp = uint48(block.timestamp);
        order.testTypeIpfsHash = _testTypeIpfsHash;
        order.sampleCollectionDeadline = sampleDeadline;
        order.resultsUploadDeadline = resultsDeadline;
        order.paymentType = TelemedicinePayments.PaymentType.ETH;

        if (!isValid || price == 0) {
            paymentOps.requestLabTestPrice(selectedLabTech, _testTypeIpfsHash, newTestId);
        } else {
            order.patientCost = price * 120 / base.PERCENTAGE_DENOMINATOR();
            if (msg.value < order.patientCost) revert InsufficientFunds();
            paymentOps.setLabTestPayment(newTestId, true);
            emit LabTestOrdered(newTestId, _patient, msg.sender, _testTypeIpfsHash, uint48(block.timestamp));
            if (msg.value > order.patientCost) {
                uint256 refund = msg.value - order.patientCost;
                paymentOps.safeTransferETH(msg.sender, refund);
            }
        }

        emit LabTestOrdered(newTestId, _patient, msg.sender, _testTypeIpfsHash, uint48(block.timestamp));
        paymentOps.monetizeData(_patient);
    }

    function collectSample(uint256 _labTestId, string calldata _ipfsHash)
        external onlyRole(core.LAB_TECH_ROLE()) nonReentrant whenNotPaused {
        LabTestOrder storage order = labTestOrders[_labTestId];
        if (order.status != LabTestStatus.Requested) revert InvalidStatus();
        if (order.labTech != msg.sender) revert NotAuthorized();
        if (_labTestId == 0 || _labTestId > labTestCounter) revert InvalidIndex();
        if (bytes(_ipfsHash).length == 0) revert InvalidIpfsHash();
        if (block.timestamp > order.orderedTimestamp + order.sampleCollectionDeadline) revert DeadlineMissed();
        if (!paymentOps.getLabTestPaymentStatus(_labTestId)) revert PaymentNotConfirmed();

        order.sampleCollectionIpfsHash = _ipfsHash;
        order.status = LabTestStatus.Collected;
        emit LabTestCollected(_labTestId, _ipfsHash);
    }

    function uploadLabResults(uint256 _labTestId, string calldata _resultsIpfsHash)
        external onlyRole(core.LAB_TECH_ROLE()) nonReentrant whenNotPaused {
        LabTestOrder storage order = labTestOrders[_labTestId];
        if (order.labTech != msg.sender) revert NotAuthorized();
        if (order.status != LabTestStatus.Collected) revert InvalidStatus();
        if (_labTestId == 0 || _labTestId > labTestCounter) revert InvalidIndex();
        if (bytes(_resultsIpfsHash).length == 0) revert InvalidIpfsHash();
        if (block.timestamp > order.orderedTimestamp + order.resultsUploadDeadline) revert DeadlineMissed();
        if (!paymentOps.getLabTestPaymentStatus(_labTestId)) revert PaymentNotConfirmed();

        order.resultsIpfsHash = _resultsIpfsHash;
        order.status = LabTestStatus.ResultsUploaded;
        order.disputeWindowEnd = uint48(block.timestamp) + base.disputeWindow();
        emit LabTestUploaded(_labTestId, _resultsIpfsHash);
        emit LabTestDisputeWindowStarted(_labTestId, order.patient, order.disputeWindowEnd);
        paymentOps.monetizeData(order.patient);
    }

    function checkLabTestDeadlines(uint256 _labTestId) external nonReentrant whenNotPaused {
        LabTestOrder storage order = labTestOrders[_labTestId];
        if (_labTestId == 0 || _labTestId > labTestCounter) revert InvalidIndex();
        if (order.status == LabTestStatus.Reviewed || order.status == LabTestStatus.Disputed || order.status == LabTestStatus.Expired) return;

        bool missedDeadline = false;
        if (order.status == LabTestStatus.Requested && block.timestamp > order.orderedTimestamp + order.sampleCollectionDeadline) {
            missedDeadline = true;
        } else if (order.status == LabTestStatus.Collected && block.timestamp > order.orderedTimestamp + order.resultsUploadDeadline) {
            missedDeadline = true;
        } else if (order.status == LabTestStatus.PaymentPending && block.timestamp > paymentOps.getLabTestPaymentDeadline(_labTestId)) {
            missedDeadline = true;
        }

        if (missedDeadline) {
            string memory locality = paymentOps.getLabTechLocality(order.labTech);
            address newLabTech = paymentOps.selectBestLabTech(order.testTypeIpfsHash, locality);
            if (newLabTech == order.labTech || newLabTech == address(0)) revert NoLabTechAvailable();

            (uint256 price, bool isValid, uint48 sampleDeadline, uint48 resultsDeadline) = paymentOps.getLabTestDetails(newLabTech, order.testTypeIpfsHash);
            if (!isValid) revert InvalidStatus();

            if (order.patientCost > 0 && paymentOps.getLabTestPaymentStatus(_labTestId)) {
                payments._refundPatient(order.patient, order.patientCost, order.paymentType);
                emit LabTestRefunded(_labTestId, order.patient, order.patientCost);
            }

            order.status = LabTestStatus.Expired;
            labTestCounter = labTestCounter + 1;
            uint256 newTestId = labTestCounter;
            uint256 patientCost = price * 120 / base.PERCENTAGE_DENOMINATOR();

            labTestOrders[newTestId] = LabTestOrder({
                id: newTestId,
                patient: order.patient,
                doctor: order.doctor,
                labTech: newLabTech,
                status: LabTestStatus.Requested,
                orderedTimestamp: uint48(block.timestamp),
                completedTimestamp: 0,
                testTypeIpfsHash: order.testTypeIpfsHash,
                sampleCollectionIpfsHash: "",
                resultsIpfsHash: "",
                patientCost: patientCost,
                disputeWindowEnd: 0,
                disputeOutcome: DisputeOutcome.Unresolved,
                sampleCollectionDeadline: sampleDeadline,
                resultsUploadDeadline: resultsDeadline,
                paymentType: order.paymentType
            });

            if (!isValid || price == 0) {
                paymentOps.requestLabTestPrice(newLabTech, order.testTypeIpfsHash, newTestId);
            } else {
                paymentOps.setLabTestPayment(newTestId, true);
                emit LabTestPaymentConfirmed(newTestId, patientCost);
            }

            emit LabTestOrdered(newTestId, order.patient, order.doctor, order.testTypeIpfsHash, uint48(block.timestamp));
            emit LabTestReordered(_labTestId, newTestId, newLabTech, order.patient);
            paymentOps.monetizeData(order.patient);
        }
    }

    function reviewLabResults(uint256 _labTestId, string calldata _medicationIpfsHash, string calldata _prescriptionIpfsHash, address _pharmacy, string calldata _locality)
        external payable onlyRole(core.DOCTOR_ROLE()) nonReentrant whenNotPaused {
        LabTestOrder storage order = labTestOrders[_labTestId];
        if (order.doctor != msg.sender) revert NotAuthorized();
        if (order.status != LabTestStatus.ResultsUploaded) revert InvalidStatus();
        if (_labTestId == 0 || _labTestId > labTestCounter) revert InvalidIndex();
        if (_pharmacy == address(0)) revert InvalidAddress();
        if (!paymentOps.isPharmacyRegistered(_pharmacy) && !paymentOps.hasPharmacyInLocality(_locality)) revert NotAuthorized();
        if (bytes(_medicationIpfsHash).length == 0 || bytes(_prescriptionIpfsHash).length == 0 || bytes(_locality).length == 0) revert InvalidIpfsHash();

        (uint256 price, bool isValid) = paymentOps.getPharmacyPrice(_pharmacy, _medicationIpfsHash);
        order.status = LabTestStatus.Reviewed;
        order.completedTimestamp = uint48(block.timestamp);

        prescriptionCounter = prescriptionCounter + 1;
        uint256 newPrescriptionId = prescriptionCounter;
        bytes32 verificationCodeHash = keccak256(abi.encodePacked(newPrescriptionId, msg.sender, block.timestamp));

        Prescription storage prescription = prescriptions[newPrescriptionId];
        prescription.id = newPrescriptionId;
        prescription.patient = order.patient;
        prescription.doctor = msg.sender;
        prescription.verificationCodeHash = verificationCodeHash;
        prescription.status = PrescriptionStatus.Generated;
        prescription.pharmacy = _pharmacy;
        prescription.generatedTimestamp = uint48(block.timestamp);
        prescription.expirationTimestamp = uint48(block.timestamp + 30 days);
        prescription.medicationIpfsHash = _medicationIpfsHash;

        if (!isValid || price == 0) {
            paymentOps.requestPrescriptionPrice(_pharmacy, _medicationIpfsHash, newPrescriptionId);
        } else {
            prescription.patientCost = price * 120 / base.PERCENTAGE_DENOMINATOR();
            if (msg.value < prescription.patientCost) revert InsufficientFunds();
            prescription.prescriptionIpfsHash = _prescriptionIpfsHash;
            paymentOps.setPrescriptionPayment(newPrescriptionId, true);
            emit PrescriptionPaymentConfirmed(newPrescriptionId, prescription.patientCost);
            if (msg.value > prescription.patientCost) {
                uint256 refund = msg.value - prescription.patientCost;
                paymentOps.safeTransferETH(msg.sender, refund);
            }
        }

        emit PrescriptionIssued(newPrescriptionId, order.patient, msg.sender, verificationCodeHash, uint48(block.timestamp));
        paymentOps.monetizeData(order.patient);
    }

    function setPrescriptionDetails(uint256 _prescriptionId, string calldata _prescriptionIpfsHash)
        external onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
        Prescription storage prescription = prescriptions[_prescriptionId];
        if (_prescriptionId == 0 || _prescriptionId > prescriptionCounter) revert InvalidIndex();
        if (prescription.patient != msg.sender) revert NotAuthorized();
        if (prescription.status != PrescriptionStatus.Generated) revert InvalidStatus();
        if (!paymentOps.getPrescriptionPaymentStatus(_prescriptionId)) revert PaymentNotConfirmed();
        if (bytes(_prescriptionIpfsHash).length == 0) revert InvalidIpfsHash();
        if (bytes(prescription.prescriptionIpfsHash).length != 0) revert InvalidStatus();

        prescription.prescriptionIpfsHash = _prescriptionIpfsHash;
        emit PrescriptionDetailsSet(_prescriptionId, _prescriptionIpfsHash);
    }

    function checkPrescriptionDeadlines(uint256 _prescriptionId) external nonReentrant whenNotPaused {
        Prescription storage prescription = prescriptions[_prescriptionId];
        if (_prescriptionId == 0 || _prescriptionId > prescriptionCounter) revert InvalidIndex();
        if (prescription.status == PrescriptionStatus.Fulfilled ||
            prescription.status == PrescriptionStatus.Revoked ||
            prescription.status == PrescriptionStatus.Expired ||
            prescription.status == PrescriptionStatus.Disputed) return;

        if (prescription.status == PrescriptionStatus.PaymentPending &&
            block.timestamp > paymentOps.getPrescriptionPaymentDeadline(_prescriptionId)) {
            prescription.status = PrescriptionStatus.Expired;
            emit PrescriptionExpired(_prescriptionId);
        } else if ((prescription.status == PrescriptionStatus.Generated || prescription.status == PrescriptionStatus.Verified) &&
                   block.timestamp > prescription.expirationTimestamp) {
            prescription.status = PrescriptionStatus.Expired;
            emit PrescriptionExpired(_prescriptionId);
        }
    }

    function verifyPrescription(uint256 _prescriptionId, bytes32 _verificationCodeHash)
        external onlyRole(core.PHARMACY_ROLE()) nonReentrant whenNotPaused {
        Prescription storage prescription = prescriptions[_prescriptionId];
        if (prescription.pharmacy != msg.sender) revert NotAuthorized();
        if (prescription.status != PrescriptionStatus.Generated) revert InvalidStatus();
        if (prescription.verificationCodeHash != _verificationCodeHash) revert NotAuthorized();
        if (block.timestamp > prescription.expirationTimestamp) revert InvalidTimestamp();
        if (_prescriptionId == 0 || _prescriptionId > prescriptionCounter) revert InvalidIndex();
        if (!paymentOps.getPrescriptionPaymentStatus(_prescriptionId)) revert PaymentNotConfirmed();
        if (bytes(prescription.prescriptionIpfsHash).length == 0) revert InvalidIpfsHash();

        prescription.status = PrescriptionStatus.Verified;
        emit PrescriptionVerified(_prescriptionId, msg.sender);
    }

    function fulfillPrescription(uint256 _prescriptionId)
        external onlyRole(core.PHARMACY_ROLE()) nonReentrant whenNotPaused {
        Prescription storage prescription = prescriptions[_prescriptionId];
        if (prescription.pharmacy != msg.sender) revert NotAuthorized();
        if (prescription.status != PrescriptionStatus.Verified) revert InvalidStatus();
        if (block.timestamp > prescription.expirationTimestamp) revert InvalidTimestamp();
        if (_prescriptionId == 0 || _prescriptionId > prescriptionCounter) revert InvalidIndex();
        if (!paymentOps.getPrescriptionPaymentStatus(_prescriptionId)) revert PaymentNotConfirmed();

        prescription.status = PrescriptionStatus.Fulfilled;
        prescription.disputeWindowEnd = uint48(block.timestamp) + base.disputeWindow();
        emit PrescriptionFulfilled(_prescriptionId);
        emit PrescriptionDisputeWindowStarted(_prescriptionId, prescription.patient, prescription.disputeWindowEnd);
    }

    function orderReplacementPrescription(uint256 _originalPrescriptionId, bytes32 _operationHash)
        external onlyDisputeResolution nonReentrant whenNotPaused onlyMultiSig(_operationHash) {
        bytes32 expectedHash = keccak256(abi.encodePacked(
            "orderReplacementPrescription",
            _originalPrescriptionId,
            msg.sender,
            block.timestamp,
            base.nonces(msg.sender)++
        ));
        if (_operationHash != expectedHash) revert MultiSigNotApproved();

        Prescription storage original = prescriptions[_originalPrescriptionId];
        if (original.status != PrescriptionStatus.Fulfilled) revert InvalidStatus();
        if (original.pharmacy == address(0)) revert InvalidAddress();
        if (_originalPrescriptionId == 0 || _originalPrescriptionId > prescriptionCounter) revert InvalidIndex();

        prescriptionCounter = prescriptionCounter + 1;
        uint256 newPrescriptionId = prescriptionCounter;
        bytes32 newVerificationCodeHash = keccak256(abi.encodePacked(newPrescriptionId, original.doctor, block.timestamp));
        prescriptions[newPrescriptionId] = Prescription({
            id: newPrescriptionId,
            patient: original.patient,
            doctor: original.doctor,
            verificationCodeHash: newVerificationCodeHash,
            status: PrescriptionStatus.Generated,
            pharmacy: original.pharmacy,
            generatedTimestamp: uint48(block.timestamp),
            expirationTimestamp: uint48(block.timestamp + 30 days),
            medicationIpfsHash: original.medicationIpfsHash,
            prescriptionIpfsHash: original.prescriptionIpfsHash,
            patientCost: original.patientCost,
            disputeWindowEnd: 0,
            disputeOutcome: DisputeOutcome.Unresolved
        });
        paymentOps.setPrescriptionPayment(newPrescriptionId, true);

        emit PrescriptionIssued(newPrescriptionId, original.patient, original.doctor, newVerificationCodeHash, uint48(block.timestamp));
        emit ReplacementPrescriptionOrdered(_originalPrescriptionId, newPrescriptionId);
    }

    function requestAISymptomAnalysis(string calldata _symptoms)
        external onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
        if (bytes(_symptoms).length == 0) revert InvalidIpfsHash();
        core.decayPoints(msg.sender);
        TelemedicineCore.Patient storage patient = core.patients(msg.sender);
        bool isFree = patient.gamification.currentLevel == core.maxLevel() &&
                      block.timestamp >= patient.lastFreeAnalysisTimestamp + core.freeAnalysisPeriod();

        aiAnalysisCounter = aiAnalysisCounter + 1;
        aiAnalyses[aiAnalysisCounter] = AISymptomAnalysis(aiAnalysisCounter, msg.sender, false, _symptoms, "");
        patient.gamification.mediPoints = uint96(patient.gamification.mediPoints + core.pointsForActions("aiAnalysis"));
        patient.lastActivityTimestamp = uint48(block.timestamp);

        if (!isFree) {
            if (core.getAIFundBalance() < core.aiAnalysisCost()) revert InsufficientFunds();
            core.aiAnalysisFund = core.aiAnalysisFund - core.aiAnalysisCost();
        } else {
            patient.lastFreeAnalysisTimestamp = uint48(block.timestamp);
            paymentOps.notifyDataRewardClaimed(msg.sender, 0);
        }

        core._levelUp(msg.sender);
        emit AISymptomAnalyzed(aiAnalysisCounter, msg.sender);
        paymentOps.monetizeData(msg.sender);
    }

    function reviewAISymptomAnalysis(uint256 _aiAnalysisId, string calldata _analysisIpfsHash)
        external onlyRole(core.DOCTOR_ROLE()) nonReentrant whenNotPaused {
        AISymptomAnalysis storage analysis = aiAnalyses[_aiAnalysisId];
        if (analysis.doctorReviewed) revert InvalidStatus();
        if (_aiAnalysisId == 0 || _aiAnalysisId > aiAnalysisCounter) revert InvalidIndex();
        if (bytes(_analysisIpfsHash).length == 0) revert InvalidIpfsHash();

        analysis.analysisIpfsHash = _analysisIpfsHash;
        analysis.doctorReviewed = true;
    }

    // Events from paymentOps used here
    event LabTestRefunded(uint256 indexed testId, address patient, uint256 amount);
    event LabTestPaymentConfirmed(uint256 indexed testId, uint256 amount);
    event PrescriptionPaymentConfirmed(uint256 indexed prescriptionId, uint256 amount);

    modifier onlyRole(bytes32 role) {
        if (!core.hasRole(role, msg.sender)) revert NotAuthorized();
        _;
    }

    modifier onlyDisputeResolution() {
        if (msg.sender != address(disputeResolution)) revert NotAuthorized();
        _;
    }

    modifier whenNotPaused() {
        if (core.paused()) revert ContractPaused();
        _;
    }

    modifier onlyMultiSig(bytes32 _operationHash) {
        if (!paymentOps.checkMultiSigApproval(_operationHash)) revert MultiSigNotApproved();
        _;
    }
}
