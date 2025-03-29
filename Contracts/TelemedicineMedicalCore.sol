// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {SafeMathUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";
import {TelemedicineCore} from "./TelemedicineCore.sol";
import {TelemedicinePayments} from "./TelemedicinePayments.sol";
import {TelemedicineDisputeResolution} from "./TelemedicineDisputeResolution.sol";
import {ChainlinkClient} from "@chainlink/contracts/src/v0.8/ChainlinkClient.sol";
import {LinkTokenInterface} from "@chainlink/contracts/src/v0.8/interfaces/LinkTokenInterface.sol";
import {TelemedicineMedicalServices} from "./TelemedicineMedicalServices.sol";

contract TelemedicineMedicalCore is Initializable, ReentrancyGuardUpgradeable, ChainlinkClient {
    using SafeMathUpgradeable for uint256;
    using Chainlink for Chainlink.Request;

    // Custom Errors
    error NotAuthorized();
    error ContractPaused();
    error InvalidAddress();
    error InvalidStatus();
    error InvalidTimestamp();
    error InsufficientFunds();
    error InvalidPageSize();
    error InvalidIndex();
    error InvalidIpfsHash();
    error MultiSigNotApproved();

    // Contract dependencies
    TelemedicineCore public core;
    TelemedicinePayments public payments;
    TelemedicineDisputeResolution public disputeResolution;
    TelemedicineMedicalServices public services;

    // Chainlink Configuration
    address public chainlinkOracle;
    bytes32 public priceListJobId;
    uint256 public chainlinkFee;
    LinkTokenInterface public linkToken;
    uint48 public chainlinkRequestTimeout;

    // Configuration Constants
    uint256 public constant DOCTOR_FEE_PERCENTAGE = 75;
    uint256 public constant RESERVE_FUND_PERCENTAGE = 5;
    uint256 public constant PLATFORM_FEE_PERCENTAGE = 20;
    uint256 public constant PERCENTAGE_DENOMINATOR = 100;
    uint48 public constant DISPUTE_WINDOW = 24 hours;
    uint256 public constant MAX_BATCH_SIZE = 50;
    uint256 public constant CANCELLATION_FEE_PERCENTAGE = 10;
    uint48 public constant REMINDER_INTERVAL = 24 hours;

    // State Variables
    mapping(uint256 => Appointment) public appointments;
    mapping(uint256 => LabTestOrder) public labTestOrders;
    mapping(uint256 => Prescription) public prescriptions;
    mapping(uint256 => AISymptomAnalysis) public aiAnalyses;
    mapping(address => PendingAppointments) public doctorPendingAppointments;
    mapping(uint256 => Reminder) public appointmentReminders;

    address[] public multiSigSigners;
    uint256 public appointmentCounter;
    uint256 public labTestCounter;
    uint256 public prescriptionCounter;
    uint256 public aiAnalysisCounter;
    uint256 public requiredSignatures;

    // Enums
    enum AppointmentStatus { Pending, Confirmed, Completed, Cancelled, Rescheduled, Emergency, Disputed }
    enum LabTestStatus { Requested, Collected, ResultsUploaded, Reviewed, Disputed, Expired }
    enum PrescriptionStatus { Generated, Verified, Fulfilled, Revoked, Expired, Disputed }
    enum DisputeOutcome { Unresolved, PatientFavored, ProviderFavored, MutualAgreement }

    // Structs
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
        string videoCallLink;
        uint48 disputeWindowEnd;
        DisputeOutcome disputeOutcome;
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
        DisputeOutcome disputeOutcome;
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

    struct PendingAppointments {
        mapping(uint256 => uint256) appointmentIds;
        uint256[] ids;
        uint256 count;
    }

    struct Reminder {
        bool active;
        uint48 lastReminderTimestamp;
        uint8 reminderCount;
    }

    // Events
    event AppointmentBooked(uint256 indexed appointmentId, address patient, address[] doctors, uint256 timestamp, string videoCallLink);
    event AppointmentStatusUpdated(uint256 indexed appointmentId, string status);
    event AppointmentCompleted(uint256 indexed appointmentId, string ipfsSummary);
    event LabTestOrdered(uint256 indexed testId, address patient, address doctor, string testTypeIpfsHash, uint48 orderedAt);
    event LabTestCollected(uint256 indexed testId, string ipfsHash);
    event LabTestUploaded(uint256 indexed testId, string ipfsHash);
    event LabTestReviewed(uint256 indexed testId);
    event PrescriptionIssued(uint256 indexed prescriptionId, address patient, address doctor, bytes32 verificationCodeHash, uint48 issuedAt);
    event PrescriptionVerified(uint256 indexed prescriptionId, address pharmacy);
    event PrescriptionFulfilled(uint256 indexed prescriptionId);
    event PrescriptionRevoked(uint256 indexed prescriptionId);
    event PrescriptionExpired(uint256 indexed prescriptionId);
    event AISymptomAnalyzed(uint256 indexed id, address indexed patient);
    event VideoCallStarted(uint256 indexed appointmentId, string videoCallLink);
    event BatchAppointmentsConfirmed(address indexed doctor, uint256[] appointmentIds);
    event DoctorPaid(uint256 indexed appointmentId, address indexed doctor, uint256 amount, TelemedicinePayments.PaymentType paymentType);
    event ReserveFundAllocated(uint256 indexed appointmentId, uint256 amount, TelemedicinePayments.PaymentType paymentType);
    event PlatformFeeAllocated(uint256 indexed appointmentId, uint256 amount, TelemedicinePayments.PaymentType paymentType);
    event ReplacementPrescriptionOrdered(uint256 indexed originalPrescriptionId, uint256 indexed newPrescriptionId);
    event AppointmentReminderSent(uint256 indexed appointmentId, address patient, uint48 timestamp);
    event CancellationFeeCharged(uint256 indexed appointmentId, uint256 amount);

    // Initialization
    function initialize(
        address _core,
        address _payments,
        address _disputeResolution,
        address _services,
        address _chainlinkOracle,
        bytes32 _priceListJobId,
        address _linkToken,
        address[] memory _multiSigSigners,
        uint256 _requiredSignatures
    ) external initializer {
        if (_core == address(0) || _payments == address(0) || _disputeResolution == address(0) || 
            _services == address(0) || _chainlinkOracle == address(0) || _linkToken == address(0)) revert InvalidAddress();
        if (_multiSigSigners.length < _requiredSignatures || _requiredSignatures == 0) revert InvalidAddress();

        __ReentrancyGuard_init();
        core = TelemedicineCore(_core);
        payments = TelemedicinePayments(_payments);
        disputeResolution = TelemedicineDisputeResolution(_disputeResolution);
        services = TelemedicineMedicalServices(_services);
        chainlinkOracle = _chainlinkOracle;
        priceListJobId = _priceListJobId;
        linkToken = LinkTokenInterface(_linkToken);
        setChainlinkToken(_linkToken);
        chainlinkFee = 0.1 ether;
        chainlinkRequestTimeout = 30 minutes;
        multiSigSigners = _multiSigSigners;
        requiredSignatures = _requiredSignatures;
    }

    // Appointment Functions
    function bookAppointment(
        address[] calldata _doctors,
        uint48 _timestamp,
        TelemedicinePayments.PaymentType _paymentType,
        bool _isVideoCall,
        string calldata _videoCallLink
    ) external payable onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
        if (_doctors.length == 0) revert InvalidAddress();
        for (uint256 i = 0; i < _doctors.length; i++) {
            if (_doctors[i] == address(0) || !core.doctors(_doctors[i]).isVerified) revert NotAuthorized();
        }
        if (_timestamp <= block.timestamp.add(core.minBookingBuffer())) revert InvalidTimestamp();

        core.decayPoints(msg.sender);
        uint256 baseFee = 0;
        for (uint256 i = 0; i < _doctors.length; i++) {
            baseFee = baseFee.add(core.getDoctorFee(_doctors[i]));
        }
        uint256 discountedFee = core._applyFeeDiscount(msg.sender, baseFee);
        if (discountedFee > type(uint96).max) revert InsufficientFunds();
        bool isPriority = core._isPriorityBooking(msg.sender);

        uint256 reserveAmount = discountedFee.mul(RESERVE_FUND_PERCENTAGE).div(PERCENTAGE_DENOMINATOR);
        uint256 platformAmount = discountedFee.mul(PLATFORM_FEE_PERCENTAGE).div(PERCENTAGE_DENOMINATOR);
        uint256 doctorAmount = discountedFee.sub(reserveAmount).sub(platformAmount);

        appointmentCounter = appointmentCounter.add(1);
        uint256 newAppointmentId = appointmentCounter;

        if (_paymentType == TelemedicinePayments.PaymentType.ETH) {
            if (msg.value < discountedFee) revert InsufficientFunds();
            core.reserveFund = core.reserveFund.add(reserveAmount);
            emit ReserveFundAllocated(newAppointmentId, reserveAmount, _paymentType);
            emit PlatformFeeAllocated(newAppointmentId, platformAmount, _paymentType);
            if (msg.value > discountedFee) {
                uint256 refund = msg.value.sub(discountedFee);
                (bool success, ) = msg.sender.call{value: refund}("");
                if (!success) revert("ETH refund failed");
            }
        } else {
            payments._processPayment(_paymentType, discountedFee);
            if (_paymentType == TelemedicinePayments.PaymentType.USDC) {
                if (!payments.usdcToken().transfer(address(core), reserveAmount)) revert("USDC reserve transfer failed");
                core.reserveFund = core.reserveFund.add(reserveAmount);
            } else if (_paymentType == TelemedicinePayments.PaymentType.SONIC) {
                if (!payments.sonicToken().transfer(address(core), reserveAmount)) revert("SONIC reserve transfer failed");
                core.reserveFund = core.reserveFund.add(reserveAmount);
            }
            emit ReserveFundAllocated(newAppointmentId, reserveAmount, _paymentType);
            emit PlatformFeeAllocated(newAppointmentId, platformAmount, _paymentType);
        }

        appointments[newAppointmentId] = Appointment(
            newAppointmentId,
            msg.sender,
            _doctors,
            _timestamp,
            AppointmentStatus.Pending,
            uint96(discountedFee),
            _paymentType,
            _isVideoCall,
            isPriority,
            _isVideoCall ? _videoCallLink : "",
            0,
            DisputeOutcome.Unresolved
        );
        
        for (uint256 i = 0; i < _doctors.length; i++) {
            _addPendingAppointment(_doctors[i], newAppointmentId);
        }
        
        appointmentReminders[newAppointmentId] = Reminder(true, 0, 0);
        TelemedicineCore.Patient storage patient = core.patients(msg.sender);
        patient.gamification.mediPoints = uint96(patient.gamification.mediPoints.add(core.pointsForActions("appointment")));
        patient.lastActivityTimestamp = uint48(block.timestamp);
        core._levelUp(msg.sender);
        emit AppointmentBooked(newAppointmentId, msg.sender, _doctors, _timestamp, _videoCallLink);
    }

    function cancelAppointment(uint256 _appointmentId) external onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
        Appointment storage apt = appointments[_appointmentId];
        if (apt.patient != msg.sender) revert NotAuthorized();
        if (apt.status != AppointmentStatus.Pending && apt.status != AppointmentStatus.Confirmed) revert InvalidStatus();
        if (_appointmentId == 0 || _appointmentId > appointmentCounter) revert InvalidIndex();

        uint256 cancellationFee = 0;
        if (apt.scheduledTimestamp <= block.timestamp.add(core.minCancellationBuffer())) {
            cancellationFee = uint256(apt.fee).mul(CANCELLATION_FEE_PERCENTAGE).div(PERCENTAGE_DENOMINATOR);
            emit CancellationFeeCharged(_appointmentId, cancellationFee);
        }

        apt.status = AppointmentStatus.Cancelled;
        for (uint256 i = 0; i < apt.doctors.length; i++) {
            _removePendingAppointment(apt.doctors[i], _appointmentId);
        }
        appointmentReminders[_appointmentId].active = false;
        payments._refundPatient(apt.patient, apt.fee.sub(cancellationFee), apt.paymentType);
        emit AppointmentStatusUpdated(_appointmentId, "Cancelled");
    }

    function rescheduleAppointment(uint256 _appointmentId, uint48 _newTimestamp) 
        external 
        onlyRole(core.PATIENT_ROLE()) 
        nonReentrant 
        whenNotPaused 
    {
        Appointment storage apt = appointments[_appointmentId];
        if (apt.patient != msg.sender) revert NotAuthorized();
        if (apt.status != AppointmentStatus.Pending && apt.status != AppointmentStatus.Confirmed) revert InvalidStatus();
        if (_newTimestamp <= block.timestamp.add(core.minBookingBuffer())) revert InvalidTimestamp();
        if (_appointmentId == 0 || _appointmentId > appointmentCounter) revert InvalidIndex();

        apt.scheduledTimestamp = _newTimestamp;
        apt.status = AppointmentStatus.Rescheduled;
        appointmentReminders[_appointmentId].lastReminderTimestamp = 0;
        emit AppointmentStatusUpdated(_appointmentId, "Rescheduled");
    }

    function confirmAppointment(uint256 _appointmentId, bool _overridePriority) 
        public 
        onlyRole(core.DOCTOR_ROLE()) 
        whenNotPaused 
    {
        Appointment storage apt = appointments[_appointmentId];
        bool isDoctor = false;
        for (uint256 i = 0; i < apt.doctors.length; i++) {
            if (apt.doctors[i] == msg.sender) {
                isDoctor = true;
                break;
            }
        }
        if (!isDoctor) revert NotAuthorized();
        if (apt.status != AppointmentStatus.Pending) revert InvalidStatus();
        if (_appointmentId == 0 || _appointmentId > appointmentCounter) revert InvalidIndex();

        if (_overridePriority) {
            if (!core.hasRole(core.ADMIN_ROLE(), msg.sender)) revert NotAuthorized();
        } else if (!apt.isPriority) {
            if (_hasPendingPriorityAppointments(msg.sender)) revert InvalidStatus();
        }

        apt.status = AppointmentStatus.Confirmed;
        _removePendingAppointment(msg.sender, _appointmentId);
        if (apt.isVideoCall) emit VideoCallStarted(_appointmentId, apt.videoCallLink);
        emit AppointmentStatusUpdated(_appointmentId, "Confirmed");
    }

    function batchConfirmAppointments(uint256[] calldata _appointmentIds) 
        external 
        onlyRole(core.DOCTOR_ROLE()) 
        whenNotPaused 
    {
        if (_appointmentIds.length > core.MAX_PENDING_APPOINTMENTS()) revert InvalidPageSize();
        for (uint256 i = 0; i < _appointmentIds.length; i = i.add(1)) {
            if (_appointmentIds[i] == 0 || _appointmentIds[i] > appointmentCounter) revert InvalidIndex();
            Appointment storage apt = appointments[_appointmentIds[i]];
            bool isDoctor = false;
            for (uint256 j = 0; j < apt.doctors.length; j++) {
                if (apt.doctors[j] == msg.sender) {
                    isDoctor = true;
                    break;
                }
            }
            if (!isDoctor) revert NotAuthorized();
            if (apt.status != AppointmentStatus.Pending) continue;
            apt.status = AppointmentStatus.Confirmed;
            _removePendingAppointment(msg.sender, _appointmentIds[i]);
            if (apt.isVideoCall) emit VideoCallStarted(_appointmentIds[i], apt.videoCallLink);
            emit AppointmentStatusUpdated(_appointmentIds[i], "Confirmed");
        }
        emit BatchAppointmentsConfirmed(msg.sender, _appointmentIds);
    }

    function completeAppointment(uint256 _appointmentId, string calldata _ipfsSummary, bytes32 _operationHash) 
        external 
        onlyRole(core.DOCTOR_ROLE()) 
        nonReentrant 
        whenNotPaused 
        onlyMultiSig(_operationHash)
    {
        Appointment storage apt = appointments[_appointmentId];
        bool isDoctor = false;
        for (uint256 i = 0; i < apt.doctors.length; i++) {
            if (apt.doctors[i] == msg.sender) {
                isDoctor = true;
                break;
            }
        }
        if (!isDoctor) revert NotAuthorized();
        if (apt.status != AppointmentStatus.Confirmed) revert InvalidStatus();
        if (apt.scheduledTimestamp > block.timestamp) revert InvalidTimestamp();
        if (_appointmentId == 0 || _appointmentId > appointmentCounter) revert InvalidIndex();
        if (disputeResolution.isDisputed(_appointmentId)) {
            DisputeOutcome outcome = disputeResolution.getDisputeOutcome(_appointmentId);
            if (outcome == DisputeOutcome.Unresolved) revert InvalidStatus();
            apt.disputeOutcome = outcome;
            services.notifyDisputeResolved(_appointmentId, "Appointment", outcome);
        }

        uint256 doctorPayment = uint256(apt.fee).mul(DOCTOR_FEE_PERCENTAGE).div(PERCENTAGE_DENOMINATOR).div(apt.doctors.length);
        for (uint256 i = 0; i < apt.doctors.length; i++) {
            if (apt.paymentType == TelemedicinePayments.PaymentType.ETH) {
                if (address(this).balance < doctorPayment) revert InsufficientFunds();
                (bool success, ) = apt.doctors[i].call{value: doctorPayment}("");
                if (!success) revert("ETH payment failed");
            } else if (apt.paymentType == TelemedicinePayments.PaymentType.USDC) {
                if (payments.usdcToken().balanceOf(address(this)) < doctorPayment) revert InsufficientFunds();
                if (!payments.usdcToken().transfer(apt.doctors[i], doctorPayment)) revert("USDC payment failed");
            } else if (apt.paymentType == TelemedicinePayments.PaymentType.SONIC) {
                if (payments.sonicToken().balanceOf(address(this)) < doctorPayment) revert InsufficientFunds();
                if (!payments.sonicToken().transfer(apt.doctors[i], doctorPayment)) revert("SONIC payment failed");
            }
            emit DoctorPaid(_appointmentId, apt.doctors[i], doctorPayment, apt.paymentType);
        }

        apt.status = AppointmentStatus.Completed;
        apt.disputeWindowEnd = uint48(block.timestamp) + DISPUTE_WINDOW;
        appointmentReminders[_appointmentId].active = false;
        emit AppointmentStatusUpdated(_appointmentId, "Completed");
        emit AppointmentCompleted(_appointmentId, _ipfsSummary);
    }

    // Reminder System
    function triggerAppointmentReminder(uint256 _appointmentId) external whenNotPaused {
        Appointment storage apt = appointments[_appointmentId];
        Reminder storage reminder = appointmentReminders[_appointmentId];
        
        if (_appointmentId == 0 || _appointmentId > appointmentCounter) revert InvalidIndex();
        if (apt.status != AppointmentStatus.Confirmed) revert InvalidStatus();
        if (!reminder.active) revert InvalidStatus();
        if (apt.scheduledTimestamp <= block.timestamp) revert InvalidTimestamp();
        if (reminder.lastReminderTimestamp + REMINDER_INTERVAL > block.timestamp) revert InvalidTimestamp();
        if (reminder.reminderCount >= 3) revert InvalidStatus();

        reminder.lastReminderTimestamp = uint48(block.timestamp);
        reminder.reminderCount = reminder.reminderCount + 1;
        emit AppointmentReminderSent(_appointmentId, apt.patient, uint48(block.timestamp));
    }

    // Lab Test Functions
    function orderLabTest(address _patient, string calldata _testTypeIpfsHash, address _labTech) 
        external 
        onlyRole(core.DOCTOR_ROLE()) 
        nonReentrant 
        whenNotPaused 
    {
        if (_patient == address(0) || _labTech == address(0)) revert InvalidAddress();
        if (!core.patients(_patient).isRegistered) revert NotAuthorized();
        if (!services.isLabTechRegistered(_labTech)) revert NotAuthorized();
        if (bytes(_testTypeIpfsHash).length == 0) revert InvalidIpfsHash();

        (uint256 price, bool isValid) = services.getLabTechPrice(_labTech, _testTypeIpfsHash);
        if (!isValid) revert InvalidStatus();

        labTestCounter = labTestCounter.add(1);
        uint256 patientCost = price.mul(120).div(PERCENTAGE_DENOMINATOR); // 20% markup
        labTestOrders[labTestCounter] = LabTestOrder(
            labTestCounter,
            _patient,
            msg.sender,
            _labTech,
            LabTestStatus.Requested,
            uint48(block.timestamp),
            0,
            _testTypeIpfsHash,
            "",
            "",
            patientCost,
            0,
            DisputeOutcome.Unresolved
        );
        emit LabTestOrdered(labTestCounter, _patient, msg.sender, _testTypeIpfsHash, uint48(block.timestamp));
        services.monetizeData(_patient);
    }

    function collectSample(uint256 _labTestId, string calldata _ipfsHash) 
        external 
        onlyRole(core.LAB_TECH_ROLE()) 
        nonReentrant 
        whenNotPaused 
    {
        LabTestOrder storage order = labTestOrders[_labTestId];
        if (order.status != LabTestStatus.Requested) revert InvalidStatus();
        if (order.labTech != msg.sender) revert NotAuthorized();
        if (_labTestId == 0 || _labTestId > labTestCounter) revert InvalidIndex();
        if (bytes(_ipfsHash).length == 0) revert InvalidIpfsHash();

        order.sampleCollectionIpfsHash = _ipfsHash;
        order.status = LabTestStatus.Collected;
        emit LabTestCollected(_labTestId, _ipfsHash);
    }

    function uploadLabResults(uint256 _labTestId, string calldata _resultsIpfsHash) 
        external 
        onlyRole(core.LAB_TECH_ROLE()) 
        nonReentrant 
        whenNotPaused 
    {
        LabTestOrder storage order = labTestOrders[_labTestId];
        if (order.labTech != msg.sender) revert NotAuthorized();
        if (order.status != LabTestStatus.Collected) revert InvalidStatus();
        if (_labTestId == 0 || _labTestId > labTestCounter) revert InvalidIndex();
        if (bytes(_resultsIpfsHash).length == 0) revert InvalidIpfsHash();

        order.resultsIpfsHash = _resultsIpfsHash;
        order.status = LabTestStatus.ResultsUploaded;
        order.disputeWindowEnd = uint48(block.timestamp) + DISPUTE_WINDOW;
        emit LabTestUploaded(_labTestId, _resultsIpfsHash);
        services.monetizeData(order.patient);
    }

    function reviewLabResults(uint256 _labTestId, string calldata _medicationIpfsHash, string calldata _prescriptionIpfsHash, address _pharmacy) 
        external 
        onlyRole(core.DOCTOR_ROLE()) 
        nonReentrant 
        whenNotPaused 
    {
        LabTestOrder storage order = labTestOrders[_labTestId];
        if (order.doctor != msg.sender) revert NotAuthorized();
        if (order.status != LabTestStatus.ResultsUploaded) revert InvalidStatus();
        if (_labTestId == 0 || _labTestId > labTestCounter) revert InvalidIndex();
        if (_pharmacy == address(0)) revert InvalidAddress();
        if (!services.isPharmacyRegistered(_pharmacy)) revert NotAuthorized();
        if (bytes(_medicationIpfsHash).length == 0 || bytes(_prescriptionIpfsHash).length == 0) revert InvalidIpfsHash();

        (uint256 price, bool isValid) = services.getPharmacyPrice(_pharmacy, _medicationIpfsHash);
        if (!isValid) revert InvalidStatus();

        order.status = LabTestStatus.Reviewed;
        order.completedTimestamp = uint48(block.timestamp);

        prescriptionCounter = prescriptionCounter.add(1);
        uint256 patientCost = price.mul(120).div(PERCENTAGE_DENOMINATOR); // 20% markup
        bytes32 verificationCodeHash = keccak256(abi.encodePacked(prescriptionCounter, msg.sender, block.timestamp));
        prescriptions[prescriptionCounter] = Prescription(
            prescriptionCounter,
            order.patient,
            msg.sender,
            verificationCodeHash,
            PrescriptionStatus.Generated,
            _pharmacy,
            uint48(block.timestamp),
            uint48(block.timestamp.add(30 days)),
            _medicationIpfsHash,
            _prescriptionIpfsHash,
            patientCost,
            0,
            DisputeOutcome.Unresolved
        );
        emit PrescriptionIssued(prescriptionCounter, order.patient, msg.sender, verificationCodeHash, uint48(block.timestamp));
        services.monetizeData(order.patient);
    }

    // Prescription Functions
    function verifyPrescription(uint256 _prescriptionId, bytes32 _verificationCodeHash) 
        external 
        onlyRole(core.PHARMACY_ROLE()) 
        nonReentrant 
        whenNotPaused 
    {
        Prescription storage prescription = prescriptions[_prescriptionId];
        if (prescription.pharmacy != msg.sender) revert NotAuthorized();
        if (prescription.status != PrescriptionStatus.Generated) revert InvalidStatus();
        if (prescription.verificationCodeHash != _verificationCodeHash) revert NotAuthorized();
        if (block.timestamp > prescription.expirationTimestamp) revert InvalidTimestamp();
        if (_prescriptionId == 0 || _prescriptionId > prescriptionCounter) revert InvalidIndex();

        prescription.status = PrescriptionStatus.Verified;
        emit PrescriptionVerified(_prescriptionId, msg.sender);
    }

    function fulfillPrescription(uint256 _prescriptionId) 
        external 
        onlyRole(core.PHARMACY_ROLE()) 
        nonReentrant 
        whenNotPaused 
    {
        Prescription storage prescription = prescriptions[_prescriptionId];
        if (prescription.pharmacy != msg.sender) revert NotAuthorized();
        if (prescription.status != PrescriptionStatus.Verified) revert InvalidStatus();
        if (block.timestamp > prescription.expirationTimestamp) revert InvalidTimestamp();
        if (_prescriptionId == 0 || _prescriptionId > prescriptionCounter) revert InvalidIndex();

        prescription.status = PrescriptionStatus.Fulfilled;
        prescription.disputeWindowEnd = uint48(block.timestamp) + DISPUTE_WINDOW;
        emit PrescriptionFulfilled(_prescriptionId);
    }

    function orderReplacementPrescription(uint256 _originalPrescriptionId) 
        external 
        onlyDisputeResolution 
        nonReentrant 
        whenNotPaused 
    {
        Prescription storage original = prescriptions[_originalPrescriptionId];
        if (original.status != PrescriptionStatus.Fulfilled) revert InvalidStatus();
        if (original.pharmacy == address(0)) revert InvalidAddress();
        if (_originalPrescriptionId == 0 || _originalPrescriptionId > prescriptionCounter) revert InvalidIndex();

        prescriptionCounter = prescriptionCounter.add(1);
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
            expirationTimestamp: uint48(block.timestamp.add(30 days)),
            medicationIpfsHash: original.medicationIpfsHash,
            prescriptionIpfsHash: original.prescriptionIpfsHash,
            patientCost: original.patientCost,
            disputeWindowEnd: 0,
            disputeOutcome: DisputeOutcome.Unresolved
        });

        emit PrescriptionIssued(newPrescriptionId, original.patient, original.doctor, newVerificationCodeHash, uint48(block.timestamp));
        emit ReplacementPrescriptionOrdered(_originalPrescriptionId, newPrescriptionId);
    }

    // AI Symptom Analysis
    function requestAISymptomAnalysis(string calldata _symptoms) 
        external 
        onlyRole(core.PATIENT_ROLE()) 
        nonReentrant 
        whenNotPaused 
    {
        if (bytes(_symptoms).length == 0) revert InvalidIpfsHash();
        core.decayPoints(msg.sender);
        TelemedicineCore.Patient storage patient = core.patients(msg.sender);
        bool isFree = patient.gamification.currentLevel == core.maxLevel() && 
                      block.timestamp >= patient.lastFreeAnalysisTimestamp.add(core.freeAnalysisPeriod());

        if (!isFree) {
            if (core.getAIFundBalance() < core.aiAnalysisCost()) revert InsufficientFunds();
            core.aiAnalysisFund = core.aiAnalysisFund.sub(core.aiAnalysisCost());
        } else {
            patient.lastFreeAnalysisTimestamp = uint48(block.timestamp);
            services.notifyDataRewardClaimed(msg.sender, 0);
        }

        aiAnalysisCounter = aiAnalysisCounter.add(1);
        aiAnalyses[aiAnalysisCounter] = AISymptomAnalysis(aiAnalysisCounter, msg.sender, false, _symptoms, "");
        patient.gamification.mediPoints = uint96(patient.gamification.mediPoints.add(core.pointsForActions("aiAnalysis")));
        patient.lastActivityTimestamp = uint48(block.timestamp);
        core._levelUp(msg.sender);
        emit AISymptomAnalyzed(aiAnalysisCounter, msg.sender);
        services.monetizeData(msg.sender);
    }

    function reviewAISymptomAnalysis(uint256 _aiAnalysisId, string calldata _analysisIpfsHash) 
        external 
        onlyRole(core.DOCTOR_ROLE()) 
        nonReentrant 
        whenNotPaused 
    {
        AISymptomAnalysis storage analysis = aiAnalyses[_aiAnalysisId];
        if (analysis.doctorReviewed) revert InvalidStatus();
        if (_aiAnalysisId == 0 || _aiAnalysisId > aiAnalysisCounter) revert InvalidIndex();
        if (bytes(_analysisIpfsHash).length == 0) revert InvalidIpfsHash();

        analysis.analysisIpfsHash = _analysisIpfsHash;
        analysis.doctorReviewed = true;
    }

    // Internal Functions
    function _addPendingAppointment(address _doctor, uint256 _appointmentId) internal {
        PendingAppointments storage pending = doctorPendingAppointments[_doctor];
        if (pending.count >= core.MAX_PENDING_APPOINTMENTS()) revert InvalidPageSize();
        pending.appointmentIds[_appointmentId] = pending.count;
        pending.ids.push(_appointmentId);
        pending.count = pending.count.add(1);
    }

    function _removePendingAppointment(address _doctor, uint256 _appointmentId) internal {
        PendingAppointments storage pending = doctorPendingAppointments[_doctor];
        uint256 index = pending.appointmentIds[_appointmentId];
        if (index >= pending.count) revert InvalidIndex();

        if (index != pending.count.sub(1)) {
            uint256 lastId = pending.ids[pending.count.sub(1)];
            pending.ids[index] = lastId;
            pending.appointmentIds[lastId] = index;
        }
        pending.ids.pop();
        delete pending.appointmentIds[_appointmentId];
        pending.count = pending.count.sub(1);
    }

    function _hasPendingPriorityAppointments(address _doctor) internal view returns (bool) {
        PendingAppointments storage pending = doctorPendingAppointments[_doctor];
        for (uint256 i = 0; i < pending.count; i = i.add(1)) {
            if (appointments[pending.ids[i]].isPriority) return true;
        }
        return false;
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

    modifier whenNotPaused() {
        if (core.paused()) revert ContractPaused();
        _;
    }

    modifier onlyMultiSig(bytes32 _operationHash) {
        if (!services.checkMultiSigApproval(_operationHash)) revert MultiSigNotApproved();
        _;
    }

    // Fallback
    receive() external payable {}
}
