// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import {SafeMathUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";
import {AddressUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/AddressUpgradeable.sol";
import {IERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import {SafeERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import {ChainlinkClient, Chainlink} from "@chainlink/contracts/src/v0.8/ChainlinkClient.sol";
import "./TelemedicineCore.sol";

/// @title TelemedicineOperations
/// @notice Manages appointments, lab tests, prescriptions, AI analyses, payment queues, and provider invitations
/// @dev UUPS upgradeable, integrates with Chainlink, and uses SafeERC20 for token transfers
contract TelemedicineOperations is Initializable, UUPSUpgradeable, ReentrancyGuardUpgradeable, PausableUpgradeable, ChainlinkClient {
    using SafeMathUpgradeable for uint256;
    using AddressUpgradeable for address payable;
    using Chainlink for Chainlink.Request;
    using SafeERC20Upgradeable for IERC20Upgradeable;

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
    error DeadlineMissed();
    error NoLabTechAvailable();
    error PaymentFailed();
    error OracleResponseInvalid();
    error InvalidLocality();
    error InvitationAlreadyExists();
    error ProvidersAlreadyExist();
    error PaymentNotConfirmed();
    error PaymentDeadlineMissed();
    error InvitationExpired();
    error ChainlinkRequestTimeout();
    error ExternalCallFailed();
    error InvalidNonce();

    // Constants
    uint256 public constant RESERVE_FUND_THRESHOLD = 1 ether;
    uint256 public constant MIN_IPFS_HASH_LENGTH = 46; // New: Standard IPFS hash length
    uint48 public constant CHAINLINK_TIMEOUT = 1 hours; // New: Chainlink request timeout
    uint256 public constant MAX_DOCTORS_PER_APPOINTMENT = 5; // New: Limit doctors per appointment

    // Configurable Parameters
    uint256 public maxPendingAppointments; // New: Configurable instead of hardcoded
    uint48 public chainlinkTimeout; // New: Configurable Chainlink timeout

    // State Variables
    mapping(uint256 => Appointment) public appointments;
    mapping(uint256 => LabTestOrder) public labTestOrders;
    mapping(uint256 => Prescription) public prescriptions;
    mapping(uint256 => AISymptomAnalysis) public aiAnalyses;
    mapping(address => PendingAppointments) public doctorPendingAppointments;
    mapping(uint256 => Reminder) public appointmentReminders;
    mapping(address => uint256) public nonces;
    mapping(uint256 => bool) public labTestPayments;
    mapping(uint256 => uint48) public labTestPaymentDeadlines;
    mapping(uint256 => bool) public prescriptionPayments;
    mapping(uint256 => uint48) public prescriptionPaymentDeadlines;
    uint256 public appointmentCounter;
    uint256 public labTestCounter;
    uint256 public prescriptionCounter;
    uint256 public aiAnalysisCounter;
    uint256 public versionNumber; // New: Track contract version

    // Payment Queue
    struct PendingPayment {
        address recipient;
        uint256 amount;
        TelemedicinePayments.PaymentType paymentType;
        bool processed;
    }
    mapping(uint256 => PendingPayment) public pendingPayments;
    uint256 public pendingPaymentCounter;

    // Invitation Mechanism
    struct Invitation {
        address patient;
        string locality;
        bytes32 inviteeContactHash; // Updated: Store hash
        bool isLabTech;
        bool fulfilled;
        uint48 expirationTimestamp;
    }
    mapping(bytes32 => Invitation) public invitations;
    uint256 public invitationCounter;

    // Chainlink Configuration
    mapping(bytes32 => uint256) public requestToLabTestId;
    mapping(bytes32 => uint256) public requestToPrescriptionId;
    mapping(bytes32 => uint48) public requestTimestamps;

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
        bytes32 videoCallLinkHash; // Updated: Store hash
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

    struct PendingAppointments {
        uint256[] ids; // Updated: Simplified to array
        mapping(uint256 => uint256) indices; // New: Track indices for removal
    }

    struct Reminder {
        bool active;
        uint48 lastReminderTimestamp;
        uint8 reminderCount;
    }

    // Enums
    enum AppointmentStatus { Pending, Confirmed, Completed, Cancelled, Rescheduled, Emergency, Disputed }
    enum LabTestStatus { Requested, PaymentPending, Collected, ResultsUploaded, Reviewed, Disputed, Expired }
    enum PrescriptionStatus { Generated, PaymentPending, Verified, Fulfilled, Revoked, Expired, Disputed }
    enum DisputeOutcome { Unresolved, PatientFavored, ProviderFavored, MutualAgreement }

    // External Contracts
    TelemedicineCore public core;
    TelemedicinePayments public payments;
    TelemedicineDisputeResolution public disputeResolution;
    TelemedicineMedicalServices public services;

    // Events
    event AppointmentBooked(uint256 indexed appointmentId, address patient, address[] doctors, uint256 timestamp);
    event AppointmentStatusUpdated(uint256 indexed appointmentId, string status);
    event AppointmentCompleted(uint256 indexed appointmentId, string ipfsSummary);
    event LabTestOrdered(uint256 indexed testId, address patient, address doctor, string testTypeIpfsHash, uint48 orderedAt);
    event LabTestCollected(uint256 indexed testId, string ipfsHash);
    event LabTestUploaded(uint256 indexed testId, string ipfsHash);
    event LabTestReviewed(uint256 indexed testId);
    event PrescriptionIssued(uint256 indexed prescriptionId, address patient, address doctor, bytes32 verificationCodeHash, uint48 issuedAt);
    event PrescriptionVerified(uint256 indexed prescriptionId, address pharmacy);
    event PrescriptionFulfilled(uint256 indexed prescriptionId);
    event DoctorPaid(uint256 indexed appointmentId, address indexed doctor, uint256 amount, TelemedicinePayments.PaymentType paymentType);
    event ReserveFundAllocated(uint256 indexed appointmentId, uint256 amount, TelemedicinePayments.PaymentType paymentType);
    event PlatformFeeAllocated(uint256 indexed appointmentId, uint256 amount, TelemedicinePayments.PaymentType paymentType);
    event InvitationSubmitted(bytes32 indexed invitationId, address patient, string locality, bool isLabTech);
    event InvitationFulfilled(bytes32 indexed invitationId, address invitee);
    event InvitationExpired(bytes32 indexed invitationId);
    event LabTestPaymentConfirmed(uint256 indexed testId, uint256 amount);
    event PrescriptionPaymentConfirmed(uint256 indexed prescriptionId, uint256 amount);
    event PaymentQueued(uint256 indexed paymentId, address recipient, uint256 amount, TelemedicinePayments.PaymentType paymentType);
    event PaymentReleasedFromQueue(uint256 indexed paymentId, address recipient, uint256 amount);
    event MaxPendingAppointmentsUpdated(uint256 newMax); // New: Configurable max
    event ChainlinkTimeoutUpdated(uint48 newTimeout); // New: Configurable timeout

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the contract with external dependencies
    /// @param _core Address of TelemedicineCore
    /// @param _payments Address of TelemedicinePayments
    /// @param _disputeResolution Address of TelemedicineDisputeResolution
    /// @param _services Address of TelemedicineMedicalServices
    function initialize(
        address _core,
        address _payments,
        address _disputeResolution,
        address _services
    ) external initializer {
        if (_core == address(0) || _payments == address(0) || _disputeResolution == address(0) || _services == address(0)) revert InvalidAddress();

        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        __Pausable_init();
        setChainlinkToken(address(TelemedicineCore(_core).linkToken()));

        core = TelemedicineCore(_core);
        payments = TelemedicinePayments(_payments);
        disputeResolution = TelemedicineDisputeResolution(_disputeResolution);
        services = TelemedicineMedicalServices(_services);

        appointmentCounter = 0;
        labTestCounter = 0;
        prescriptionCounter = 0;
        aiAnalysisCounter = 0;
        invitationCounter = 0;
        pendingPaymentCounter = 0;
        maxPendingAppointments = 100; // New: Configurable default
        chainlinkTimeout = CHAINLINK_TIMEOUT; // New: Configurable default
        versionNumber = 1;

        emit MaxPendingAppointmentsUpdated(100);
        emit ChainlinkTimeoutUpdated(CHAINLINK_TIMEOUT);
    }

    /// @notice Authorizes contract upgrades (admin only)
    function _authorizeUpgrade(address newImplementation) internal override onlyRole(core.ADMIN_ROLE()) {
        versionNumber = versionNumber.add(1);
    }

    /// @notice Updates max pending appointments (admin only)
    /// @param _newMax New maximum (minimum 10)
    function updateMaxPendingAppointments(uint256 _newMax) external onlyRole(core.ADMIN_ROLE()) {
        if (_newMax < 10) revert InvalidPageSize();
        maxPendingAppointments = _newMax;
        emit MaxPendingAppointmentsUpdated(_newMax);
    }

    /// @notice Updates Chainlink request timeout (admin only)
    /// @param _newTimeout New timeout in seconds (minimum 30 minutes)
    function updateChainlinkTimeout(uint48 _newTimeout) external onlyRole(core.ADMIN_ROLE()) {
        if (_newTimeout < 30 minutes) revert InvalidTimestamp();
        chainlinkTimeout = _newTimeout;
        emit ChainlinkTimeoutUpdated(_newTimeout);
    }

    // Appointment Functions

    /// @notice Books an appointment with multiple doctors
    /// @param _doctors Array of doctor addresses
    /// @param _timestamp Scheduled timestamp
    /// @param _paymentType Payment type (ETH, USDC, SONIC)
    /// @param _isVideoCall Whether it's a video call
    /// @param _videoCallLinkHash Hash of the video call link
    function bookAppointment(
        address[] calldata _doctors,
        uint48 _timestamp,
        TelemedicinePayments.PaymentType _paymentType,
        bool _isVideoCall,
        bytes32 _videoCallLinkHash
    ) external payable onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
        if (_doctors.length == 0 || _doctors.length > MAX_DOCTORS_PER_APPOINTMENT) revert InvalidAddress();
        for (uint256 i = 0; i < _doctors.length; i++) {
            if (_doctors[i] == address(0) || !core.doctors(_doctors[i]).isVerified) revert NotAuthorized();
        }
        if (_timestamp <= block.timestamp + core.minBookingBuffer()) revert InvalidTimestamp();
        if (_isVideoCall && _videoCallLinkHash == bytes32(0)) revert InvalidIpfsHash();

        core.decayPoints(msg.sender);
        uint256 baseFee = 0;
        for (uint256 i = 0; i < _doctors.length; i++) {
            baseFee = baseFee.add(core.doctors(_doctors[i]).consultationFee);
        }
        uint256 discountedFee = core._applyFeeDiscount(msg.sender, baseFee);
        if (discountedFee > type(uint96).max) revert InsufficientFunds();
        bool isPriority = core._isPriorityBooking(msg.sender);

        uint256 reserveAmount = discountedFee.mul(core.reserveFundPercentage()).div(core.PERCENTAGE_DENOMINATOR());
        uint256 platformAmount = discountedFee.mul(core.platformFeePercentage()).div(core.PERCENTAGE_DENOMINATOR());

        appointmentCounter = appointmentCounter.add(1);
        uint256 newAppointmentId = appointmentCounter;

        appointments[newAppointmentId] = Appointment({
            id: newAppointmentId,
            patient: msg.sender,
            doctors: _doctors,
            scheduledTimestamp: _timestamp,
            status: AppointmentStatus.Pending,
            fee: uint96(discountedFee),
            paymentType: _paymentType,
            isVideoCall: _isVideoCall,
            isPriority: isPriority,
            videoCallLinkHash: _isVideoCall ? _videoCallLinkHash : bytes32(0),
            disputeWindowEnd: 0,
            disputeOutcome: DisputeOutcome.Unresolved
        });

        for (uint256 i = 0; i < _doctors.length; i++) {
            _addPendingAppointment(_doctors[i], newAppointmentId);
        }
        appointmentReminders[newAppointmentId] = Reminder(true, 0, 0);
        TelemedicineCore.Patient storage patient = core.patients(msg.sender);
        patient.gamification.mediPoints = uint96(patient.gamification.mediPoints.add(core.pointsForActions("appointment")));
        patient.lastActivityTimestamp = uint48(block.timestamp);

        if (_paymentType == TelemedicinePayments.PaymentType.ETH) {
            if (msg.value < discountedFee) revert InsufficientFunds();
            core.reserveFund = core.reserveFund.add(reserveAmount);
            emit ReserveFundAllocated(newAppointmentId, reserveAmount, _paymentType);
            emit PlatformFeeAllocated(newAppointmentId, platformAmount, _paymentType);
            if (msg.value > discountedFee) {
                _safeTransferETH(msg.sender, msg.value.sub(discountedFee));
            }
        } else {
            // Updated: Try-catch for payment processing
            try payments._processPayment(_paymentType, discountedFee) {
                if (_paymentType == TelemedicinePayments.PaymentType.USDC) {
                    payments.usdcToken().safeTransferFrom(address(payments), address(this), reserveAmount);
                    core.reserveFund = core.reserveFund.add(reserveAmount);
                } else if (_paymentType == TelemedicinePayments.PaymentType.SONIC) {
                    payments.sonicToken().safeTransferFrom(address(payments), address(this), reserveAmount);
                    core.reserveFund = core.reserveFund.add(reserveAmount);
                }
                emit ReserveFundAllocated(newAppointmentId, reserveAmount, _paymentType);
                emit PlatformFeeAllocated(newAppointmentId, platformAmount, _paymentType);
            } catch {
                revert ExternalCallFailed();
            }
        }

        core._levelUp(msg.sender);
        emit AppointmentBooked(newAppointmentId, msg.sender, _doctors, _timestamp);
    }

    /// @notice Confirms an appointment
    /// @param _appointmentId Appointment ID
    /// @param _overridePriority Whether to override priority scheduling
    function confirmAppointment(uint256 _appointmentId, bool _overridePriority) public onlyRole(core.DOCTOR_ROLE()) whenNotPaused {
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
        } else if (!apt.isPriority && _hasPendingPriorityAppointments(msg.sender)) {
            revert InvalidStatus();
        }

        apt.status = AppointmentStatus.Confirmed;
        _removePendingAppointment(msg.sender, _appointmentId);
        emit AppointmentStatusUpdated(_appointmentId, "Confirmed");
    }

    /// @notice Completes an appointment with multi-sig approval
    /// @param _appointmentId Appointment ID
    /// @param _ipfsSummary IPFS hash of the summary
    /// @param _operationHash Multi-sig operation hash
    function completeAppointment(uint256 _appointmentId, string calldata _ipfsSummary, bytes32 _operationHash)
        external onlyRole(core.DOCTOR_ROLE()) nonReentrant whenNotPaused onlyMultiSig(_operationHash)
    {
        if (bytes(_ipfsSummary).length < MIN_IPFS_HASH_LENGTH) revert InvalidIpfsHash();
        // Updated: Validate nonce
        uint256 currentNonce = nonces[msg.sender];
        bytes32 expectedHash = keccak256(abi.encodePacked(
            "completeAppointment",
            _appointmentId,
            _ipfsSummary,
            msg.sender,
            block.timestamp,
            currentNonce
        ));
        if (_operationHash != expectedHash) revert MultiSigNotApproved();
        nonces[msg.sender] = currentNonce.add(1);

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
        if (_appointmentId == 0 || _appointmentId > appointmentCounter) revert InvalidIndex();

        // Updated: Try-catch for dispute resolution
        DisputeOutcome outcome = DisputeOutcome.Unresolved;
        try disputeResolution.isDisputed(_appointmentId) returns (bool isDisputed) {
            if (isDisputed) {
                outcome = disputeResolution.getDisputeOutcome(_appointmentId);
                if (outcome == DisputeOutcome.Unresolved) revert InvalidStatus();
                apt.disputeOutcome = outcome;
            }
        } catch {
            revert ExternalCallFailed();
        }

        apt.status = AppointmentStatus.Completed;
        apt.disputeWindowEnd = uint48(block.timestamp).add(core.disputeWindow());
        appointmentReminders[_appointmentId].active = false;

        uint256 doctorPayment = uint256(apt.fee).mul(core.doctorFeePercentage()).div(core.PERCENTAGE_DENOMINATOR()).div(apt.doctors.length);
        for (uint256 i = 0; i < apt.doctors.length; i++) {
            _releasePayment(apt.doctors[i], doctorPayment, apt.paymentType);
            emit DoctorPaid(_appointmentId, apt.doctors[i], doctorPayment, apt.paymentType);
        }

        if (apt.disputeOutcome != DisputeOutcome.Unresolved) {
            try services.notifyDisputeResolved(_appointmentId, "Appointment", apt.disputeOutcome) {
                // Success
            } catch {
                revert ExternalCallFailed();
            }
        }
        emit AppointmentStatusUpdated(_appointmentId, "Completed");
        emit AppointmentCompleted(_appointmentId, _ipfsSummary);
    }

    // Lab Test Functions

    /// @notice Orders a lab test for a patient
    /// @param _patient Patient address
    /// @param _testTypeIpfsHash IPFS hash of the test type
    /// @param _locality Locality for lab tech selection
    function orderLabTest(address _patient, string calldata _testTypeIpfsHash, string calldata _locality) 
        external payable onlyRole(core.DOCTOR_ROLE()) nonReentrant whenNotPaused 
    {
        if (_patient == address(0) || !core.patients(_patient).isRegistered) revert InvalidAddress();
        if (bytes(_testTypeIpfsHash).length < MIN_IPFS_HASH_LENGTH || bytes(_locality).length == 0) revert InvalidIpfsHash();

        address selectedLabTech = selectBestLabTech(_testTypeIpfsHash, _locality);
        if (selectedLabTech == address(0)) revert NoLabTechAvailable();

        // Updated: Validate deadlines
        (uint256 price, bool isValid, uint48 sampleDeadline, uint48 resultsDeadline) = services.getLabTestDetails(selectedLabTech, _testTypeIpfsHash);
        if (sampleDeadline < block.timestamp + 1 hours || resultsDeadline < sampleDeadline + 1 hours) revert InvalidTimestamp();

        labTestCounter = labTestCounter.add(1);
        uint256 newTestId = labTestCounter;

        labTestOrders[newTestId] = LabTestOrder({
            id: newTestId,
            patient: _patient,
            doctor: msg.sender,
            labTech: selectedLabTech,
            status: LabTestStatus.Requested,
            orderedTimestamp: uint48(block.timestamp),
            completedTimestamp: 0,
            testTypeIpfsHash: _testTypeIpfsHash,
            sampleCollectionIpfsHash: "",
            resultsIpfsHash: "",
            patientCost: 0,
            disputeWindowEnd: uint48(block.timestamp).add(core.disputeWindow()), // Updated: Set initially
            disputeOutcome: DisputeOutcome.Unresolved,
            sampleCollectionDeadline: sampleDeadline,
            resultsUploadDeadline: resultsDeadline,
            paymentType: TelemedicinePayments.PaymentType.ETH
        });

        if (!isValid || price == 0) {
            requestLabTestPrice(selectedLabTech, _testTypeIpfsHash, newTestId);
        } else {
            labTestOrders[newTestId].patientCost = price.mul(120).div(core.PERCENTAGE_DENOMINATOR());
            if (msg.value < labTestOrders[newTestId].patientCost) revert InsufficientFunds();
            labTestPayments[newTestId] = true;
            emit LabTestPaymentConfirmed(newTestId, labTestOrders[newTestId].patientCost);
            if (msg.value > labTestOrders[newTestId].patientCost) {
                _safeTransferETH(msg.sender, msg.value.sub(labTestOrders[newTestId].patientCost));
            }
        }

        emit LabTestOrdered(newTestId, _patient, msg.sender, _testTypeIpfsHash, uint48(block.timestamp));
        // Updated: Try-catch for monetizeData
        try services.monetizeData(_patient) {
            // Success
        } catch {
            // Log failure but don't revert
        }
    }

    /// @notice Requests lab test price from Chainlink oracle
    /// @param _labTech Lab technician address
    /// @param _testTypeIpfsHash IPFS hash of the test type
    /// @param _labTestId Lab test ID
    function requestLabTestPrice(address _labTech, string calldata _testTypeIpfsHash, uint256 _labTestId) internal returns (bytes32) {
        // Updated: Clarify manualPriceOverride
        if (core.manualPriceOverride()) {
            // Fallback to default price (set by admin off-chain)
            labTestOrders[_labTestId].patientCost = 0.01 ether; // Example default
            labTestOrders[_labTestId].status = LabTestStatus.PaymentPending;
            labTestPaymentDeadlines[_labTestId] = uint48(block.timestamp).add(core.paymentConfirmationDeadline());
            emit LabTestPaymentConfirmed(_labTestId, labTestOrders[_labTestId].patientCost);
            return bytes32(0);
        }
        Chainlink.Request memory req = buildChainlinkRequest(core.priceListJobId(), address(this), this.fulfillLabTestPrice.selector);
        req.add("testType", _testTypeIpfsHash);
        req.add("labTech", toString(_labTech));
        bytes32 requestId = sendChainlinkRequestTo(core.chainlinkOracle(), req, core.chainlinkFee());
        requestToLabTestId[requestId] = _labTestId;
        requestTimestamps[requestId] = uint48(block.timestamp);
        return requestId;
    }

    /// @notice Handles Chainlink lab test price response
    /// @param _requestId Chainlink request ID
    /// @param _price Returned price
    function fulfillLabTestPrice(bytes32 _requestId, uint256 _price) public recordChainlinkFulfillment(_requestId) {
        // Updated: Check timeout
        if (block.timestamp > requestTimestamps[_requestId] + chainlinkTimeout) revert ChainlinkRequestTimeout();

        uint256 labTestId = requestToLabTestId[_requestId];
        if (labTestId == 0 || labTestId > labTestCounter) revert InvalidIndex();
        LabTestOrder storage order = labTestOrders[labTestId];
        if (order.status != LabTestStatus.Requested) revert InvalidStatus();
        if (_price == 0) {
            // Fallback to default price
            order.patientCost = 0.01 ether; // Example default
        } else {
            order.patientCost = _price.mul(120).div(core.PERCENTAGE_DENOMINATOR());
        }

        order.status = LabTestStatus.PaymentPending;
        labTestPaymentDeadlines[labTestId] = uint48(block.timestamp).add(core.paymentConfirmationDeadline());
        delete requestToLabTestId[_requestId];
        delete requestTimestamps[_requestId];
        emit LabTestPaymentConfirmed(labTestId, order.patientCost);
    }

    // Prescription Functions

    /// @notice Issues a prescription for a patient
    /// @param _patient Patient address
    /// @param _medicationIpfsHash IPFS hash of the medication
    /// @param _pharmacy Pharmacy address
    /// @param _locality Locality for pharmacy selection
    function issuePrescription(address _patient, string calldata _medicationIpfsHash, address _pharmacy, string calldata _locality) 
        external payable onlyRole(core.DOCTOR_ROLE()) nonReentrant whenNotPaused 
    {
        if (_patient == address(0) || !core.patients(_patient).isRegistered || _pharmacy == address(0)) revert InvalidAddress();
        if (!services.isPharmacyRegistered(_pharmacy) && !services.hasPharmacyInLocality(_locality)) revert NotAuthorized();
        if (bytes(_medicationIpfsHash).length < MIN_IPFS_HASH_LENGTH || bytes(_locality).length == 0) revert InvalidIpfsHash();

        (uint256 price, bool isValid) = services.getPharmacyPrice(_pharmacy, _medicationIpfsHash);
        prescriptionCounter = prescriptionCounter.add(1);
        uint256 newPrescriptionId = prescriptionCounter;
        bytes32 verificationCodeHash = keccak256(abi.encodePacked(newPrescriptionId, msg.sender, block.timestamp));

        prescriptions[newPrescriptionId] = Prescription({
            id: newPrescriptionId,
            patient: _patient,
            doctor: msg.sender,
            verificationCodeHash: verificationCodeHash,
            status: PrescriptionStatus.Generated,
            pharmacy: _pharmacy,
            generatedTimestamp: uint48(block.timestamp),
            expirationTimestamp: uint48(block.timestamp).add(30 days),
            medicationIpfsHash: _medicationIpfsHash,
            prescriptionIpfsHash: "",
            patientCost: 0,
            disputeWindowEnd: uint48(block.timestamp).add(core.disputeWindow()), // Updated: Set initially
            disputeOutcome: DisputeOutcome.Unresolved
        });

        if (!isValid || price == 0) {
            requestPrescriptionPrice(_pharmacy, _medicationIpfsHash, newPrescriptionId);
        } else {
            prescriptions[newPrescriptionId].patientCost = price.mul(120).div(core.PERCENTAGE_DENOMINATOR());
            if (msg.value < prescriptions[newPrescriptionId].patientCost) revert InsufficientFunds();
            prescriptionPayments[newPrescriptionId] = true;
            emit PrescriptionPaymentConfirmed(newPrescriptionId, prescriptions[newPrescriptionId].patientCost);
            if (msg.value > prescriptions[newPrescriptionId].patientCost) {
                _safeTransferETH(msg.sender, msg
