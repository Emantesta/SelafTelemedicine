// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {SafeMathUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";
import {SafeERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import {TelemedicineCore} from "./TelemedicineCore.sol";
import {TelemedicinePayments} from "./TelemedicinePayments.sol";
import {TelemedicineDisputeResolution} from "./TelemedicineDisputeResolution.sol";
import {ChainlinkClient, Chainlink} from "@chainlink/contracts/src/v0.8/ChainlinkClient.sol";
import {LinkTokenInterface} from "@chainlink/contracts/src/v0.8/interfaces/LinkTokenInterface.sol";
import {TelemedicineMedicalServices} from "./TelemedicineMedicalServices.sol";
import {IERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";

contract TelemedicineMedicalCore is Initializable, ReentrancyGuardUpgradeable, ChainlinkClient {
    using SafeMathUpgradeable for uint256;
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
    error InvalidPercentage();
    error ChainlinkRequestTimeout();

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
    bool public manualPriceOverride; // Added: Circuit breaker for Chainlink failures
    mapping(bytes32 => uint256) public requestToLabTestId;
    mapping(bytes32 => uint256) public requestToPrescriptionId;
    mapping(bytes32 => uint48) public requestTimestamps;

    // Configurable Constants
    uint256 public doctorFeePercentage;
    uint256 public reserveFundPercentage;
    uint256 public platformFeePercentage;
    uint256 public constant PERCENTAGE_DENOMINATOR = 100;
    uint48 public disputeWindow;
    uint256 public maxBatchSize;
    uint256 public cancellationFeePercentage;
    uint48 public reminderInterval;
    uint48 public paymentConfirmationDeadline;
    uint48 public invitationExpirationPeriod;
    uint256 public maxDoctorsPerAppointment;

    // State Variables
    mapping(uint256 => Appointment) public appointments;
    mapping(uint256 => LabTestOrder) public labTestOrders;
    mapping(uint256 => Prescription) public prescriptions;
    mapping(uint256 => AISymptomAnalysis) public aiAnalyses;
    mapping(address => PendingAppointments) public doctorPendingAppointments;
    mapping(uint256 => Reminder) public appointmentReminders;
    mapping(address => uint256) public nonces;
    mapping(uint256 => bool) public labTestPayments;
    mapping(uint256 => bool) public prescriptionPayments;
    mapping(uint256 => uint48) public labTestPaymentDeadlines;
    mapping(uint256 => uint48) public prescriptionPaymentDeadlines;

    // Added: Payment Queue for Insufficient Funds
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
        string inviteeContact;
        bool isLabTech;
        bool fulfilled;
        uint48 expirationTimestamp;
    }
    mapping(bytes32 => Invitation) public invitations;
    uint256 public invitationCounter;

    address[] public multiSigSigners;
    uint256 public appointmentCounter;
    uint256 public labTestCounter;
    uint256 public prescriptionCounter;
    uint256 public aiAnalysisCounter;
    uint256 public requiredSignatures;

    // Enums
    enum AppointmentStatus { Pending, Confirmed, Completed, Cancelled, Rescheduled, Emergency, Disputed }
    enum LabTestStatus { Requested, PaymentPending, Collected, ResultsUploaded, Reviewed, Disputed, Expired }
    enum PrescriptionStatus { Generated, PaymentPending, Verified, Fulfilled, Revoked, Expired, Disputed }
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
    event LabTestReordered(uint256 indexed originalTestId, uint256 indexed newTestId, address newLabTech, address patient);
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
    event FundsWithdrawn(address indexed recipient, uint256 amount, TelemedicinePayments.PaymentType paymentType);
    event LabTestRefunded(uint256 indexed testId, address patient, uint256 amount);
    event PrescriptionRefunded(uint256 indexed prescriptionId, address patient, uint256 amount);
    event InvitationSubmitted(bytes32 indexed invitationId, address patient, string locality, string inviteeContact, bool isLabTech);
    event InvitationFulfilled(bytes32 indexed invitationId, address invitee);
    event InvitationExpired(bytes32 indexed invitationId);
    event LabTestPaymentConfirmed(uint256 indexed testId, uint256 amount);
    event PrescriptionPaymentConfirmed(uint256 indexed prescriptionId, uint256 amount);
    event LabTestPaymentPending(uint256 indexed testId, uint256 patientCost, uint48 deadline);
    event PrescriptionPaymentPending(uint256 indexed prescriptionId, uint256 patientCost, uint48 deadline);
    event PrescriptionDetailsSet(uint256 indexed prescriptionId, string prescriptionIpfsHash);
    event LabTestDisputeWindowStarted(uint256 indexed testId, address patient, uint48 disputeWindowEnd);
    event PrescriptionDisputeWindowStarted(uint256 indexed prescriptionId, address patient, uint48 disputeWindowEnd);
    event LabTestPaymentReleased(uint256 indexed testId, address labTech, uint256 amount, TelemedicinePayments.PaymentType paymentType);
    event PrescriptionPaymentReleased(uint256 indexed prescriptionId, address pharmacy, uint256 amount, TelemedicinePayments.PaymentType paymentType);
    event ConfigurationUpdated(string parameter, uint256 value);
    // Added: Events for payment queue
    event PaymentQueued(uint256 indexed paymentId, address recipient, uint256 amount, TelemedicinePayments.PaymentType paymentType);
    event PaymentReleasedFromQueue(uint256 indexed paymentId, address recipient, uint256 amount);

    /// @notice Initializes the contract with dependencies and configuration
    function initialize(
        address _core,
        address _payments,
        address _disputeResolution,
        address _services,
        address _chainlinkOracle,
        bytes32 _priceListJobId,
        address _linkToken,
        address[] memory _multiSigSigners,
        uint256 _requiredSignatures,
        uint256 _doctorFeePercentage,
        uint256 _reserveFundPercentage,
        uint256 _platformFeePercentage,
        uint48 _disputeWindow,
        uint256 _maxBatchSize,
        uint256 _cancellationFeePercentage,
        uint48 _reminderInterval,
        uint48 _paymentConfirmationDeadline,
        uint48 _invitationExpirationPeriod,
        uint256 _maxDoctorsPerAppointment
    ) external initializer {
        if (_core == address(0) || _payments == address(0) || _disputeResolution == address(0) ||
            _services == address(0) || _chainlinkOracle == address(0) || _linkToken == address(0)) revert InvalidAddress();
        if (_multiSigSigners.length < _requiredSignatures || _requiredSignatures == 0) revert InvalidAddress();
        // Added: Validate percentage sum at initialization
        if (_doctorFeePercentage + _reserveFundPercentage + _platformFeePercentage != 100) revert InvalidPercentage();

        for (uint256 i = 0; i < _multiSigSigners.length; i++) {
            for (uint256 j = i + 1; j < _multiSigSigners.length; j++) {
                if (_multiSigSigners[i] == _multiSigSigners[j]) revert InvalidAddress();
            }
        }

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
        manualPriceOverride = false; // Added: Default to Chainlink usage
        multiSigSigners = _multiSigSigners;
        requiredSignatures = _requiredSignatures;

        // Updated: Use parameters instead of hardcoded values
        doctorFeePercentage = _doctorFeePercentage;
        reserveFundPercentage = _reserveFundPercentage;
        platformFeePercentage = _platformFeePercentage;
        disputeWindow = _disputeWindow;
        maxBatchSize = _maxBatchSize;
        cancellationFeePercentage = _cancellationFeePercentage;
        reminderInterval = _reminderInterval;
        paymentConfirmationDeadline = _paymentConfirmationDeadline;
        invitationExpirationPeriod = _invitationExpirationPeriod;
        maxDoctorsPerAppointment = _maxDoctorsPerAppointment;

        appointmentCounter = 0;
        labTestCounter = 0;
        prescriptionCounter = 0;
        aiAnalysisCounter = 0;
        invitationCounter = 0;
        pendingPaymentCounter = 0; // Added: Initialize payment queue counter
    }

    // Configuration Functions
    /// @notice Updates a configuration parameter with percentage validation
    function updateConfiguration(string calldata _parameter, uint256 _value) external onlyRole(core.ADMIN_ROLE()) {
        bytes32 paramHash = keccak256(abi.encodePacked(_parameter));
        if (paramHash == keccak256("doctorFeePercentage")) {
            if (_value > 100) revert InvalidPercentage();
            doctorFeePercentage = _value;
        } else if (paramHash == keccak256("reserveFundPercentage")) {
            if (_value > 100) revert InvalidPercentage();
            reserveFundPercentage = _value;
        } else if (paramHash == keccak256("platformFeePercentage")) {
            if (_value > 100) revert InvalidPercentage();
            platformFeePercentage = _value;
        } else if (paramHash == keccak256("disputeWindow")) {
            disputeWindow = uint48(_value);
        } else if (paramHash == keccak256("maxBatchSize")) {
            maxBatchSize = _value;
        } else if (paramHash == keccak256("cancellationFeePercentage")) {
            if (_value > 100) revert InvalidPercentage();
            cancellationFeePercentage = _value;
        } else if (paramHash == keccak256("reminderInterval")) {
            reminderInterval = uint48(_value);
        } else if (paramHash == keccak256("paymentConfirmationDeadline")) {
            paymentConfirmationDeadline = uint48(_value);
        } else if (paramHash == keccak256("invitationExpirationPeriod")) {
            invitationExpirationPeriod = uint48(_value);
        } else if (paramHash == keccak256("maxDoctorsPerAppointment")) {
            maxDoctorsPerAppointment = _value;
        } else if (paramHash == keccak256("chainlinkFee")) {
            chainlinkFee = _value;
        } else {
            revert("Unknown parameter");
        }
        // Added: Validate percentage sum after updates
        if (paramHash == keccak256("doctorFeePercentage") || paramHash == keccak256("reserveFundPercentage") || paramHash == keccak256("platformFeePercentage")) {
            if (doctorFeePercentage + reserveFundPercentage + platformFeePercentage != 100) revert InvalidPercentage();
        }
        emit ConfigurationUpdated(_parameter, _value);
    }

    /// @notice Confirms payment for a lab test or prescription
    function confirmPayment(uint256 _id, bool _isLabTest, TelemedicinePayments.PaymentType _paymentType)
        external payable onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
        if (_isLabTest) {
            LabTestOrder storage order = labTestOrders[_id];
            if (_id == 0 || _id > labTestCounter) revert InvalidIndex();
            if (order.patient != msg.sender) revert NotAuthorized();
            if (order.status != LabTestStatus.PaymentPending) revert InvalidStatus();
            if (block.timestamp > labTestPaymentDeadlines[_id]) revert PaymentDeadlineMissed();

            if (_paymentType == TelemedicinePayments.PaymentType.ETH) {
                if (msg.value < order.patientCost) revert InsufficientFunds();
                order.paymentType = _paymentType;
                labTestPayments[_id] = true;
                order.status = LabTestStatus.Requested;
                emit LabTestPaymentConfirmed(_id, order.patientCost);
                if (msg.value > order.patientCost) {
                    uint256 refund = msg.value - order.patientCost;
                    _safeTransferETH(msg.sender, refund);
                }
            } else {
                payments._processPayment(_paymentType, order.patientCost);
                order.paymentType = _paymentType;
                labTestPayments[_id] = true;
                order.status = LabTestStatus.Requested;
                emit LabTestPaymentConfirmed(_id, order.patientCost);
            }
        } else {
            Prescription storage prescription = prescriptions[_id];
            if (_id == 0 || _id > prescriptionCounter) revert InvalidIndex();
            if (prescription.patient != msg.sender) revert NotAuthorized();
            if (prescription.status != PrescriptionStatus.PaymentPending) revert InvalidStatus();
            if (block.timestamp > prescriptionPaymentDeadlines[_id]) revert PaymentDeadlineMissed();

            if (_paymentType == TelemedicinePayments.PaymentType.ETH) {
                if (msg.value < prescription.patientCost) revert InsufficientFunds();
                prescription.paymentType = _paymentType;
                prescriptionPayments[_id] = true;
                prescription.status = PrescriptionStatus.Generated;
                emit PrescriptionPaymentConfirmed(_id, prescription.patientCost);
                if (msg.value > prescription.patientCost) {
                    uint256 refund = msg.value - prescription.patientCost;
                    _safeTransferETH(msg.sender, refund);
                }
            } else {
                payments._processPayment(_paymentType, prescription.patientCost);
                prescription.paymentType = _paymentType;
                prescriptionPayments[_id] = true;
                prescription.status = PrescriptionStatus.Generated;
                emit PrescriptionPaymentConfirmed(_id, prescription.patientCost);
            }
        }
    }

    /// @notice Sets prescription details after payment
    function setPrescriptionDetails(uint256 _prescriptionId, string calldata _prescriptionIpfsHash)
        external onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
        Prescription storage prescription = prescriptions[_prescriptionId];
        if (_prescriptionId == 0 || _prescriptionId > prescriptionCounter) revert InvalidIndex();
        if (prescription.patient != msg.sender) revert NotAuthorized();
        if (prescription.status != PrescriptionStatus.Generated) revert InvalidStatus();
        if (!prescriptionPayments[_prescriptionId]) revert PaymentNotConfirmed();
        if (bytes(_prescriptionIpfsHash).length == 0) revert InvalidIpfsHash();
        if (bytes(prescription.prescriptionIpfsHash).length != 0) revert InvalidStatus();

        prescription.prescriptionIpfsHash = _prescriptionIpfsHash;
        emit PrescriptionDetailsSet(_prescriptionId, _prescriptionIpfsHash);
    }

    /// @notice Checks and expires prescriptions if deadlines are missed
    function checkPrescriptionDeadlines(uint256 _prescriptionId) external nonReentrant whenNotPaused {
        Prescription storage prescription = prescriptions[_prescriptionId];
        if (_prescriptionId == 0 || _prescriptionId > prescriptionCounter) revert InvalidIndex();
        if (prescription.status == PrescriptionStatus.Fulfilled ||
            prescription.status == PrescriptionStatus.Revoked ||
            prescription.status == PrescriptionStatus.Expired ||
            prescription.status == PrescriptionStatus.Disputed) return;

        if (prescription.status == PrescriptionStatus.PaymentPending &&
            block.timestamp > prescriptionPaymentDeadlines[_prescriptionId]) {
            prescription.status = PrescriptionStatus.Expired;
            emit PrescriptionExpired(_prescriptionId);
        } else if ((prescription.status == PrescriptionStatus.Generated || prescription.status == PrescriptionStatus.Verified) &&
                   block.timestamp > prescription.expirationTimestamp) {
            prescription.status = PrescriptionStatus.Expired;
            emit PrescriptionExpired(_prescriptionId);
        }
    }

    /// @notice Invites a provider (lab tech or pharmacy) to join the platform
    function inviteProvider(string calldata _locality, string calldata _inviteeContact, bool _isLabTech)
        external onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
        if (bytes(_locality).length == 0 || bytes(_inviteeContact).length == 0) revert InvalidLocality();

        bool hasProvider = _isLabTech ?
            services.hasLabTechInLocality(_locality) :
            services.hasPharmacyInLocality(_locality);
        if (hasProvider) revert ProvidersAlreadyExist();

        bytes32 invitationId = keccak256(abi.encodePacked(msg.sender, _locality, _isLabTech, block.timestamp));
        if (invitations[invitationId].patient != address(0)) revert InvitationAlreadyExists();

        invitationCounter = invitationCounter + 1;
        invitations[invitationId] = Invitation({
            patient: msg.sender,
            locality: _locality,
            inviteeContact: _inviteeContact,
            isLabTech: _isLabTech,
            fulfilled: false,
            expirationTimestamp: uint48(block.timestamp) + invitationExpirationPeriod
        });

        emit InvitationSubmitted(invitationId, msg.sender, _locality, _inviteeContact, _isLabTech);
    }

    /// @notice Registers an invited provider
    function registerAsInvitedProvider(bytes32 _invitationId, address _providerAddress)
        external onlyRole(core.ADMIN_ROLE()) nonReentrant whenNotPaused {
        Invitation storage invitation = invitations[_invitationId];
        if (invitation.patient == address(0)) revert InvalidIndex();
        if (invitation.fulfilled) revert InvalidStatus();
        if (block.timestamp > invitation.expirationTimestamp) revert InvitationExpired();
        if (_providerAddress == address(0)) revert InvalidAddress();

        if (invitation.isLabTech) {
            services.registerLabTech(_providerAddress, invitation.locality);
        } else {
            services.registerPharmacy(_providerAddress, invitation.locality);
        }

        invitation.fulfilled = true;
        emit InvitationFulfilled(_invitationId, _providerAddress);
    }

    /// @notice Checks and expires an invitation if it has passed its expiration timestamp
    function checkInvitationExpiration(bytes32 _invitationId) external nonReentrant whenNotPaused {
        Invitation storage invitation = invitations[_invitationId];
        if (invitation.patient == address(0)) revert InvalidIndex();
        if (invitation.fulfilled) return;
        if (block.timestamp <= invitation.expirationTimestamp) return;

        delete invitations[_invitationId];
        emit InvitationExpired(_invitationId);
    }

    /// @notice Books an appointment with multiple doctors
    function bookAppointment(
        address[] calldata _doctors,
        uint48 _timestamp,
        TelemedicinePayments.PaymentType _paymentType,
        bool _isVideoCall,
        string calldata _videoCallLink
    ) external payable onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
        if (_doctors.length == 0 || _doctors.length > maxDoctorsPerAppointment) revert InvalidAddress();
        for (uint256 i = 0; i < _doctors.length; i++) {
            if (_doctors[i] == address(0) || !core.doctors(_doctors[i]).isVerified) revert NotAuthorized();
        }
        if (_timestamp <= block.timestamp + core.minBookingBuffer()) revert InvalidTimestamp();

        core.decayPoints(msg.sender);
        uint256 baseFee = 0;
        for (uint256 i = 0; i < _doctors.length; i++) {
            baseFee = baseFee + core.getDoctorFee(_doctors[i]);
        }
        uint256 discountedFee = core._applyFeeDiscount(msg.sender, baseFee);
        if (discountedFee > type(uint96).max) revert InsufficientFunds();
        bool isPriority = core._isPriorityBooking(msg.sender);

        uint256 reserveAmount = discountedFee * reserveFundPercentage / PERCENTAGE_DENOMINATOR;
        uint256 platformAmount = discountedFee * platformFeePercentage / PERCENTAGE_DENOMINATOR;

        appointmentCounter = appointmentCounter + 1;
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
            videoCallLink: _isVideoCall ? _videoCallLink : "",
            disputeWindowEnd: 0,
            disputeOutcome: DisputeOutcome.Unresolved
        });

        for (uint256 i = 0; i < _doctors.length; i++) {
            _addPendingAppointment(_doctors[i], newAppointmentId);
        }
        appointmentReminders[newAppointmentId] = Reminder(true, 0, 0);
        TelemedicineCore.Patient storage patient = core.patients(msg.sender);
        patient.gamification.mediPoints = uint96(patient.gamification.mediPoints + core.pointsForActions("appointment"));
        patient.lastActivityTimestamp = uint48(block.timestamp);

        if (_paymentType == TelemedicinePayments.PaymentType.ETH) {
            if (msg.value < discountedFee) revert InsufficientFunds();
            core.reserveFund = core.reserveFund + reserveAmount;
            emit ReserveFundAllocated(newAppointmentId, reserveAmount, _paymentType);
            emit PlatformFeeAllocated(newAppointmentId, platformAmount, _paymentType);
            if (msg.value > discountedFee) {
                uint256 refund = msg.value - discountedFee;
                _safeTransferETH(msg.sender, refund);
            }
        } else {
            payments._processPayment(_paymentType, discountedFee);
            if (_paymentType == TelemedicinePayments.PaymentType.USDC) {
                if (!payments.usdcToken().transfer(address(core), reserveAmount)) revert PaymentFailed();
                core.reserveFund = core.reserveFund + reserveAmount;
            } else if (_paymentType == TelemedicinePayments.PaymentType.SONIC) {
                if (!payments.sonicToken().transfer(address(core), reserveAmount)) revert PaymentFailed();
                core.reserveFund = core.reserveFund + reserveAmount;
            }
            emit ReserveFundAllocated(newAppointmentId, reserveAmount, _paymentType);
            emit PlatformFeeAllocated(newAppointmentId, platformAmount, _paymentType);
        }

        core._levelUp(msg.sender);
        emit AppointmentBooked(newAppointmentId, msg.sender, _doctors, _timestamp, _videoCallLink);
    }

    /// @notice Cancels an appointment and processes refund if applicable
    function cancelAppointment(uint256 _appointmentId) external onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
        Appointment storage apt = appointments[_appointmentId];
        if (apt.patient != msg.sender) revert NotAuthorized();
        if (apt.status != AppointmentStatus.Pending && apt.status != AppointmentStatus.Confirmed) revert InvalidStatus();
        if (_appointmentId == 0 || _appointmentId > appointmentCounter) revert InvalidIndex();

        uint256 cancellationFee = 0;
        if (apt.scheduledTimestamp <= block.timestamp + core.minCancellationBuffer()) {
            cancellationFee = uint256(apt.fee) * cancellationFeePercentage / PERCENTAGE_DENOMINATOR;
            emit CancellationFeeCharged(_appointmentId, cancellationFee);
        }

        apt.status = AppointmentStatus.Cancelled;
        for (uint256 i = 0; i < apt.doctors.length; i++) {
            _removePendingAppointment(apt.doctors[i], _appointmentId);
        }
        appointmentReminders[_appointmentId].active = false;

        if (apt.fee > cancellationFee) {
            payments._refundPatient(apt.patient, apt.fee - cancellationFee, apt.paymentType);
        }
        emit AppointmentStatusUpdated(_appointmentId, "Cancelled");
    }

    /// @notice Reschedules an appointment to a new timestamp
    function rescheduleAppointment(uint256 _appointmentId, uint48 _newTimestamp)
        external onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
        Appointment storage apt = appointments[_appointmentId];
        if (apt.patient != msg.sender) revert NotAuthorized();
        if (apt.status != AppointmentStatus.Pending && apt.status != AppointmentStatus.Confirmed) revert InvalidStatus();
        if (_newTimestamp <= block.timestamp + core.minBookingBuffer()) revert InvalidTimestamp();
        if (_appointmentId == 0 || _appointmentId > appointmentCounter) revert InvalidIndex();

        apt.scheduledTimestamp = _newTimestamp;
        apt.status = AppointmentStatus.Rescheduled;
        appointmentReminders[_appointmentId].lastReminderTimestamp = 0;
        emit AppointmentStatusUpdated(_appointmentId, "Rescheduled");
    }

    /// @notice Confirms an appointment, optionally overriding priority
    function confirmAppointment(uint256 _appointmentId, bool _overridePriority)
        public onlyRole(core.DOCTOR_ROLE()) whenNotPaused {
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
        if (apt.isVideoCall) emit VideoCallStarted(_appointmentId, apt.videoCallLink);
        emit AppointmentStatusUpdated(_appointmentId, "Confirmed");
    }

    /// @notice Confirms multiple appointments with pagination
    function batchConfirmAppointments(uint256 _startIndex, uint256 _pageSize)
        external onlyRole(core.DOCTOR_ROLE()) whenNotPaused {
        if (_pageSize > maxBatchSize || _pageSize == 0) revert InvalidPageSize();
        PendingAppointments storage pending = doctorPendingAppointments[msg.sender];
        if (_startIndex >= pending.count) revert InvalidIndex();

        uint256 endIndex = _startIndex + _pageSize > pending.count ? pending.count : _startIndex + _pageSize;
        uint256[] memory confirmedIds = new uint256[](endIndex - _startIndex);
        uint256 confirmedCount = 0;

        for (uint256 i = _startIndex; i < endIndex; i++) {
            uint256 appointmentId = pending.ids[i];
            Appointment storage apt = appointments[appointmentId];
            if (apt.status != AppointmentStatus.Pending) continue;

            apt.status = AppointmentStatus.Confirmed;
            _removePendingAppointment(msg.sender, appointmentId);
            if (apt.isVideoCall) emit VideoCallStarted(appointmentId, apt.videoCallLink);
            emit AppointmentStatusUpdated(appointmentId, "Confirmed");
            confirmedIds[confirmedCount] = appointmentId;
            confirmedCount++;
        }

        if (confirmedCount > 0) {
            uint256[] memory trimmedIds = new uint256[](confirmedCount);
            for (uint256 i = 0; i < confirmedCount; i++) {
                trimmedIds[i] = confirmedIds[i];
            }
            emit BatchAppointmentsConfirmed(msg.sender, trimmedIds);
        }
    }

    /// @notice Completes an appointment and distributes payments
    function completeAppointment(uint256 _appointmentId, string calldata _ipfsSummary, bytes32 _operationHash)
        external onlyRole(core.DOCTOR_ROLE()) nonReentrant whenNotPaused onlyMultiSig(_operationHash) {
        bytes32 expectedHash = keccak256(abi.encodePacked(
            "completeAppointment",
            _appointmentId,
            _ipfsSummary,
            msg.sender,
            block.timestamp,
            nonces[msg.sender]++
        ));
        if (_operationHash != expectedHash) revert MultiSigNotApproved();

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
        }

        apt.status = AppointmentStatus.Completed;
        apt.disputeWindowEnd = uint48(block.timestamp) + disputeWindow;
        appointmentReminders[_appointmentId].active = false;

        uint256 doctorPayment = uint256(apt.fee) * doctorFeePercentage / PERCENTAGE_DENOMINATOR / apt.doctors.length;
        for (uint256 i = 0; i < apt.doctors.length; i++) {
            // Updated: Use _releasePayment with queuing
            _releasePayment(apt.doctors[i], doctorPayment, apt.paymentType);
            emit DoctorPaid(_appointmentId, apt.doctors[i], doctorPayment, apt.paymentType);
        }

        if (apt.disputeOutcome != DisputeOutcome.Unresolved) {
            services.notifyDisputeResolved(_appointmentId, "Appointment", apt.disputeOutcome);
        }
        emit AppointmentStatusUpdated(_appointmentId, "Completed");
        emit AppointmentCompleted(_appointmentId, _ipfsSummary);
    }

    /// @notice Triggers a reminder for an appointment
    function triggerAppointmentReminder(uint256 _appointmentId) external whenNotPaused {
        Appointment storage apt = appointments[_appointmentId];
        Reminder storage reminder = appointmentReminders[_appointmentId];

        if (_appointmentId == 0 || _appointmentId > appointmentCounter) revert InvalidIndex();
        if (apt.status != AppointmentStatus.Confirmed) revert InvalidStatus();
        if (!reminder.active) revert InvalidStatus();
        if (apt.scheduledTimestamp <= block.timestamp) revert InvalidTimestamp();
        if (reminder.lastReminderTimestamp + reminderInterval > block.timestamp) revert InvalidTimestamp();
        if (reminder.reminderCount >= 3) revert InvalidStatus();

        reminder.lastReminderTimestamp = uint48(block.timestamp);
        reminder.reminderCount = reminder.reminderCount + 1;
        emit AppointmentReminderSent(_appointmentId, apt.patient, uint48(block.timestamp));
    }

    /// @notice Requests lab test price from Chainlink oracle
    function requestLabTestPrice(address _labTech, string calldata _testTypeIpfsHash, uint256 _labTestId)
        internal returns (bytes32) {
        // Updated: Skip Chainlink if manual override is active
        if (manualPriceOverride) return bytes32(0);
        Chainlink.Request memory req = buildChainlinkRequest(
            priceListJobId,
            address(this),
            this.fulfillLabTestPrice.selector
        );
        req.add("testType", _testTypeIpfsHash);
        req.add("labTech", toString(_labTech));
        bytes32 requestId = sendChainlinkRequestTo(chainlinkOracle, req, chainlinkFee);
        requestToLabTestId[requestId] = _labTestId;
        requestTimestamps[requestId] = uint48(block.timestamp);
        return requestId;
    }

    /// @notice Fulfills lab test price from Chainlink oracle
    function fulfillLabTestPrice(bytes32 _requestId, uint256 _price) public recordChainlinkFulfillment(_requestId) {
        uint256 labTestId = requestToLabTestId[_requestId];
        if (labTestId == 0 || labTestId > labTestCounter) revert InvalidIndex();
        LabTestOrder storage order = labTestOrders[labTestId];
        if (order.status != LabTestStatus.Requested) revert InvalidStatus();
        if (_price == 0) revert OracleResponseInvalid();

        order.patientCost = _price * 120 / PERCENTAGE_DENOMINATOR;
        order.status = LabTestStatus.PaymentPending;
        labTestPaymentDeadlines[labTestId] = uint48(block.timestamp) + paymentConfirmationDeadline;
        delete requestToLabTestId[_requestId];
        delete requestTimestamps[_requestId];
        emit LabTestPaymentPending(labTestId, order.patientCost, labTestPaymentDeadlines[labTestId]);
    }

    /// @notice Requests prescription price from Chainlink oracle
    function requestPrescriptionPrice(address _pharmacy, string calldata _medicationIpfsHash, uint256 _prescriptionId)
        internal returns (bytes32) {
        // Updated: Skip Chainlink if manual override is active
        if (manualPriceOverride) return bytes32(0);
        Chainlink.Request memory req = buildChainlinkRequest(
            priceListJobId,
            address(this),
            this.fulfillPrescriptionPrice.selector
        );
        req.add("medication", _medicationIpfsHash);
        req.add("pharmacy", toString(_pharmacy));
        bytes32 requestId = sendChainlinkRequestTo(chainlinkOracle, req, chainlinkFee);
        requestToPrescriptionId[requestId] = _prescriptionId;
        requestTimestamps[requestId] = uint48(block.timestamp);
        return requestId;
    }

    /// @notice Fulfills prescription price from Chainlink oracle
    function fulfillPrescriptionPrice(bytes32 _requestId, uint256 _price) public recordChainlinkFulfillment(_requestId) {
        uint256 prescriptionId = requestToPrescriptionId[_requestId];
        if (prescriptionId == 0 || prescriptionId > prescriptionCounter) revert InvalidIndex();
        Prescription storage prescription = prescriptions[prescriptionId];
        if (prescription.status != PrescriptionStatus.Generated) revert InvalidStatus();
        if (_price == 0) revert OracleResponseInvalid();

        prescription.patientCost = _price * 120 / PERCENTAGE_DENOMINATOR;
        prescription.status = PrescriptionStatus.PaymentPending;
        prescriptionPaymentDeadlines[prescriptionId] = uint48(block.timestamp) + paymentConfirmationDeadline;
        delete requestToPrescriptionId[_requestId];
        delete requestTimestamps[_requestId];
        emit PrescriptionPaymentPending(prescriptionId, prescription.patientCost, prescriptionPaymentDeadlines[prescriptionId]);
    }

    /// @notice Cancels a stalled Chainlink request
    function cancelChainlinkRequest(bytes32 _requestId) external onlyRole(core.ADMIN_ROLE()) {
        if (requestToLabTestId[_requestId] == 0 && requestToPrescriptionId[_requestId] == 0) revert InvalidIndex();
        if (block.timestamp <= requestTimestamps[_requestId] + chainlinkRequestTimeout) revert InvalidTimestamp();

        cancelChainlinkRequest(_requestId);
        delete requestToLabTestId[_requestId];
        delete requestToPrescriptionId[_requestId];
        delete requestTimestamps[_requestId];
    }

    /// @notice Orders a lab test for a patient
    function orderLabTest(address _patient, string calldata _testTypeIpfsHash, string calldata _locality)
        external payable onlyRole(core.DOCTOR_ROLE()) nonReentrant whenNotPaused {
        if (_patient == address(0)) revert InvalidAddress();
        if (!core.patients(_patient).isRegistered) revert NotAuthorized();
        if (bytes(_testTypeIpfsHash).length == 0 || bytes(_locality).length == 0) revert InvalidIpfsHash();

        address selectedLabTech = selectBestLabTech(_testTypeIpfsHash, _locality);
        if (selectedLabTech == address(0)) revert NoLabTechAvailable();

        (uint256 price, bool isValid, uint48 sampleDeadline, uint48 resultsDeadline) = services.getLabTestDetails(selectedLabTech, _testTypeIpfsHash);
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
            requestLabTestPrice(selectedLabTech, _testTypeIpfsHash, newTestId);
        } else {
            order.patientCost = price * 120 / PERCENTAGE_DENOMINATOR;
            if (msg.value < order.patientCost) revert InsufficientFunds();
            labTestPayments[newTestId] = true;
            emit LabTestPaymentConfirmed(newTestId, order.patientCost);
            if (msg.value > order.patientCost) {
                uint256 refund = msg.value - order.patientCost;
                _safeTransferETH(msg.sender, refund);
            }
        }

        emit LabTestOrdered(newTestId, _patient, msg.sender, _testTypeIpfsHash, uint48(block.timestamp));
        services.monetizeData(_patient);
    }

    /// @notice Collects a sample for a lab test
    function collectSample(uint256 _labTestId, string calldata _ipfsHash)
        external onlyRole(core.LAB_TECH_ROLE()) nonReentrant whenNotPaused {
        LabTestOrder storage order = labTestOrders[_labTestId];
        if (order.status != LabTestStatus.Requested) revert InvalidStatus();
        if (order.labTech != msg.sender) revert NotAuthorized();
        if (_labTestId == 0 || _labTestId > labTestCounter) revert InvalidIndex();
        if (bytes(_ipfsHash).length == 0) revert InvalidIpfsHash();
        if (block.timestamp > order.orderedTimestamp + order.sampleCollectionDeadline) revert DeadlineMissed();
        if (!labTestPayments[_labTestId]) revert PaymentNotConfirmed();

        order.sampleCollectionIpfsHash = _ipfsHash;
        order.status = LabTestStatus.Collected;
        emit LabTestCollected(_labTestId, _ipfsHash);
    }

    /// @notice Uploads lab test results
    function uploadLabResults(uint256 _labTestId, string calldata _resultsIpfsHash)
        external onlyRole(core.LAB_TECH_ROLE()) nonReentrant whenNotPaused {
        LabTestOrder storage order = labTestOrders[_labTestId];
        if (order.labTech != msg.sender) revert NotAuthorized();
        if (order.status != LabTestStatus.Collected) revert InvalidStatus();
        if (_labTestId == 0 || _labTestId > labTestCounter) revert InvalidIndex();
        if (bytes(_resultsIpfsHash).length == 0) revert InvalidIpfsHash();
        if (block.timestamp > order.orderedTimestamp + order.resultsUploadDeadline) revert DeadlineMissed();
        if (!labTestPayments[_labTestId]) revert PaymentNotConfirmed();

        order.resultsIpfsHash = _resultsIpfsHash;
        order.status = LabTestStatus.ResultsUploaded;
        order.disputeWindowEnd = uint48(block.timestamp) + disputeWindow;
        emit LabTestUploaded(_labTestId, _resultsIpfsHash);
        emit LabTestDisputeWindowStarted(_labTestId, order.patient, order.disputeWindowEnd);
        services.monetizeData(order.patient);
    }

    /// @notice Releases payment for a lab test after dispute window
    function releaseLabTestPayment(uint256 _labTestId) external nonReentrant whenNotPaused {
        LabTestOrder storage order = labTestOrders[_labTestId];
        if (_labTestId == 0 || _labTestId > labTestCounter) revert InvalidIndex();
        if (order.status != LabTestStatus.ResultsUploaded && order.status != LabTestStatus.Reviewed && order.status != LabTestStatus.Disputed) revert InvalidStatus();
        if (block.timestamp <= order.disputeWindowEnd) revert InvalidTimestamp();
        if (!labTestPayments[_labTestId]) revert PaymentNotConfirmed();

        bool isDisputed = disputeResolution.isDisputed(_labTestId);
        if (isDisputed) {
            DisputeOutcome outcome = disputeResolution.getDisputeOutcome(_labTestId);
            if (outcome == DisputeOutcome.Unresolved) revert InvalidStatus();

            if (outcome == DisputeOutcome.PatientFavored) {
                payments._refundPatient(order.patient, order.patientCost, order.paymentType);
                emit LabTestRefunded(_labTestId, order.patient, order.patientCost);
            } else if (outcome == DisputeOutcome.ProviderFavored || outcome == DisputeOutcome.MutualAgreement) {
                // Updated: Use _releasePayment with queuing
                _releasePayment(order.labTech, order.patientCost, order.paymentType);
                emit LabTestPaymentReleased(_labTestId, order.labTech, order.patientCost, order.paymentType);
            }
            order.status = LabTestStatus.Disputed;
            services.notifyDisputeResolved(_labTestId, "LabTest", outcome);
        } else {
            // Updated: Use _releasePayment with queuing
            _releasePayment(order.labTech, order.patientCost, order.paymentType);
            emit LabTestPaymentReleased(_labTestId, order.labTech, order.patientCost, order.paymentType);
        }

        labTestPayments[_labTestId] = false;
    }

    /// @notice Checks and reorders lab tests if deadlines are missed
    function checkLabTestDeadlines(uint256 _labTestId) external nonReentrant whenNotPaused {
        LabTestOrder storage order = labTestOrders[_labTestId];
        if (_labTestId == 0 || _labTestId > labTestCounter) revert InvalidIndex();
        if (order.status == LabTestStatus.Reviewed || order.status == LabTestStatus.Disputed || order.status == LabTestStatus.Expired) return;

        bool missedDeadline = false;
        if (order.status == LabTestStatus.Requested && block.timestamp > order.orderedTimestamp + order.sampleCollectionDeadline) {
            missedDeadline = true;
        } else if (order.status == LabTestStatus.Collected && block.timestamp > order.orderedTimestamp + order.resultsUploadDeadline) {
            missedDeadline = true;
        } else if (order.status == LabTestStatus.PaymentPending && block.timestamp > labTestPaymentDeadlines[_labTestId]) {
            missedDeadline = true;
        }

        if (missedDeadline) {
            string memory locality = services.getLabTechLocality(order.labTech);
            address newLabTech = selectBestLabTech(order.testTypeIpfsHash, locality);
            if (newLabTech == order.labTech || newLabTech == address(0)) revert NoLabTechAvailable();

            (uint256 price, bool isValid, uint48 sampleDeadline, uint48 resultsDeadline) = services.getLabTestDetails(newLabTech, order.testTypeIpfsHash);
            if (!isValid) revert InvalidStatus();

            if (order.patientCost > 0 && labTestPayments[_labTestId]) {
                payments._refundPatient(order.patient, order.patientCost, order.paymentType);
                emit LabTestRefunded(_labTestId, order.patient, order.patientCost);
            }

            order.status = LabTestStatus.Expired;
            labTestCounter = labTestCounter + 1;
            uint256 newTestId = labTestCounter;
            uint256 patientCost = price * 120 / PERCENTAGE_DENOMINATOR;

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
                requestLabTestPrice(newLabTech, order.testTypeIpfsHash, newTestId);
            } else {
                labTestPayments[newTestId] = true;
                emit LabTestPaymentConfirmed(newTestId, patientCost);
            }

            emit LabTestOrdered(newTestId, order.patient, order.doctor, order.testTypeIpfsHash, uint48(block.timestamp));
            emit LabTestReordered(_labTestId, newTestId, newLabTech, order.patient);
            services.monetizeData(order.patient);
        }
    }

    /// @notice Reviews lab results and issues a prescription
    function reviewLabResults(uint256 _labTestId, string calldata _medicationIpfsHash, string calldata _prescriptionIpfsHash, address _pharmacy, string calldata _locality)
        external payable onlyRole(core.DOCTOR_ROLE()) nonReentrant whenNotPaused {
        LabTestOrder storage order = labTestOrders[_labTestId];
        if (order.doctor != msg.sender) revert NotAuthorized();
        if (order.status != LabTestStatus.ResultsUploaded) revert InvalidStatus();
        if (_labTestId == 0 || _labTestId > labTestCounter) revert InvalidIndex();
        if (_pharmacy == address(0)) revert InvalidAddress();
        if (!services.isPharmacyRegistered(_pharmacy) && !services.hasPharmacyInLocality(_locality)) revert NotAuthorized();
        if (bytes(_medicationIpfsHash).length == 0 || bytes(_prescriptionIpfsHash).length == 0 || bytes(_locality).length == 0) revert InvalidIpfsHash();

        (uint256 price, bool isValid) = services.getPharmacyPrice(_pharmacy, _medicationIpfsHash);
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
            requestPrescriptionPrice(_pharmacy, _medicationIpfsHash, newPrescriptionId);
        } else {
            prescription.patientCost = price * 120 / PERCENTAGE_DENOMINATOR;
            if (msg.value < prescription.patientCost) revert InsufficientFunds();
            prescription.prescriptionIpfsHash = _prescriptionIpfsHash;
            prescriptionPayments[newPrescriptionId] = true;
            emit PrescriptionPaymentConfirmed(newPrescriptionId, prescription.patientCost);
            if (msg.value > prescription.patientCost) {
                uint256 refund = msg.value - prescription.patientCost;
                _safeTransferETH(msg.sender, refund);
            }
        }

        emit PrescriptionIssued(newPrescriptionId, order.patient, msg.sender, verificationCodeHash, uint48(block.timestamp));
        services.monetizeData(order.patient);
    }

    /// @notice Verifies a prescription with a verification code
    function verifyPrescription(uint256 _prescriptionId, bytes32 _verificationCodeHash)
        external onlyRole(core.PHARMACY_ROLE()) nonReentrant whenNotPaused {
        Prescription storage prescription = prescriptions[_prescriptionId];
        if (prescription.pharmacy != msg.sender) revert NotAuthorized();
        if (prescription.status != PrescriptionStatus.Generated) revert InvalidStatus();
        if (prescription.verificationCodeHash != _verificationCodeHash) revert NotAuthorized();
        if (block.timestamp > prescription.expirationTimestamp) revert InvalidTimestamp();
        if (_prescriptionId == 0 || _prescriptionId > prescriptionCounter) revert InvalidIndex();
        if (!prescriptionPayments[_prescriptionId]) revert PaymentNotConfirmed();
        if (bytes(prescription.prescriptionIpfsHash).length == 0) revert InvalidIpfsHash();

        prescription.status = PrescriptionStatus.Verified;
        emit PrescriptionVerified(_prescriptionId, msg.sender);
    }

    /// @notice Fulfills a verified prescription
    function fulfillPrescription(uint256 _prescriptionId)
        external onlyRole(core.PHARMACY_ROLE()) nonReentrant whenNotPaused {
        Prescription storage prescription = prescriptions[_prescriptionId];
        if (prescription.pharmacy != msg.sender) revert NotAuthorized();
        if (prescription.status != PrescriptionStatus.Verified) revert InvalidStatus();
        if (block.timestamp > prescription.expirationTimestamp) revert InvalidTimestamp();
        if (_prescriptionId == 0 || _prescriptionId > prescriptionCounter) revert InvalidIndex();
        if (!prescriptionPayments[_prescriptionId]) revert PaymentNotConfirmed();

        prescription.status = PrescriptionStatus.Fulfilled;
        prescription.disputeWindowEnd = uint48(block.timestamp) + disputeWindow;
        emit PrescriptionFulfilled(_prescriptionId);
        emit PrescriptionDisputeWindowStarted(_prescriptionId, prescription.patient, prescription.disputeWindowEnd);
    }

    /// @notice Releases payment for a prescription after dispute window
    function releasePrescriptionPayment(uint256 _prescriptionId) external nonReentrant whenNotPaused {
        Prescription storage prescription = prescriptions[_prescriptionId];
        if (_prescriptionId == 0 || _prescriptionId > prescriptionCounter) revert InvalidIndex();
        if (prescription.status != PrescriptionStatus.Fulfilled && prescription.status != PrescriptionStatus.Disputed) revert InvalidStatus();
        if (block.timestamp <= prescription.disputeWindowEnd) revert InvalidTimestamp();
        if (!prescriptionPayments[_prescriptionId]) revert PaymentNotConfirmed();

        bool isDisputed = disputeResolution.isDisputed(_prescriptionId);
        if (isDisputed) {
            DisputeOutcome outcome = disputeResolution.getDisputeOutcome(_prescriptionId);
            if (outcome == DisputeOutcome.Unresolved) revert InvalidStatus();

            if (outcome == DisputeOutcome.PatientFavored) {
                payments._refundPatient(prescription.patient, prescription.patientCost, prescription.paymentType);
                emit PrescriptionRefunded(_prescriptionId, prescription.patient, prescription.patientCost);
            } else if (outcome == DisputeOutcome.ProviderFavored || outcome == DisputeOutcome.MutualAgreement) {
                // Updated: Use _releasePayment with queuing
                _releasePayment(prescription.pharmacy, prescription.patientCost, prescription.paymentType);
                emit PrescriptionPaymentReleased(_prescriptionId, prescription.pharmacy, prescription.patientCost, prescription.paymentType);
            }
            prescription.status = PrescriptionStatus.Disputed;
            services.notifyDisputeResolved(_prescriptionId, "Prescription", outcome);
        } else {
            // Updated: Use _releasePayment with queuing
            _releasePayment(prescription.pharmacy, prescription.patientCost, prescription.paymentType);
            emit PrescriptionPaymentReleased(_prescriptionId, prescription.pharmacy, prescription.patientCost, prescription.paymentType);
        }

        prescriptionPayments[_prescriptionId] = false;
    }

    /// @notice Orders a replacement prescription
    function orderReplacementPrescription(uint256 _originalPrescriptionId, bytes32 _operationHash)
        external onlyDisputeResolution nonReentrant whenNotPaused onlyMultiSig(_operationHash) {
        bytes32 expectedHash = keccak256(abi.encodePacked(
            "orderReplacementPrescription",
            _originalPrescriptionId,
            msg.sender,
            block.timestamp,
            nonces[msg.sender]++
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
        prescriptionPayments[newPrescriptionId] = true;

        emit PrescriptionIssued(newPrescriptionId, original.patient, original.doctor, newVerificationCodeHash, uint48(block.timestamp));
        emit ReplacementPrescriptionOrdered(_originalPrescriptionId, newPrescriptionId);
    }

    /// @notice Requests an AI symptom analysis
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
            services.notifyDataRewardClaimed(msg.sender, 0);
        }

        core._levelUp(msg.sender);
        emit AISymptomAnalyzed(aiAnalysisCounter, msg.sender);
        services.monetizeData(msg.sender);
    }

    /// @notice Reviews an AI symptom analysis
    function reviewAISymptomAnalysis(uint256 _aiAnalysisId, string calldata _analysisIpfsHash)
        external onlyRole(core.DOCTOR_ROLE()) nonReentrant whenNotPaused {
        AISymptomAnalysis storage analysis = aiAnalyses[_aiAnalysisId];
        if (analysis.doctorReviewed) revert InvalidStatus();
        if (_aiAnalysisId == 0 || _aiAnalysisId > aiAnalysisCounter) revert InvalidIndex();
        if (bytes(_analysisIpfsHash).length == 0) revert InvalidIpfsHash();

        analysis.analysisIpfsHash = _analysisIpfsHash;
        analysis.doctorReviewed = true;
    }

    /// @notice Withdraws funds from the contract
    function withdrawFunds(
        address _recipient,
        uint256 _amount,
        TelemedicinePayments.PaymentType _paymentType,
        bytes32 _operationHash
    ) external onlyRole(core.ADMIN_ROLE()) nonReentrant whenNotPaused onlyMultiSig(_operationHash) {
        bytes32 expectedHash = keccak256(abi.encodePacked(
            "withdrawFunds",
            _recipient,
            _amount,
            _paymentType,
            msg.sender,
            block.timestamp,
            nonces[msg.sender]++
        ));
        if (_operationHash != expectedHash) revert MultiSigNotApproved();

        if (_recipient == address(0)) revert InvalidAddress();
        if (_amount == 0) revert InsufficientFunds();

        // Updated: Use _releasePayment with queuing
        _releasePayment(_recipient, _amount, _paymentType);
        emit FundsWithdrawn(_recipient, _amount, _paymentType);
    }

    // Added: Manual override functions for Chainlink failures
    /// @notice Manual override for lab test price if Chainlink fails
    function setManualLabTestPrice(uint256 _labTestId, uint256 _price) external onlyRole(core.ADMIN_ROLE()) {
        if (!manualPriceOverride) revert NotAuthorized();
        if (_labTestId == 0 || _labTestId > labTestCounter) revert InvalidIndex();
        LabTestOrder storage order = labTestOrders[_labTestId];
        if (order.status != LabTestStatus.Requested) revert InvalidStatus();
        if (_price == 0) revert InsufficientFunds();

        order.patientCost = _price * 120 / PERCENTAGE_DENOMINATOR;
        order.status = LabTestStatus.PaymentPending;
        labTestPaymentDeadlines[_labTestId] = uint48(block.timestamp) + paymentConfirmationDeadline;
        emit LabTestPaymentPending(_labTestId, order.patientCost, labTestPaymentDeadlines[_labTestId]);
    }

    /// @notice Manual override for prescription price if Chainlink fails
    function setManualPrescriptionPrice(uint256 _prescriptionId, uint256 _price) external onlyRole(core.ADMIN_ROLE()) {
        if (!manualPriceOverride) revert NotAuthorized();
        if (_prescriptionId == 0 || _prescriptionId > prescriptionCounter) revert InvalidIndex();
        Prescription storage prescription = prescriptions[_prescriptionId];
        if (prescription.status != PrescriptionStatus.Generated) revert InvalidStatus();
        if (_price == 0) revert InsufficientFunds();

        prescription.patientCost = _price * 120 / PERCENTAGE_DENOMINATOR;
        prescription.status = PrescriptionStatus.PaymentPending;
        prescriptionPaymentDeadlines[_prescriptionId] = uint48(block.timestamp) + paymentConfirmationDeadline;
        emit PrescriptionPaymentPending(_prescriptionId, prescription.patientCost, prescriptionPaymentDeadlines[_prescriptionId]);
    }

    /// @notice Toggles Chainlink manual override mode
    function toggleManualPriceOverride(bool _enabled) external onlyRole(core.ADMIN_ROLE()) {
        manualPriceOverride = _enabled;
    }

    // Added: Function to release queued payments
    /// @notice Releases queued payments when funds are available
    function releasePendingPayments(uint256 _startId, uint256 _count) external onlyRole(core.ADMIN_ROLE()) nonReentrant {
        uint256 endId = _startId + _count > pendingPaymentCounter ? pendingPaymentCounter : _startId + _count;
        for (uint256 i = _startId; i < endId; i++) {
            PendingPayment storage payment = pendingPayments[i];
            if (payment.processed || payment.amount == 0) continue;

            if (_hasSufficientFunds(payment.amount, payment.paymentType)) {
                _releasePayment(payment.recipient, payment.amount, payment.paymentType);
                payment.processed = true;
                emit PaymentReleasedFromQueue(i, payment.recipient, payment.amount);
            }
        }
    }

    // Internal Functions

    /// @notice Selects the best lab technician based on rating, capacity, and price
    function selectBestLabTech(string memory _testTypeIpfsHash, string memory _locality) internal view returns (address) {
        (address[] memory labTechs, ) = services.getLabTechsInLocality(_locality, 0, maxBatchSize);
        if (labTechs.length == 0) return address(0);

        address bestLabTech = address(0);
        uint256 highestScore = 0;
        address fallbackTech = address(0);

        for (uint256 i = 0; i < labTechs.length; i++) {
            if (!services.isLabTechRegistered(labTechs[i])) continue;
            (uint256 price, bool isValid, , ) = services.getLabTestDetails(labTechs[i], _testTypeIpfsHash);
            if (!isValid || price == 0) continue;
            uint256 capacity = services.getLabTechCapacity(labTechs[i]);
            if (capacity == 0) continue;

            if (fallbackTech == address(0)) fallbackTech = labTechs[i];
            (uint256 avgRating, uint256 ratingCount) = services.getLabTechRating(labTechs[i]);
            uint256 score = (avgRating > 0 && ratingCount > 0) ? avgRating * ratingCount / price : 0;

            if (score > highestScore) {
                highestScore = score;
                bestLabTech = labTechs[i];
            }
        }
        return bestLabTech != address(0) ? bestLabTech : fallbackTech;
    }

    /// @notice Adds an appointment to a doctor's pending list
    function _addPendingAppointment(address _doctor, uint256 _appointmentId) internal {
        PendingAppointments storage pending = doctorPendingAppointments[_doctor];
        if (pending.count >= core.MAX_PENDING_APPOINTMENTS()) revert InvalidPageSize();
        pending.appointmentIds[_appointmentId] = pending.count;
        pending.ids.push(_appointmentId);
        pending.count = pending.count + 1;
    }

    /// @notice Removes an appointment from a doctor's pending list
    function _removePendingAppointment(address _doctor, uint256 _appointmentId) internal {
        PendingAppointments storage pending = doctorPendingAppointments[_doctor];
        uint256 index = pending.appointmentIds[_appointmentId];
        if (index >= pending.count) revert InvalidIndex();

        if (index != pending.count - 1) {
            uint256 lastId = pending.ids[pending.count - 1];
            pending.ids[index] = lastId;
            pending.appointmentIds[lastId] = index;
        }
        pending.ids.pop();
        delete pending.appointmentIds[_appointmentId];
        pending.count = pending.count - 1;
    }

    /// @notice Checks if a doctor has pending priority appointments
    function _hasPendingPriorityAppointments(address _doctor) internal view returns (bool) {
        PendingAppointments storage pending = doctorPendingAppointments[_doctor];
        for (uint256 i = 0; i < pending.count; i++) {
            if (appointments[pending.ids[i]].isPriority) return true;
        }
        return false;
    }

    /// @notice Converts an address to a string
    function toString(address _addr) internal pure returns (string memory) {
        bytes32 value = bytes32(uint256(uint160(_addr)));
        bytes memory alphabet = "0123456789abcdef";
        bytes memory str = new bytes(42);
        str[0] = "0";
        str[1] = "x";
        for (uint256 i = 0; i < 20; i++) {
            str[2 + i * 2] = alphabet[uint8(value[i + 12] >> 4)];
            str[3 + i * 2] = alphabet[uint8(value[i + 12] & 0x0f)];
        }
        return string(str);
    }

    /// @notice Safely transfers ETH to an address
    function _safeTransferETH(address _to, uint256 _amount) internal {
        (bool success, ) = _to.call{value: _amount}("");
        if (!success) revert PaymentFailed();
    }

    /// @notice Releases payment to a recipient with queuing if funds are insufficient
    function _releasePayment(address _to, uint256 _amount, TelemedicinePayments.PaymentType _paymentType) internal {
        if (!_hasSufficientFunds(_amount, _paymentType)) {
            pendingPaymentCounter++;
            pendingPayments[pendingPaymentCounter] = PendingPayment(_to, _amount, _paymentType, false);
            emit PaymentQueued(pendingPaymentCounter, _to, _amount, _paymentType);
            return;
        }

        if (_paymentType == TelemedicinePayments.PaymentType.ETH) {
            _safeTransferETH(_to, _amount);
        } else if (_paymentType == TelemedicinePayments.PaymentType.USDC) {
            payments.usdcToken().safeTransfer(_to, _amount);
        } else if (_paymentType == TelemedicinePayments.PaymentType.SONIC) {
            payments.sonicToken().safeTransfer(_to, _amount);
        } else {
            revert InvalidStatus();
        }
    }

    /// @notice Checks if sufficient funds are available for a payment
    function _hasSufficientFunds(uint256 _amount, TelemedicinePayments.PaymentType _paymentType) internal view returns (bool) {
        if (_paymentType == TelemedicinePayments.PaymentType.ETH) {
            return address(this).balance >= _amount;
        } else if (_paymentType == TelemedicinePayments.PaymentType.USDC) {
            return payments.usdcToken().balanceOf(address(this)) >= _amount;
        } else if (_paymentType == TelemedicinePayments.PaymentType.SONIC) {
            return payments.sonicToken().balanceOf(address(this)) >= _amount;
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
