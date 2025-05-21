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
import "./ITelemedicinePayments.sol";
import "./TelemedicineDisputeResolution.sol";
import "./TelemedicineMedicalServices.sol";

/// @title TelemedicineOperations
/// @notice Manages appointments, lab tests, prescriptions, AI symptom analyses, payment queues, and provider invitations
/// @dev UUPS upgradeable, integrates with Chainlink for pricing and AI services, uses SafeERC20 for token transfers
/// @dev Sonic $S reward validation is centralized in TelemedicinePayments
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
    error InvalidSymptoms();
    error AnalysisNotPending();
    error AlreadyReviewed();

    // Constants
    uint256 public constant RESERVE_FUND_THRESHOLD = 1 ether;
    uint256 public constant MIN_IPFS_HASH_LENGTH = 46;
    uint48 public constant CHAINLINK_TIMEOUT = 1 hours;
    uint256 public constant MAX_DOCTORS_PER_APPOINTMENT = 5;
    uint256 public constant MIN_SYMPTOMS_LENGTH = 10;
    uint256 public constant MAX_SYMPTOMS_LENGTH = 1000;
    uint256 public constant AI_ANALYSIS_FEE = 10 * 10**6; // 10 USDC (6 decimals)

    // Configurable Parameters
    uint256 public maxPendingAppointments;
    uint48 public chainlinkTimeout;
    uint256 public aiAnalysisFee; // AI analysis fee in USDC (6 decimals)

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
    mapping(bytes32 => uint256) public requestToLabTestId;
    mapping(bytes32 => uint256) public requestToPrescriptionId;
    mapping(bytes32 => uint256) public requestToAnalysisId;
    mapping(bytes32 => uint48) public requestTimestamps;
    mapping(uint256 => uint256) public appointmentToDisputeIds;
    mapping(uint256 => uint256) public labTestToDisputeIds;
    mapping(uint256 => uint256) public aiAnalysisToDisputeIds;
    uint256 public appointmentCounter;
    uint256 public labTestCounter;
    uint256 public prescriptionCounter;
    uint256 public aiAnalysisCounter;
    uint256 public versionNumber;
    uint256 public pendingPaymentCounter;
    uint256 public invitationCounter;

    // Payment Queue
    struct PendingPayment {
        address recipient;
        uint256 amount;
        ITelemedicinePayments.PaymentType paymentType;
        bool processed;
    }
    mapping(uint256 => PendingPayment) public pendingPayments;

    // Invitation Mechanism
    struct Invitation {
        address patient;
        string locality;
        bytes32 inviteeContactHash;
        bool isLabTech;
        bool fulfilled;
        uint48 expirationTimestamp;
    }
    mapping(bytes32 => Invitation) public invitations;

    // Structs
    struct Appointment {
        uint256 id;
        address patient;
        address[] doctors;
        uint48 scheduledTimestamp;
        AppointmentStatus status;
        uint96 fee;
        ITelemedicinePayments.PaymentType paymentType;
        bool isVideoCall;
        bool isPriority;
        bytes32 videoCallLinkHash;
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
        ITelemedicinePayments.PaymentType paymentType;
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
        address doctor;
        AISymptomStatus status;
        string symptoms;
        string analysisIpfsHash;
        uint256 cost;
        uint48 requestTimestamp;
        uint48 disputeWindowEnd;
        DisputeOutcome disputeOutcome;
        ITelemedicinePayments.PaymentType paymentType;
    }

    struct PendingAppointments {
        uint256[] ids;
        mapping(uint256 => uint256) indices;
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
    enum AISymptomStatus { Requested, Pending, Completed, Reviewed, Cancelled, Disputed }

    // External Contracts
    TelemedicineCore public core;
    ITelemedicinePayments public payments;
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
    event DoctorPaid(uint256 indexed appointmentId, address indexed doctor, uint256 amount, ITelemedicinePayments.PaymentType paymentType);
    event ReserveFundAllocated(uint256 indexed appointmentId, uint256 amount, ITelemedicinePayments.PaymentType paymentType);
    event PlatformFeeAllocated(uint256 indexed appointmentId, uint256 amount, ITelemedicinePayments.PaymentType paymentType);
    event InvitationSubmitted(bytes32 indexed invitationId, address patient, string locality, bool isLabTech);
    event InvitationFulfilled(bytes32 indexed invitationId, address invitee);
    event InvitationExpired(bytes32 indexed invitationId);
    event LabTestPaymentConfirmed(uint256 indexed testId, uint256 amount);
    event PrescriptionPaymentConfirmed(uint256 indexed prescriptionId, uint256 amount);
    event PaymentQueued(uint256 indexed paymentId, address recipient, uint256 amount, ITelemedicinePayments.PaymentType paymentType);
    event PaymentReleasedFromQueue(uint256 indexed paymentId, address recipient, uint256 amount);
    event MaxPendingAppointmentsUpdated(uint256 newMax);
    event ChainlinkTimeoutUpdated(uint48 newTimeout);
    event AISymptomAnalysisRequested(uint256 indexed analysisId, address patient, string symptoms, uint48 requestedAt);
    event AISymptomAnalysisFulfilled(uint256 indexed analysisId, string analysisIpfsHash);
    event AISymptomAnalysisReviewed(uint256 indexed analysisId, address doctor);
    event AISymptomAnalysisCancelled(uint256 indexed analysisId);
    event AIAnalysisFeeUpdated(uint256 newFee);

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
        payments = ITelemedicinePayments(_payments);
        disputeResolution = TelemedicineDisputeResolution(_disputeResolution);
        services = TelemedicineMedicalServices(_services);

        appointmentCounter = 0;
        labTestCounter = 0;
        prescriptionCounter = 0;
        aiAnalysisCounter = 0;
        invitationCounter = 0;
        pendingPaymentCounter = 0;
        maxPendingAppointments = 100;
        chainlinkTimeout = CHAINLINK_TIMEOUT;
        aiAnalysisFee = AI_ANALYSIS_FEE;
        versionNumber = 1;

        emit MaxPendingAppointmentsUpdated(100);
        emit ChainlinkTimeoutUpdated(CHAINLINK_TIMEOUT);
        emit AIAnalysisFeeUpdated(AI_ANALYSIS_FEE);
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

    /// @notice Updates AI analysis fee (admin only)
    /// @param _newFee New fee in USDC (6 decimals, minimum 1 USDC)
    function updateAIAnalysisFee(uint256 _newFee) external onlyRole(core.ADMIN_ROLE()) {
        if (_newFee < 1 * 10**6) revert InsufficientFunds();
        aiAnalysisFee = _newFee;
        emit AIAnalysisFeeUpdated(_newFee);
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
        ITelemedicinePayments.PaymentType _paymentType,
        bool _isVideoCall,
        bytes32 _videoCallLinkHash
    ) external payable onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
        if (_doctors.length == 0 || _doctors.length > MAX_DOCTORS_PER_APPOINTMENT) revert InvalidAddress();
        for (uint256 i = 0; i < _doctors.length; i++) {
            if (_doctors[i] == address(0) || !core.doctors(_doctors[i]).isVerified) revert NotAuthorized();
        }
        if (_timestamp <= block.timestamp + core.minBookingBuffer()) revert InvalidTimestamp();
        if (_isVideoCall && _videoCallLinkHash == bytes32(0)) revert InvalidIpfsHash();
        if (disputeResolution.isDisputed(appointmentCounter + 1)) revert InvalidStatus();

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

        if (_paymentType == ITelemedicinePayments.PaymentType.ETH) {
            if (msg.value < discountedFee) revert InsufficientFunds();
            core.reserveFundETH = core.reserveFundETH.add(reserveAmount);
            emit ReserveFundAllocated(newAppointmentId, reserveAmount, _paymentType);
            emit PlatformFeeAllocated(newAppointmentId, platformAmount, _paymentType);
            if (msg.value > discountedFee) {
                _safeTransferETH(msg.sender, msg.value.sub(discountedFee));
            }
        } else {
            try payments._processPayment(_paymentType, discountedFee) {
                if (_paymentType == ITelemedicinePayments.PaymentType.USDC) {
                    payments.usdcToken().safeTransferFrom(address(payments), address(this), reserveAmount);
                    core.reserveFundUSDC = core.reserveFundUSDC.add(reserveAmount);
                } else if (_paymentType == ITelemedicinePayments.PaymentType.SONIC) {
                    payments.sonicNativeToken().safeTransferFrom(address(payments), address(this), reserveAmount);
                    core.reserveFundSONIC = core.reserveFundSONIC.add(reserveAmount);
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

        DisputeOutcome outcome = DisputeOutcome.Unresolved;
        uint256 disputeId = appointmentToDisputeIds[_appointmentId];
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
        if (disputeResolution.isDisputed(labTestCounter + 1)) revert InvalidStatus();

        address selectedLabTech = selectBestLabTech(_testTypeIpfsHash, _locality);
        if (selectedLabTech == address(0)) revert NoLabTechAvailable();

        (uint256 price, bool isValid) = services.getLabTechPrice(selectedLabTech, _testTypeIpfsHash);
        if (!isValid) revert InvalidStatus();

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
            patientCost: price.mul(120).div(core.PERCENTAGE_DENOMINATOR()),
            disputeWindowEnd: uint48(block.timestamp).add(core.disputeWindow()),
            disputeOutcome: DisputeOutcome.Unresolved,
            sampleCollectionDeadline: uint48(block.timestamp + 7 days),
            resultsUploadDeadline: uint48(block.timestamp + 14 days),
            paymentType: ITelemedicinePayments.PaymentType.ETH
        });

        if (price == 0) {
            requestLabTestPrice(selectedLabTech, _testTypeIpfsHash, newTestId);
        } else {
            if (msg.value < labTestOrders[newTestId].patientCost) revert InsufficientFunds();
            labTestPayments[newTestId] = true;
            emit LabTestPaymentConfirmed(newTestId, labTestOrders[newTestId].patientCost);
            if (msg.value > labTestOrders[newTestId].patientCost) {
                _safeTransferETH(msg.sender, msg.value.sub(labTestOrders[newTestId].patientCost));
            }
        }

        emit LabTestOrdered(newTestId, _patient, msg.sender, _testTypeIpfsHash, uint48(block.timestamp));
        try services.monetizeData(_patient, labTestOrders[newTestId].patientCost) {
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
        if (core.manualPriceOverride()) {
            labTestOrders[_labTestId].patientCost = 0.01 ether;
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
        if (block.timestamp > requestTimestamps[_requestId] + chainlinkTimeout) revert ChainlinkRequestTimeout();

        uint256 labTestId = requestToLabTestId[_requestId];
        if (labTestId == 0 || labTestId > labTestCounter) revert InvalidIndex();
        LabTestOrder storage order = labTestOrders[labTestId];
        if (order.status != LabTestStatus.Requested) revert InvalidStatus();
        if (_price == 0) {
            order.patientCost = 0.01 ether;
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
        if (disputeResolution.isDisputed(prescriptionCounter + 1)) revert InvalidStatus();

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
            disputeWindowEnd: uint48(block.timestamp).add(core.disputeWindow()),
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
                _safeTransferETH(msg.sender, msg.value.sub(prescriptions[newPrescriptionId].patientCost));
            }
        }

        emit PrescriptionIssued(newPrescriptionId, _patient, msg.sender, verificationCodeHash, uint48(block.timestamp));
        try services.monetizeData(_patient, prescriptions[newPrescriptionId].patientCost) {
            // Success
        } catch {
            // Log failure but don't revert
        }
    }

    /// @notice Requests prescription price from Chainlink oracle
    /// @param _pharmacy Pharmacy address
    /// @param _medicationIpfsHash IPFS hash of the medication
    /// @param _prescriptionId Prescription ID
    function requestPrescriptionPrice(address _pharmacy, string calldata _medicationIpfsHash, uint256 _prescriptionId) internal returns (bytes32) {
        if (core.manualPriceOverride()) {
            prescriptions[_prescriptionId].patientCost = 0.005 ether;
            prescriptions[_prescriptionId].status = PrescriptionStatus.PaymentPending;
            prescriptionPaymentDeadlines[_prescriptionId] = uint48(block.timestamp).add(core.paymentConfirmationDeadline());
            emit PrescriptionPaymentConfirmed(_prescriptionId, prescriptions[_prescriptionId].patientCost);
            return bytes32(0);
        }
        Chainlink.Request memory req = buildChainlinkRequest(core.priceListJobId(), address(this), this.fulfillPrescriptionPrice.selector);
        req.add("medication", _medicationIpfsHash);
        req.add("pharmacy", toString(_pharmacy));
        bytes32 requestId = sendChainlinkRequestTo(core.chainlinkOracle(), req, core.chainlinkFee());
        requestToPrescriptionId[requestId] = _prescriptionId;
        requestTimestamps[requestId] = uint48(block.timestamp);
        return requestId;
    }

    /// @notice Handles Chainlink prescription price response
    /// @param _requestId Chainlink request ID
    /// @param _price Returned price
    function fulfillPrescriptionPrice(bytes32 _requestId, uint256 _price) public recordChainlinkFulfillment(_requestId) {
        if (block.timestamp > requestTimestamps[_requestId] + chainlinkTimeout) revert ChainlinkRequestTimeout();

        uint256 prescriptionId = requestToPrescriptionId[_requestId];
        if (prescriptionId == 0 || prescriptionId > prescriptionCounter) revert InvalidIndex();
        Prescription storage prescription = prescriptions[prescriptionId];
        if (prescription.status != PrescriptionStatus.Generated) revert InvalidStatus();
        if (_price == 0) {
            prescription.patientCost = 0.005 ether;
        } else {
            prescription.patientCost = _price.mul(120).div(core.PERCENTAGE_DENOMINATOR());
        }

        prescription.status = PrescriptionStatus.PaymentPending;
        prescriptionPaymentDeadlines[prescriptionId] = uint48(block.timestamp).add(core.paymentConfirmationDeadline());
        delete requestToPrescriptionId[_requestId];
        delete requestTimestamps[_requestId];
        emit PrescriptionPaymentConfirmed(prescriptionId, prescription.patientCost);
    }

    // AI Symptom Analysis Functions

    /// @notice Requests an AI symptom analysis
    /// @param _symptoms Description of patient symptoms
    /// @param _paymentType Payment type (ETH, USDC, SONIC)
    function requestAISymptomAnalysis(string calldata _symptoms, ITelemedicinePayments.PaymentType _paymentType)
        external payable onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused
    {
        if (bytes(_symptoms).length < MIN_SYMPTOMS_LENGTH || bytes(_symptoms).length > MAX_SYMPTOMS_LENGTH) revert InvalidSymptoms();
        if (disputeResolution.isDisputed(aiAnalysisCounter + 1)) revert InvalidStatus();

        aiAnalysisCounter = aiAnalysisCounter.add(1);
        uint256 newAnalysisId = aiAnalysisCounter;

        aiAnalyses[newAnalysisId] = AISymptomAnalysis({
            id: newAnalysisId,
            patient: msg.sender,
            doctor: address(0),
            status: AISymptomStatus.Requested,
            symptoms: _symptoms,
            analysisIpfsHash: "",
            cost: aiAnalysisFee,
            requestTimestamp: uint48(block.timestamp),
            disputeWindowEnd: 0,
            disputeOutcome: DisputeOutcome.Unresolved,
            paymentType: _paymentType
        });

        if (_paymentType == ITelemedicinePayments.PaymentType.ETH) {
            if (msg.value < aiAnalysisFee) revert InsufficientFunds();
            uint256 reserveAmount = aiAnalysisFee.mul(core.reserveFundPercentage()).div(core.PERCENTAGE_DENOMINATOR());
            core.reserveFundETH = core.reserveFundETH.add(reserveAmount);
            emit ReserveFundAllocated(newAnalysisId, reserveAmount, _paymentType);
            if (msg.value > aiAnalysisFee) {
                _safeTransferETH(msg.sender, msg.value.sub(aiAnalysisFee));
            }
        } else {
            try payments._processPayment(_paymentType, aiAnalysisFee) {
                uint256 reserveAmount = aiAnalysisFee.mul(core.reserveFundPercentage()).div(core.PERCENTAGE_DENOMINATOR());
                if (_paymentType == ITelemedicinePayments.PaymentType.USDC) {
                    payments.usdcToken().safeTransferFrom(address(payments), address(this), reserveAmount);
                    core.reserveFundUSDC = core.reserveFundUSDC.add(reserveAmount);
                } else if (_paymentType == ITelemedicinePayments.PaymentType.SONIC) {
                    payments.sonicNativeToken().safeTransferFrom(address(payments), address(this), reserveAmount);
                    core.reserveFundSONIC = core.reserveFundSONIC.add(reserveAmount);
                }
                emit ReserveFundAllocated(newAnalysisId, reserveAmount, _paymentType);
            } catch {
                revert ExternalCallFailed();
            }
        }

        bytes32 requestId = requestAIAnalysis(_symptoms, newAnalysisId);
        aiAnalyses[newAnalysisId].status = AISymptomStatus.Pending;
        requestToAnalysisId[requestId] = newAnalysisId;

        emit AISymptomAnalysisRequested(newAnalysisId, msg.sender, _symptoms, uint48(block.timestamp));
    }

    /// @notice Requests AI analysis from an external service via Chainlink
    /// @param _symptoms Symptoms to analyze
    /// @param _analysisId Analysis ID
    /// @return Chainlink request ID
    function requestAIAnalysis(string memory _symptoms, uint256 _analysisId) internal returns (bytes32) {
        if (core.manualPriceOverride()) {
            aiAnalyses[_analysisId].analysisIpfsHash = "QmMockAnalysisHash";
            aiAnalyses[_analysisId].status = AISymptomStatus.Completed;
            aiAnalyses[_analysisId].disputeWindowEnd = uint48(block.timestamp).add(core.disputeWindow());
            emit AISymptomAnalysisFulfilled(_analysisId, aiAnalyses[_analysisId].analysisIpfsHash);
            return bytes32(0);
        }

        Chainlink.Request memory req = buildChainlinkRequest(
            core.aiAnalysisJobId(),
            address(this),
            this.fulfillAISymptomAnalysis.selector
        );
        req.add("symptoms", _symptoms);
        req.add("analysisId", toString(_analysisId));
        bytes32 requestId = sendChainlinkRequestTo(core.chainlinkOracle(), req, core.chainlinkFee());
        requestTimestamps[requestId] = uint48(block.timestamp);
        return requestId;
    }

    /// @notice Handles Chainlink AI analysis response
    /// @param _requestId Chainlink request ID
    /// @param _analysisIpfsHash IPFS hash of the AI analysis
    function fulfillAISymptomAnalysis(bytes32 _requestId, string calldata _analysisIpfsHash)
        public recordChainlinkFulfillment(_requestId)
    {
        if (block.timestamp > requestTimestamps[_requestId] + chainlinkTimeout) revert ChainlinkRequestTimeout();
        if (bytes(_analysisIpfsHash).length < MIN_IPFS_HASH_LENGTH) revert InvalidIpfsHash();

        uint256 analysisId = requestToAnalysisId[_requestId];
        if (analysisId == 0 || analysisId > aiAnalysisCounter) revert InvalidIndex();
        AISymptomAnalysis storage analysis = aiAnalyses[analysisId];
        if (analysis.status != AISymptomStatus.Pending) revert AnalysisNotPending();

        analysis.analysisIpfsHash = _analysisIpfsHash;
        analysis.status = AISymptomStatus.Completed;
        analysis.disputeWindowEnd = uint48(block.timestamp).add(core.disputeWindow());

        delete requestToAnalysisId[_requestId];
        delete requestTimestamps[_requestId];
        emit AISymptomAnalysisFulfilled(analysisId, _analysisIpfsHash);

        try services.monetizeData(analysis.patient, analysis.cost) {
            // Success
        } catch {
            // Log failure but don't revert
        }
    }

    /// @notice Allows a doctor to review an AI symptom analysis
    /// @param _analysisId Analysis ID
    /// @param _operationHash Multi-sig operation hash
    function reviewAISymptomAnalysis(uint256 _analysisId, bytes32 _operationHash)
        external onlyRole(core.DOCTOR_ROLE()) nonReentrant whenNotPaused onlyMultiSig(_operationHash)
    {
        AISymptomAnalysis storage analysis = aiAnalyses[_analysisId];
        if (_analysisId == 0 || _analysisId > aiAnalysisCounter) revert InvalidIndex();
        if (analysis.status != AISymptomStatus.Completed) revert InvalidStatus();
        if (analysis.doctor != address(0)) revert AlreadyReviewed();
        if (block.timestamp > analysis.disputeWindowEnd) revert DeadlineMissed();

        uint256 currentNonce = nonces[msg.sender];
        bytes32 expectedHash = keccak256(abi.encodePacked(
            "reviewAISymptomAnalysis",
            _analysisId,
            msg.sender,
            block.timestamp,
            currentNonce
        ));
        if (_operationHash != expectedHash) revert MultiSigNotApproved();
        nonces[msg.sender] = currentNonce.add(1);

        DisputeOutcome outcome = DisputeOutcome.Unresolved;
        uint256 disputeId = aiAnalysisToDisputeIds[_analysisId];
        try disputeResolution.isDisputed(_analysisId) returns (bool isDisputed) {
            if (isDisputed) {
                outcome = disputeResolution.getDisputeOutcome(_analysisId);
                if (outcome == DisputeOutcome.Unresolved) revert InvalidStatus();
                analysis.disputeOutcome = outcome;
            }
        } catch {
            revert ExternalCallFailed();
        }

        analysis.doctor = msg.sender;
        analysis.status = AISymptomStatus.Reviewed;

        uint256 reviewFee = aiAnalysisFee.mul(core.doctorFeePercentage()).div(core.PERCENTAGE_DENOMINATOR());
        _releasePayment(msg.sender, reviewFee, analysis.paymentType);
        emit DoctorPaid(_analysisId, msg.sender, reviewFee, analysis.paymentType);

        if (outcome != DisputeOutcome.Unresolved) {
            try services.notifyDisputeResolved(_analysisId, "AISymptomAnalysis", outcome) {
                // Success
            } catch {
                revert ExternalCallFailed();
            }
        }

        emit AISymptomAnalysisReviewed(_analysisId, msg.sender);
    }

    /// @notice Cancels a pending AI symptom analysis
    /// @param _analysisId Analysis ID
    function cancelAISymptomAnalysis(uint256 _analysisId)
        external onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused
    {
        AISymptomAnalysis storage analysis = aiAnalyses[_analysisId];
        if (_analysisId == 0 || _analysisId > aiAnalysisCounter) revert InvalidIndex();
        if (analysis.patient != msg.sender) revert NotAuthorized();
        if (analysis.status != AISymptomStatus.Requested && analysis.status != AISymptomStatus.Pending) revert InvalidStatus();

        analysis.status = AISymptomStatus.Cancelled;

        try payments._refundPatient(msg.sender, analysis.cost, analysis.paymentType) {
            // Success
        } catch {
            revert ExternalCallFailed();
        }

        emit AISymptomAnalysisCancelled(_analysisId);
    }

    // Invitation Functions

    /// @notice Invites a provider to a locality
    /// @param _locality Locality name
    /// @param _inviteeContactHash Hash of invitee contact info
    /// @param _isLabTech Whether the invitee is a lab technician
    function inviteProvider(string calldata _locality, bytes32 _inviteeContactHash, bool _isLabTech)
        external onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused
    {
        if (bytes(_locality).length == 0 || _inviteeContactHash == bytes32(0)) revert InvalidLocality();

        bool hasProvider = _isLabTech ? services.hasLabTechInLocality(_locality) : services.hasPharmacyInLocality(_locality);
        if (hasProvider) revert ProvidersAlreadyExist();

        bytes32 invitationId = keccak256(abi.encodePacked(msg.sender, _locality, _isLabTech, block.timestamp));
        if (invitations[invitationId].patient != address(0)) revert InvitationAlreadyExists();

        invitationCounter = invitationCounter.add(1);
        invitations[invitationId] = Invitation({
            patient: msg.sender,
            locality: _locality,
            inviteeContactHash: _inviteeContactHash,
            isLabTech: _isLabTech,
            fulfilled: false,
            expirationTimestamp: uint48(block.timestamp).add(core.invitationExpirationPeriod())
        });

        emit InvitationSubmitted(invitationId, msg.sender, _locality, _isLabTech);
    }

    /// @notice Registers an invited provider
    /// @param _invitationId Invitation ID
    /// @param _providerAddress Provider address
    function registerAsInvitedProvider(bytes32 _invitationId, address _providerAddress)
        external onlyRole(core.ADMIN_ROLE()) nonReentrant whenNotPaused
    {
        Invitation storage invitation = invitations[_invitationId];
        if (invitation.patient == address(0)) revert InvalidIndex();
        if (invitation.fulfilled) revert InvalidStatus();
        if (block.timestamp > invitation.expirationTimestamp) revert InvitationExpired();
        if (_providerAddress == address(0)) revert InvalidAddress();

        try invitation.isLabTech ?
            services.registerLabTech(_providerAddress) :
            services.registerPharmacy(_providerAddress)
        {
            invitation.fulfilled = true;
            emit InvitationFulfilled(_invitationId, _providerAddress);
        } catch {
            revert ExternalCallFailed();
        }
    }

    // Payment Queue Functions

    /// @notice Processes pending payments in batch
    /// @param _paymentIds Array of payment IDs to process
    function processPendingPayments(uint256[] calldata _paymentIds) external onlyRole(core.ADMIN_ROLE()) nonReentrant whenNotPaused {
        for (uint256 i = 0; i < _paymentIds.length; i++) {
            PendingPayment storage payment = pendingPayments[_paymentIds[i]];
            if (payment.processed || payment.recipient == address(0)) continue;
            payment.processed = true;
            try payments.queuePayment(payment.recipient, payment.amount, payment.paymentType) {
                emit PaymentReleasedFromQueue(_paymentIds[i], payment.recipient, payment.amount);
            } catch {
                payment.processed = false; // Revert processing status on failure
            }
        }
    }

    // Internal Functions

    /// @notice Adds a pending appointment for a doctor
    /// @param _doctor Doctor address
    /// @param _appointmentId Appointment ID
    function _addPendingAppointment(address _doctor, uint256 _appointmentId) internal {
        PendingAppointments storage pending = doctorPendingAppointments[_doctor];
        if (pending.ids.length >= maxPendingAppointments) revert InvalidPageSize();
        pending.indices[_appointmentId] = pending.ids.length;
        pending.ids.push(_appointmentId);
    }

    /// @notice Removes a pending appointment for a doctor
    /// @param _doctor Doctor address
    /// @param _appointmentId Appointment ID
    function _removePendingAppointment(address _doctor, uint256 _appointmentId) internal {
        PendingAppointments storage pending = doctorPendingAppointments[_doctor];
        uint256 index = pending.indices[_appointmentId];
        if (index >= pending.ids.length) revert InvalidIndex();

        if (index != pending.ids.length - 1) {
            uint256 lastId = pending.ids[pending.ids.length - 1];
            pending.ids[index] = lastId;
            pending.indices[lastId] = index;
        }
        pending.ids.pop();
        delete pending.indices[_appointmentId];
    }

    /// @notice Checks for pending priority appointments
    /// @param _doctor Doctor address
    /// @return True if priority appointments exist
    function _hasPendingPriorityAppointments(address _doctor) internal view returns (bool) {
        PendingAppointments storage pending = doctorPendingAppointments[_doctor];
        for (uint256 i = 0; i < pending.ids.length; i++) {
            if (appointments[pending.ids[i]].isPriority) return true;
        }
        return false;
    }

    /// @notice Selects the best lab technician based on rating, price, and capacity
    /// @param _testTypeIpfsHash IPFS hash of the test type
    /// @param _locality Locality for selection
    /// @return Selected lab technician address
    function selectBestLabTech(string memory _testTypeIpfsHash, string memory _locality) internal view returns (address) {
        (address[] memory labTechs, ) = services.getLabTechs(0, core.maxBatchSize());
        if (labTechs.length == 0) return address(0);

        address bestLabTech = address(0);
        uint256 highestScore = 0;
        address fallbackTech = address(0);

        uint256 maxIterations = labTechs.length > core.maxBatchSize() ? core.maxBatchSize() : labTechs.length;
        for (uint256 i = 0; i < maxIterations; i++) {
            if (!services.isLabTechRegistered(labTechs[i])) continue;
            (uint256 price, bool isValid) = services.getLabTechPrice(labTechs[i], _testTypeIpfsHash);
            if (!isValid || price == 0) continue;

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

    /// @notice Safely transfers ETH with gas limit
    /// @param _to Recipient address
    /// @param _amount Amount to transfer
    function _safeTransferETH(address _to, uint256 _amount) internal {
        (bool success, ) = _to.call{value: _amount, gas: 30000}("");
        if (!success) revert PaymentFailed();
    }

    /// @notice Releases a payment or queues it if funds are insufficient
    /// @param _to Recipient address
    /// @param _amount Amount to transfer
    /// @param _paymentType Payment type
    function _releasePayment(address _to, uint256 _amount, ITelemedicinePayments.PaymentType _paymentType) internal {
        if (!_hasSufficientFunds(_amount, _paymentType)) {
            pendingPaymentCounter = pendingPaymentCounter.add(1);
            pendingPayments[pendingPaymentCounter] = PendingPayment(_to, _amount, _paymentType, false);
            emit PaymentQueued(pendingPaymentCounter, _to, _amount, _paymentType);
            return;
        }

        try payments.queuePayment(_to, _amount, _paymentType) {
            // Success, validation handled by TelemedicinePayments
        } catch {
            // Queue payment on failure
            pendingPaymentCounter = pendingPaymentCounter.add(1);
            pendingPayments[pendingPaymentCounter] = PendingPayment(_to, _amount, _paymentType, false);
            emit PaymentQueued(pendingPaymentCounter, _to, _amount, _paymentType);
        }
    }

    /// @notice Checks if sufficient funds are available
    /// @param _amount Amount to check
    /// @param _paymentType Payment type
    /// @return True if funds are sufficient
    function _hasSufficientFunds(uint256 _amount, ITelemedicinePayments.PaymentType _paymentType) internal view returns (bool) {
        if (_paymentType == ITelemedicinePayments.PaymentType.ETH) {
            return address(this).balance >= _amount;
        } else if (_paymentType == ITelemedicinePayments.PaymentType.USDC) {
            return payments.usdcToken().balanceOf(address(this)) >= _amount;
        } else if (_paymentType == ITelemedicinePayments.PaymentType.SONIC) {
            return payments.sonicNativeToken().balanceOf(address(this)) >= _amount;
        }
        return false;
    }

    /// @notice Converts address to string for Chainlink requests
    /// @param _addr Address to convert
    /// @return String representation
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

    /// @notice Converts uint256 to string for Chainlink requests
    /// @param _value Value to convert
    /// @return String representation
    function toString(uint256 _value) internal pure returns (string memory) {
        if (_value == 0) return "0";
        uint256 temp = _value;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        bytes memory buffer = new bytes(digits);
        while (_value != 0) {
            digits--;
            buffer[digits] = bytes1(uint8(48 + (_value % 10)));
            _value /= 10;
        }
        return string(buffer);
    }

    // Modifiers

    /// @notice Restricts access to a specific role
    /// @param role The role required
    modifier onlyRole(bytes32 role) {
        if (!core.hasRole(role, msg.sender)) revert NotAuthorized();
        _;
    }

    /// @notice Ensures the contract is not paused
    modifier whenNotPaused() {
        if (core.paused()) revert ContractPaused();
        _;
    }

    /// @notice Requires multi-sig approval
    /// @param _operationHash Operation hash
    modifier onlyMultiSig(bytes32 _operationHash) {
        if (!services.checkMultiSigApproval(_operationHash)) revert MultiSigNotApproved();
        _;
    }

    // Fallback
    receive() external payable {}

    // Storage gap for future upgrades
    uint256[50] private __gap;
}
