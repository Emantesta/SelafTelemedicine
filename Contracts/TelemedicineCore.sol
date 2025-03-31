// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import {SafeMathUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";
import {AddressUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/AddressUpgradeable.sol";
import {IERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import {SafeERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import {ChainlinkClient, Chainlink} from "@chainlink/contracts/src/v0.8/ChainlinkClient.sol";
import {LinkTokenInterface} from "@chainlink/contracts/src/v0.8/interfaces/LinkTokenInterface.sol";

// External contract interfaces (assumed based on TelemedicineMedicalCore.sol)
interface TelemedicinePayments {
    enum PaymentType { ETH, USDC, SONIC }
    function _processPayment(PaymentType paymentType, uint256 amount) external;
    function _refundPatient(address patient, uint256 amount, PaymentType paymentType) external;
    function usdcToken() external view returns (IERC20Upgradeable);
    function sonicToken() external view returns (IERC20Upgradeable);
}

interface TelemedicineDisputeResolution {
    function isDisputed(uint256 id) external view returns (bool);
    function getDisputeOutcome(uint256 id) external view returns (DisputeOutcome);
}

interface TelemedicineMedicalServices {
    function hasLabTechInLocality(string calldata locality) external view returns (bool);
    function hasPharmacyInLocality(string calldata locality) external view returns (bool);
    function registerLabTech(address labTech, string calldata locality) external;
    function registerPharmacy(address pharmacy, string calldata locality) external;
    function isLabTechRegistered(address labTech) external view returns (bool);
    function isPharmacyRegistered(address pharmacy) external view returns (bool);
    function getLabTechsInLocality(string calldata locality, uint256 page, uint256 pageSize) external view returns (address[] memory, uint256);
    function getLabTechCapacity(address labTech) external view returns (uint256);
    function getLabTechRating(address labTech) external view returns (uint256, uint256);
    function getLabTestDetails(address labTech, string calldata testTypeIpfsHash) external view returns (uint256, bool, uint48, uint48);
    function getPharmacyPrice(address pharmacy, string calldata medicationIpfsHash) external view returns (uint256, bool);
    function getLabTechLocality(address labTech) external view returns (string memory);
    function monetizeData(address patient) external;
    function notifyDisputeResolved(uint256 id, string calldata serviceType, DisputeOutcome outcome) external;
    function notifyDataRewardClaimed(address patient, uint256 reward) external;
    function checkMultiSigApproval(bytes32 operationHash) external view returns (bool);
}

contract TelemedicineCore is Initializable, UUPSUpgradeable, AccessControlUpgradeable, ReentrancyGuardUpgradeable, PausableUpgradeable, ChainlinkClient {
    using SafeMathUpgradeable for uint256;
    using AddressUpgradeable for address payable;
    using Chainlink for Chainlink.Request;
    using SafeERC20Upgradeable for IERC20Upgradeable;

    // Roles
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant DOCTOR_ROLE = keccak256("DOCTOR_ROLE");
    bytes32 public constant PATIENT_ROLE = keccak256("PATIENT_ROLE");
    bytes32 public constant LAB_TECH_ROLE = keccak256("LAB_TECH_ROLE");
    bytes32 public constant PHARMACY_ROLE = keccak256("PHARMACY_ROLE");

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

    // Configuration Variables
    uint256 public minBookingBuffer;
    uint256 public minCancellationBuffer;
    uint256 public verificationTimeout;
    uint256 public dataMonetizationReward;
    uint256 public aiAnalysisCost;
    uint256 public pointsPerLevel;
    uint8 public maxLevel;
    uint256 public decayRate;
    uint256 public decayPeriod;
    uint256 public freeAnalysisPeriod;
    uint256 public minReserveBalance;
    uint256 public versionNumber;
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

    // Chainlink Configuration
    address public chainlinkOracle;
    bytes32 public priceListJobId;
    uint256 public chainlinkFee;
    LinkTokenInterface public linkToken;
    uint48 public chainlinkRequestTimeout;
    bool public manualPriceOverride;
    mapping(bytes32 => uint256) public requestToLabTestId;
    mapping(bytes32 => uint256) public requestToPrescriptionId;
    mapping(bytes32 => uint48) public requestTimestamps;

    // Constants
    uint256 public constant MAX_ADMINS = 10;
    uint256 public constant MAX_PENDING_APPOINTMENTS = 100;
    uint256 public constant MAX_BATCH_SIZE = 50;
    uint256 public constant RESERVE_FUND_THRESHOLD = 1 ether;

    // State Variables
    mapping(address => Patient) public patients;
    mapping(address => Doctor) public doctors;
    mapping(address => LabTechnician) public labTechnicians;
    mapping(address => Pharmacy) public pharmacies;
    mapping(uint8 => uint256) public discountLevels;
    mapping(string => uint256) public pointsForActions;
    address[] public admins;
    uint256 public aiAnalysisFund;
    uint256 public reserveFund;
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
    uint256 public appointmentCounter;
    uint256 public labTestCounter;
    uint256 public prescriptionCounter;
    uint256 public aiAnalysisCounter;
    address[] public multiSigSigners;
    uint256 public requiredSignatures;

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
        string inviteeContact;
        bool isLabTech;
        bool fulfilled;
        uint48 expirationTimestamp;
    }
    mapping(bytes32 => Invitation) public invitations;
    uint256 public invitationCounter;

    // Structs
    struct Patient {
        bool isRegistered;
        bytes32 medicalHistoryHash;
        GamificationData gamification;
        DataSharingStatus dataSharing;
        uint48 registrationTimestamp;
        uint48 lastActivityTimestamp;
        uint48 lastFreeAnalysisTimestamp;
        string encryptedSymmetricKey;
    }

    struct GamificationData {
        uint96 mediPoints;
        uint8 currentLevel;
    }

    struct Doctor {
        bool isVerified;
        uint96 consultationFee;
        string licenseNumber;
    }

    struct LabTechnician {
        bool isVerified;
        string licenseNumber;
    }

    struct Pharmacy {
        bool isRegistered;
        string licenseNumber;
    }

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

    // Enums
    enum DataSharingStatus { Disabled, Enabled }
    enum AppointmentStatus { Pending, Confirmed, Completed, Cancelled, Rescheduled, Emergency, Disputed }
    enum LabTestStatus { Requested, PaymentPending, Collected, ResultsUploaded, Reviewed, Disputed, Expired }
    enum PrescriptionStatus { Generated, PaymentPending, Verified, Fulfilled, Revoked, Expired, Disputed }
    enum DisputeOutcome { Unresolved, PatientFavored, ProviderFavored, MutualAgreement }

    // External Contracts
    TelemedicinePayments public payments;
    TelemedicineDisputeResolution public disputeResolution;
    TelemedicineMedicalServices public services;

    // Events
    event PatientRegistered(address indexed patient);
    event DoctorVerified(address indexed doctor);
    event LabTechnicianVerified(address indexed labTech);
    event PharmacyRegistered(address indexed pharmacy);
    event DataMonetizationOptIn(address indexed patient, bool enabled);
    event LevelUp(address indexed patient, uint8 newLevel);
    event PointsDecayed(address indexed patient, uint256 decayedPoints);
    event FreeAnalysisClaimed(address indexed patient);
    event AIFundDeposited(address indexed sender, uint256 amount);
    event ReserveFundDeposited(address indexed sender, uint256 amount);
    event MinBalanceAlert(address indexed contractAddress, uint256 balance);
    event AuditLog(uint256 indexed timestamp, address indexed actor, string action);
    event DisputeResolutionUpdated(address indexed oldAddress, address indexed newAddress);
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
    event DoctorPaid(uint256 indexed appointmentId, address indexed doctor, uint256 amount, TelemedicinePayments.PaymentType paymentType);
    event ReserveFundAllocated(uint256 indexed appointmentId, uint256 amount, TelemedicinePayments.PaymentType paymentType);
    event PlatformFeeAllocated(uint256 indexed appointmentId, uint256 amount, TelemedicinePayments.PaymentType paymentType);
    event InvitationSubmitted(bytes32 indexed invitationId, address patient, string locality, string inviteeContact, bool isLabTech);
    event InvitationFulfilled(bytes32 indexed invitationId, address invitee);
    event InvitationExpired(bytes32 indexed invitationId);
    event LabTestPaymentConfirmed(uint256 indexed testId, uint256 amount);
    event PrescriptionPaymentConfirmed(uint256 indexed prescriptionId, uint256 amount);
    event PaymentQueued(uint256 indexed paymentId, address recipient, uint256 amount, TelemedicinePayments.PaymentType paymentType);
    event PaymentReleasedFromQueue(uint256 indexed paymentId, address recipient, uint256 amount);
    event ConfigurationUpdated(string parameter, uint256 value);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address[] memory _initialAdmins,
        address _payments,
        address _disputeResolution,
        address _services,
        address _chainlinkOracle,
        bytes32 _priceListJobId,
        address _linkToken,
        address[] memory _multiSigSigners,
        uint256 _requiredSignatures
    ) external initializer {
        require(_initialAdmins.length >= 2 && _initialAdmins.length <= MAX_ADMINS, "Invalid initial admin count");
        if (_payments == address(0) || _disputeResolution == address(0) || _services == address(0) ||
            _chainlinkOracle == address(0) || _linkToken == address(0)) revert InvalidAddress();
        if (_multiSigSigners.length < _requiredSignatures || _requiredSignatures == 0) revert InvalidAddress();

        __UUPSUpgradeable_init();
        __AccessControl_init();
        __ReentrancyGuard_init();
        __Pausable_init();
        setChainlinkToken(_linkToken);

        _setRoleAdmin(ADMIN_ROLE, ADMIN_ROLE);
        _setRoleAdmin(DOCTOR_ROLE, ADMIN_ROLE);
        _setRoleAdmin(PATIENT_ROLE, ADMIN_ROLE);
        _setRoleAdmin(LAB_TECH_ROLE, ADMIN_ROLE);
        _setRoleAdmin(PHARMACY_ROLE, ADMIN_ROLE);

        for (uint256 i = 0; i < _initialAdmins.length; i++) {
            require(_initialAdmins[i] != address(0), "Admin address cannot be zero");
            _grantRole(ADMIN_ROLE, _initialAdmins[i]);
            admins.push(_initialAdmins[i]);
        }

        minBookingBuffer = 15 minutes;
        minCancellationBuffer = 1 hours;
        verificationTimeout = 7 days;
        dataMonetizationReward = 10 * 10**18;
        aiAnalysisCost = 0.01 ether;
        pointsPerLevel = 100;
        maxLevel = 10;
        decayRate = 10;
        decayPeriod = 30 days;
        freeAnalysisPeriod = 30 days;
        minReserveBalance = RESERVE_FUND_THRESHOLD;
        versionNumber = 1;
        doctorFeePercentage = 70;
        reserveFundPercentage = 20;
        platformFeePercentage = 10;
        disputeWindow = 7 days;
        maxBatchSize = 50;
        cancellationFeePercentage = 25;
        reminderInterval = 24 hours;
        paymentConfirmationDeadline = 3 days;
        invitationExpirationPeriod = 30 days;
        maxDoctorsPerAppointment = 3;

        discountLevels[3] = 5;
        discountLevels[5] = 10;
        pointsForActions["appointment"] = 20;
        pointsForActions["aiAnalysis"] = 10;

        payments = TelemedicinePayments(_payments);
        disputeResolution = TelemedicineDisputeResolution(_disputeResolution);
        services = TelemedicineMedicalServices(_services);
        chainlinkOracle = _chainlinkOracle;
        priceListJobId = _priceListJobId;
        linkToken = LinkTokenInterface(_linkToken);
        chainlinkFee = 0.1 ether;
        chainlinkRequestTimeout = 30 minutes;
        manualPriceOverride = false;
        multiSigSigners = _multiSigSigners;
        requiredSignatures = _requiredSignatures;

        appointmentCounter = 0;
        labTestCounter = 0;
        prescriptionCounter = 0;
        aiAnalysisCounter = 0;
        invitationCounter = 0;
        pendingPaymentCounter = 0;

        emit AuditLog(block.timestamp, msg.sender, "Contract Initialized");
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyRole(ADMIN_ROLE) {
        versionNumber = versionNumber.add(1);
        emit AuditLog(block.timestamp, msg.sender, "Contract Upgraded");
    }

    // Configuration Functions
    function updateConfiguration(string calldata _parameter, uint256 _value) external onlyRole(ADMIN_ROLE) {
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
        if (paramHash == keccak256("doctorFeePercentage") || paramHash == keccak256("reserveFundPercentage") || paramHash == keccak256("platformFeePercentage")) {
            if (doctorFeePercentage + reserveFundPercentage + platformFeePercentage != 100) revert InvalidPercentage();
        }
        emit ConfigurationUpdated(_parameter, _value);
    }

    // Patient Functions
    function registerPatient(string calldata _encryptedSymmetricKey) external whenNotPaused {
        if (patients[msg.sender].isRegistered) revert InvalidStatus();
        patients[msg.sender] = Patient(
            true,
            bytes32(0),
            GamificationData(0, 1),
            DataSharingStatus.Disabled,
            uint48(block.timestamp),
            uint48(block.timestamp),
            0,
            _encryptedSymmetricKey
        );
        _grantRole(PATIENT_ROLE, msg.sender);
        emit PatientRegistered(msg.sender);
    }

    function toggleDataMonetization(bool _enable) external onlyRole(PATIENT_ROLE) nonReentrant whenNotPaused {
        Patient storage patient = patients[msg.sender];
        if (!patient.isRegistered) revert InvalidStatus();
        if (_enable && patient.dataSharing == DataSharingStatus.Disabled) {
            patient.dataSharing = DataSharingStatus.Enabled;
            patient.lastActivityTimestamp = uint48(block.timestamp);
        } else if (!_enable && patient.dataSharing == DataSharingStatus.Enabled) {
            _claimDataReward(msg.sender);
            patient.dataSharing = DataSharingStatus.Disabled;
        }
        emit DataMonetizationOptIn(msg.sender, _enable);
    }

    function claimDataReward() external onlyRole(PATIENT_ROLE) nonReentrant whenNotPaused {
        _claimDataReward(msg.sender);
    }

    function decayPoints(address _patient) external nonReentrant whenNotPaused {
        if (!hasRole(PATIENT_ROLE, _patient)) revert NotAuthorized();
        _decayPoints(_patient);
    }

    function claimFreeAnalysis() external onlyRole(PATIENT_ROLE) nonReentrant whenNotPaused {
        Patient storage patient = patients[msg.sender];
        if (!patient.isRegistered) revert InvalidStatus();
        if (block.timestamp < patient.lastFreeAnalysisTimestamp.add(freeAnalysisPeriod)) revert InvalidTimestamp();
        if (aiAnalysisFund < aiAnalysisCost) revert InsufficientFunds();

        patient.lastFreeAnalysisTimestamp = uint48(block.timestamp);
        aiAnalysisFund = aiAnalysisFund.sub(aiAnalysisCost);
        emit FreeAnalysisClaimed(msg.sender);
    }

    // Admin Functions
    function verifyDoctor(address _doctor, string calldata _licenseNumber, uint256 _fee) external onlyRole(ADMIN_ROLE) {
        if (_doctor == address(0)) revert InvalidAddress();
        if (_fee > type(uint96).max) revert InsufficientFunds();
        doctors[_doctor] = Doctor(true, uint96(_fee), _licenseNumber);
        _grantRole(DOCTOR_ROLE, _doctor);
        emit DoctorVerified(_doctor);
    }

    function verifyLabTechnician(address _labTech, string calldata _licenseNumber) external onlyRole(ADMIN_ROLE) {
        if (_labTech == address(0)) revert InvalidAddress();
        labTechnicians[_labTech] = LabTechnician(true, _licenseNumber);
        _grantRole(LAB_TECH_ROLE, _labTech);
        emit LabTechnicianVerified(_labTech);
    }

    function registerPharmacy(address _pharmacy, string calldata _licenseNumber) external onlyRole(ADMIN_ROLE) {
        if (_pharmacy == address(0)) revert InvalidAddress();
        pharmacies[_pharmacy] = Pharmacy(true, _licenseNumber);
        _grantRole(PHARMACY_ROLE, _pharmacy);
        emit PharmacyRegistered(_pharmacy);
    }

    function depositAIFund() external payable onlyRole(ADMIN_ROLE) {
        if (msg.value == 0) revert InsufficientFunds();
        aiAnalysisFund = aiAnalysisFund.add(msg.value);
        emit AIFundDeposited(msg.sender, msg.value);
    }

    function depositReserveFund() external payable onlyRole(ADMIN_ROLE) {
        if (msg.value == 0) revert InsufficientFunds();
        reserveFund = reserveFund.add(msg.value);
        emit ReserveFundDeposited(msg.sender, msg.value);
        _checkMinBalance();
    }

    function setDisputeResolution(address _disputeResolution) external onlyRole(ADMIN_ROLE) {
        if (_disputeResolution == address(0)) revert InvalidAddress();
        address oldAddress = address(disputeResolution);
        disputeResolution = TelemedicineDisputeResolution(_disputeResolution);
        emit DisputeResolutionUpdated(oldAddress, _disputeResolution);
    }

    function pause() external onlyRole(ADMIN_ROLE) {
        _pause();
        emit AuditLog(block.timestamp, msg.sender, "Contract Paused");
    }

    function unpause() external onlyRole(ADMIN_ROLE) {
        _unpause();
        emit AuditLog(block.timestamp, msg.sender, "Contract Unpaused");
    }

    // Appointment Functions
    function bookAppointment(
        address[] calldata _doctors,
        uint48 _timestamp,
        TelemedicinePayments.PaymentType _paymentType,
        bool _isVideoCall,
        string calldata _videoCallLink
    ) external payable onlyRole(PATIENT_ROLE) nonReentrant whenNotPaused {
        if (_doctors.length == 0 || _doctors.length > maxDoctorsPerAppointment) revert InvalidAddress();
        for (uint256 i = 0; i < _doctors.length; i++) {
            if (_doctors[i] == address(0) || !doctors[_doctors[i]].isVerified) revert NotAuthorized();
        }
        if (_timestamp <= block.timestamp + minBookingBuffer) revert InvalidTimestamp();

        _decayPoints(msg.sender);
        uint256 baseFee = 0;
        for (uint256 i = 0; i < _doctors.length; i++) {
            baseFee = baseFee.add(doctors[_doctors[i]].consultationFee);
        }
        uint256 discountedFee = _applyFeeDiscount(msg.sender, baseFee);
        if (discountedFee > type(uint96).max) revert InsufficientFunds();
        bool isPriority = _isPriorityBooking(msg.sender);

        uint256 reserveAmount = discountedFee.mul(reserveFundPercentage).div(PERCENTAGE_DENOMINATOR);
        uint256 platformAmount = discountedFee.mul(platformFeePercentage).div(PERCENTAGE_DENOMINATOR);

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
            videoCallLink: _isVideoCall ? _videoCallLink : "",
            disputeWindowEnd: 0,
            disputeOutcome: DisputeOutcome.Unresolved
        });

        for (uint256 i = 0; i < _doctors.length; i++) {
            _addPendingAppointment(_doctors[i], newAppointmentId);
        }
        appointmentReminders[newAppointmentId] = Reminder(true, 0, 0);
        Patient storage patient = patients[msg.sender];
        patient.gamification.mediPoints = uint96(patient.gamification.mediPoints.add(pointsForActions["appointment"]));
        patient.lastActivityTimestamp = uint48(block.timestamp);

        if (_paymentType == TelemedicinePayments.PaymentType.ETH) {
            if (msg.value < discountedFee) revert InsufficientFunds();
            reserveFund = reserveFund.add(reserveAmount);
            emit ReserveFundAllocated(newAppointmentId, reserveAmount, _paymentType);
            emit PlatformFeeAllocated(newAppointmentId, platformAmount, _paymentType);
            if (msg.value > discountedFee) {
                _safeTransferETH(msg.sender, msg.value.sub(discountedFee));
            }
        } else {
            payments._processPayment(_paymentType, discountedFee);
            if (_paymentType == TelemedicinePayments.PaymentType.USDC) {
                if (!payments.usdcToken().transfer(address(this), reserveAmount)) revert PaymentFailed();
                reserveFund = reserveFund.add(reserveAmount);
            } else if (_paymentType == TelemedicinePayments.PaymentType.SONIC) {
                if (!payments.sonicToken().transfer(address(this), reserveAmount)) revert PaymentFailed();
                reserveFund = reserveFund.add(reserveAmount);
            }
            emit ReserveFundAllocated(newAppointmentId, reserveAmount, _paymentType);
            emit PlatformFeeAllocated(newAppointmentId, platformAmount, _paymentType);
        }

        _levelUp(msg.sender);
        emit AppointmentBooked(newAppointmentId, msg.sender, _doctors, _timestamp, _videoCallLink);
    }

    function confirmAppointment(uint256 _appointmentId, bool _overridePriority) public onlyRole(DOCTOR_ROLE) whenNotPaused {
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
            if (!hasRole(ADMIN_ROLE, msg.sender)) revert NotAuthorized();
        } else if (!apt.isPriority && _hasPendingPriorityAppointments(msg.sender)) {
            revert InvalidStatus();
        }

        apt.status = AppointmentStatus.Confirmed;
        _removePendingAppointment(msg.sender, _appointmentId);
        emit AppointmentStatusUpdated(_appointmentId, "Confirmed");
    }

    function completeAppointment(uint256 _appointmentId, string calldata _ipfsSummary, bytes32 _operationHash)
        external onlyRole(DOCTOR_ROLE) nonReentrant whenNotPaused onlyMultiSig(_operationHash) {
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
        if (_appointmentId == 0 || _appointmentId > appointmentCounter) revert InvalidIndex();

        if (disputeResolution.isDisputed(_appointmentId)) {
            DisputeOutcome outcome = disputeResolution.getDisputeOutcome(_appointmentId);
            if (outcome == DisputeOutcome.Unresolved) revert InvalidStatus();
            apt.disputeOutcome = outcome;
        }

        apt.status = AppointmentStatus.Completed;
        apt.disputeWindowEnd = uint48(block.timestamp).add(disputeWindow);
        appointmentReminders[_appointmentId].active = false;

        uint256 doctorPayment = uint256(apt.fee).mul(doctorFeePercentage).div(PERCENTAGE_DENOMINATOR).div(apt.doctors.length);
        for (uint256 i = 0; i < apt.doctors.length; i++) {
            _releasePayment(apt.doctors[i], doctorPayment, apt.paymentType);
            emit DoctorPaid(_appointmentId, apt.doctors[i], doctorPayment, apt.paymentType);
        }

        if (apt.disputeOutcome != DisputeOutcome.Unresolved) {
            services.notifyDisputeResolved(_appointmentId, "Appointment", apt.disputeOutcome);
        }
        emit AppointmentStatusUpdated(_appointmentId, "Completed");
        emit AppointmentCompleted(_appointmentId, _ipfsSummary);
    }

    // Lab Test Functions
    function orderLabTest(address _patient, string calldata _testTypeIpfsHash, string calldata _locality) external payable onlyRole(DOCTOR_ROLE) nonReentrant whenNotPaused {
        if (_patient == address(0) || !patients[_patient].isRegistered) revert InvalidAddress();
        if (bytes(_testTypeIpfsHash).length == 0 || bytes(_locality).length == 0) revert InvalidIpfsHash();

        address selectedLabTech = selectBestLabTech(_testTypeIpfsHash, _locality);
        if (selectedLabTech == address(0)) revert NoLabTechAvailable();

        (uint256 price, bool isValid, uint48 sampleDeadline, uint48 resultsDeadline) = services.getLabTestDetails(selectedLabTech, _testTypeIpfsHash);
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
            disputeWindowEnd: 0,
            disputeOutcome: DisputeOutcome.Unresolved,
            sampleCollectionDeadline: sampleDeadline,
            resultsUploadDeadline: resultsDeadline,
            paymentType: TelemedicinePayments.PaymentType.ETH
        });

        if (!isValid || price == 0) {
            requestLabTestPrice(selectedLabTech, _testTypeIpfsHash, newTestId);
        } else {
            labTestOrders[newTestId].patientCost = price.mul(120).div(PERCENTAGE_DENOMINATOR);
            if (msg.value < labTestOrders[newTestId].patientCost) revert InsufficientFunds();
            labTestPayments[newTestId] = true;
            emit LabTestPaymentConfirmed(newTestId, labTestOrders[newTestId].patientCost);
            if (msg.value > labTestOrders[newTestId].patientCost) {
                _safeTransferETH(msg.sender, msg.value.sub(labTestOrders[newTestId].patientCost));
            }
        }

        emit LabTestOrdered(newTestId, _patient, msg.sender, _testTypeIpfsHash, uint48(block.timestamp));
        services.monetizeData(_patient);
    }

    function requestLabTestPrice(address _labTech, string calldata _testTypeIpfsHash, uint256 _labTestId) internal returns (bytes32) {
        if (manualPriceOverride) return bytes32(0);
        Chainlink.Request memory req = buildChainlinkRequest(priceListJobId, address(this), this.fulfillLabTestPrice.selector);
        req.add("testType", _testTypeIpfsHash);
        req.add("labTech", toString(_labTech));
        bytes32 requestId = sendChainlinkRequestTo(chainlinkOracle, req, chainlinkFee);
        requestToLabTestId[requestId] = _labTestId;
        requestTimestamps[requestId] = uint48(block.timestamp);
        return requestId;
    }

    function fulfillLabTestPrice(bytes32 _requestId, uint256 _price) public recordChainlinkFulfillment(_requestId) {
        uint256 labTestId = requestToLabTestId[_requestId];
        if (labTestId == 0 || labTestId > labTestCounter) revert InvalidIndex();
        LabTestOrder storage order = labTestOrders[labTestId];
        if (order.status != LabTestStatus.Requested) revert InvalidStatus();
        if (_price == 0) revert OracleResponseInvalid();

        order.patientCost = _price.mul(120).div(PERCENTAGE_DENOMINATOR);
        order.status = LabTestStatus.PaymentPending;
        labTestPaymentDeadlines[labTestId] = uint48(block.timestamp).add(paymentConfirmationDeadline);
        delete requestToLabTestId[_requestId];
        delete requestTimestamps[_requestId];
        emit LabTestPaymentConfirmed(labTestId, order.patientCost);
    }

    // Prescription Functions
    function issuePrescription(address _patient, string calldata _medicationIpfsHash, address _pharmacy, string calldata _locality) external payable onlyRole(DOCTOR_ROLE) nonReentrant whenNotPaused {
        if (_patient == address(0) || !patients[_patient].isRegistered || _pharmacy == address(0)) revert InvalidAddress();
        if (!services.isPharmacyRegistered(_pharmacy) && !services.hasPharmacyInLocality(_locality)) revert NotAuthorized();
        if (bytes(_medicationIpfsHash).length == 0 || bytes(_locality).length == 0) revert InvalidIpfsHash();

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
            disputeWindowEnd: 0,
            disputeOutcome: DisputeOutcome.Unresolved
        });

        if (!isValid || price == 0) {
            requestPrescriptionPrice(_pharmacy, _medicationIpfsHash, newPrescriptionId);
        } else {
            prescriptions[newPrescriptionId].patientCost = price.mul(120).div(PERCENTAGE_DENOMINATOR);
            if (msg.value < prescriptions[newPrescriptionId].patientCost) revert InsufficientFunds();
            prescriptionPayments[newPrescriptionId] = true;
            emit PrescriptionPaymentConfirmed(newPrescriptionId, prescriptions[newPrescriptionId].patientCost);
            if (msg.value > prescriptions[newPrescriptionId].patientCost) {
                _safeTransferETH(msg.sender, msg.value.sub(prescriptions[newPrescriptionId].patientCost));
            }
        }

        emit PrescriptionIssued(newPrescriptionId, _patient, msg.sender, verificationCodeHash, uint48(block.timestamp));
        services.monetizeData(_patient);
    }

    function requestPrescriptionPrice(address _pharmacy, string calldata _medicationIpfsHash, uint256 _prescriptionId) internal returns (bytes32) {
        if (manualPriceOverride) return bytes32(0);
        Chainlink.Request memory req = buildChainlinkRequest(priceListJobId, address(this), this.fulfillPrescriptionPrice.selector);
        req.add("medication", _medicationIpfsHash);
        req.add("pharmacy", toString(_pharmacy));
        bytes32 requestId = sendChainlinkRequestTo(chainlinkOracle, req, chainlinkFee);
        requestToPrescriptionId[requestId] = _prescriptionId;
        requestTimestamps[requestId] = uint48(block.timestamp);
        return requestId;
    }

    function fulfillPrescriptionPrice(bytes32 _requestId, uint256 _price) public recordChainlinkFulfillment(_requestId) {
        uint256 prescriptionId = requestToPrescriptionId[_requestId];
        if (prescriptionId == 0 || prescriptionId > prescriptionCounter) revert InvalidIndex();
        Prescription storage prescription = prescriptions[prescriptionId];
        if (prescription.status != PrescriptionStatus.Generated) revert InvalidStatus();
        if (_price == 0) revert OracleResponseInvalid();

        prescription.patientCost = _price.mul(120).div(PERCENTAGE_DENOMINATOR);
        prescription.status = PrescriptionStatus.PaymentPending;
        prescriptionPaymentDeadlines[prescriptionId] = uint48(block.timestamp).add(paymentConfirmationDeadline);
        delete requestToPrescriptionId[_requestId];
        delete requestTimestamps[_requestId];
        emit PrescriptionPaymentConfirmed(prescriptionId, prescription.patientCost);
    }

    // Invitation Functions
    function inviteProvider(string calldata _locality, string calldata _inviteeContact, bool _isLabTech) external onlyRole(PATIENT_ROLE) nonReentrant whenNotPaused {
        if (bytes(_locality).length == 0 || bytes(_inviteeContact).length == 0) revert InvalidLocality();

        bool hasProvider = _isLabTech ? services.hasLabTechInLocality(_locality) : services.hasPharmacyInLocality(_locality);
        if (hasProvider) revert ProvidersAlreadyExist();

        bytes32 invitationId = keccak256(abi.encodePacked(msg.sender, _locality, _isLabTech, block.timestamp));
        if (invitations[invitationId].patient != address(0)) revert InvitationAlreadyExists();

        invitationCounter = invitationCounter.add(1);
        invitations[invitationId] = Invitation({
            patient: msg.sender,
            locality: _locality,
            inviteeContact: _inviteeContact,
            isLabTech: _isLabTech,
            fulfilled: false,
            expirationTimestamp: uint48(block.timestamp).add(invitationExpirationPeriod)
        });

        emit InvitationSubmitted(invitationId, msg.sender, _locality, _inviteeContact, _isLabTech);
    }

    function registerAsInvitedProvider(bytes32 _invitationId, address _providerAddress) external onlyRole(ADMIN_ROLE) nonReentrant whenNotPaused {
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

    // Internal Functions
    function _claimDataReward(address _patient) internal {
        Patient storage patient = patients[_patient];
        if (patient.dataSharing != DataSharingStatus.Enabled) revert InvalidStatus();
        if (block.timestamp <= patient.lastActivityTimestamp) revert InvalidTimestamp();

        uint256 timeElapsed = block.timestamp.sub(patient.lastActivityTimestamp);
        uint256 reward = timeElapsed.mul(dataMonetizationReward).div(1 days);
        patient.gamification.mediPoints = uint96(
            patient.gamification.mediPoints.add(reward) > type(uint96).max 
            ? type(uint96).max 
            : patient.gamification.mediPoints.add(reward)
        );
        patient.lastActivityTimestamp = uint48(block.timestamp);
        _levelUp(_patient);
    }

    function _decayPoints(address _patient) internal {
        Patient storage patient = patients[_patient];
        if (!patient.isRegistered) revert InvalidStatus();

        uint256 timeElapsed = block.timestamp.sub(patient.lastActivityTimestamp);
        if (timeElapsed >= decayPeriod && patient.gamification.mediPoints > 0) {
            uint256 periods = timeElapsed.div(decayPeriod);
            uint256 decayedPoints = patient.gamification.mediPoints.mul(decayRate).mul(periods).div(100);
            decayedPoints = decayedPoints > patient.gamification.mediPoints ? patient.gamification.mediPoints : decayedPoints;
            patient.gamification.mediPoints = uint96(patient.gamification.mediPoints.sub(decayedPoints));
            patient.lastActivityTimestamp = uint48(block.timestamp);
            emit PointsDecayed(_patient, decayedPoints);
        }
    }

    function _applyFeeDiscount(address _patient, uint256 _baseFee) internal view returns (uint256) {
        uint8 level = patients[_patient].gamification.currentLevel;
        uint256 discountPercentage = discountLevels[level];
        if (discountPercentage == 0) return _baseFee;
        uint256 discount = _baseFee.mul(discountPercentage).div(100);
        return _baseFee.sub(discount);
    }

    function _isPriorityBooking(address _patient) internal view returns (bool) {
        return patients[_patient].gamification.currentLevel >= 5;
    }

    function _levelUp(address _patient) internal {
        Patient storage patient = patients[_patient];
        GamificationData storage gamification = patient.gamification;
        uint256 pointsNeeded = uint256(gamification.currentLevel + 1).mul(pointsPerLevel);
        if (gamification.mediPoints >= pointsNeeded && gamification.currentLevel < maxLevel) {
            gamification.currentLevel = gamification.currentLevel + 1;
            emit LevelUp(_patient, gamification.currentLevel);
        }
    }

    function _checkMinBalance() internal {
        if (address(this).balance < minReserveBalance) {
            emit MinBalanceAlert(address(this), address(this).balance);
        }
    }

    function _addPendingAppointment(address _doctor, uint256 _appointmentId) internal {
        PendingAppointments storage pending = doctorPendingAppointments[_doctor];
        if (pending.count >= MAX_PENDING_APPOINTMENTS) revert InvalidPageSize();
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
        for (uint256 i = 0; i < pending.count; i++) {
            if (appointments[pending.ids[i]].isPriority) return true;
        }
        return false;
    }

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

    function _safeTransferETH(address _to, uint256 _amount) internal {
        (bool success, ) = _to.call{value: _amount}("");
        if (!success) revert PaymentFailed();
    }

    function _releasePayment(address _to, uint256 _amount, TelemedicinePayments.PaymentType _paymentType) internal {
        if (!_hasSufficientFunds(_amount, _paymentType)) {
            pendingPaymentCounter = pendingPaymentCounter.add(1);
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
        }
    }

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

    // Getters
    function getPatientLevel(address _patient) external view returns (uint8) {
        return patients[_patient].gamification.currentLevel;
    }

    function getPatientPoints(address _patient) external view returns (uint256) {
        return patients[_patient].gamification.mediPoints;
    }

    function getDoctorFee(address _doctor) external view returns (uint256) {
        return doctors[_doctor].consultationFee;
    }

    function getContractBalance() external view returns (uint256) {
        return address(this).balance;
    }

    function getAIFundBalance() external view returns (uint256) {
        return aiAnalysisFund;
    }

    function getReserveFundBalance() external view returns (uint256) {
        return reserveFund;
    }

    function paused() external view returns (bool) {
        return super.paused();
    }

    // Modifiers
    modifier onlyRole(bytes32 role) {
        if (!hasRole(role, msg.sender)) revert NotAuthorized();
        _;
    }

    modifier whenNotPaused() {
        if (super.paused()) revert ContractPaused();
        _;
    }

    modifier onlyMultiSig(bytes32 _operationHash) {
        if (!services.checkMultiSigApproval(_operationHash)) revert MultiSigNotApproved();
        _;
    }

    // Fallback
    receive() external payable {
        emit ReserveFundDeposited(msg.sender, msg.value);
        reserveFund = reserveFund.add(msg.value);
        _checkMinBalance();
    }
}
