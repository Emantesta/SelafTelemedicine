// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {SafeMathUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";
import {SafeERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import {TelemedicineCore} from "./TelemedicineCore.sol";
import {TelemedicinePayments} from "./TelemedicinePayments.sol";
import {TelemedicineDisputeResolution} from "./TelemedicineDisputeResolution.sol";
import {TelemedicineOperations} from "./TelemedicineOperations.sol";
import {ITelemedicinePayments} from "./Interfaces/ITelemedicinePayments.sol";

/// @title TelemedicineBase
/// @notice Manages appointments, reminders, and configurations
/// @dev UUPS upgradeable, integrates with core, payments, dispute, and operations
contract TelemedicineBase is Initializable, UUPSUpgradeable, ReentrancyGuardUpgradeable {
    using SafeMathUpgradeable for uint256;
    using SafeERC20Upgradeable for IERC20Upgradeable;

    // Immutable Dependencies
    TelemedicineCore public immutable core;
    TelemedicinePayments public immutable payments;
    TelemedicineDisputeResolution public immutable disputeResolution;
    TelemedicineOperations public immutable operations;

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
    uint256 public versionNumber; // New: Track version

    // State Variables
    mapping(uint256 => Appointment) private appointments; // Updated: Private
    mapping(address => PendingAppointments) private doctorPendingAppointments; // Updated: Private
    mapping(uint256 => Reminder) private appointmentReminders; // Updated: Private
    mapping(address => uint256) private nonces; // Updated: Private
    address[] public multiSigSigners;
    uint256 public appointmentCounter;
    uint256 public requiredSignatures;
    mapping(address => uint256) private doctorPriorityCounts; // New: Track priority appointments

    // Enums
    enum AppointmentStatus { Pending, Confirmed, Completed, Cancelled, Rescheduled, Emergency, Disputed }

    // Structs
    struct Appointment {
        uint256 id;
        address patient;
        address[] doctors;
        uint48 scheduledTimestamp;
        AppointmentStatus status;
        uint96 fee;
        ITelemedicinePayments.PaymentType paymentType; // Updated: Use interface
        bool isVideoCall;
        bool isPriority;
        bytes32 videoCallLinkHash; // Updated: Hashed link
        uint48 disputeWindowEnd;
        TelemedicineMedicalCore.DisputeOutcome disputeOutcome; // Updated: Standardize
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

    // Constants
    uint256 public constant MIN_CANCELLATION_FEE = 0.01 * 10**6; // New: 0.01 USDC (6 decimals)
    uint256 public constant MAX_COUNTER = 1_000_000; // New: Limit counter
    uint48 public constant MIN_DISPUTE_WINDOW = 1 hours; // New: Minimum dispute window
    uint48 public constant MIN_REMINDER_INTERVAL = 1 hours; // New: Minimum reminder interval
    uint48 public constant MIN_PAYMENT_DEADLINE = 1 days; // New: Minimum payment deadline
    uint48 public constant MIN_INVITATION_EXPIRATION = 7 days; // New: Minimum invitation expiration

    // Events
    event AppointmentBooked(uint256 indexed appointmentId, bytes32 patientHash, bytes32[] doctorHashes, uint256 timestamp);
    event AppointmentStatusUpdated(uint256 indexed appointmentId, string status);
    event AppointmentCompleted(uint256 indexed appointmentId, bytes32 ipfsSummaryHash);
    event VideoCallStarted(uint256 indexed appointmentId, bytes32 videoCallLinkHash);
    event BatchAppointmentsConfirmed(bytes32 indexed doctorHash, uint256[] appointmentIds);
    event DoctorPaid(uint256 indexed appointmentId, bytes32 indexed doctorHash, uint256 amount, ITelemedicinePayments.PaymentType paymentType);
    event ReserveFundAllocated(uint256 indexed appointmentId, uint256 amount, ITelemedicinePayments.PaymentType paymentType);
    event PlatformFeeAllocated(uint256 indexed appointmentId, uint256 amount, ITelemedicinePayments.PaymentType paymentType);
    event AppointmentReminderSent(uint256 indexed appointmentId, bytes32 patientHash, uint48 timestamp);
    event CancellationFeeCharged(uint256 indexed appointmentId, uint256 amount);
    event ConfigurationUpdated(string indexed parameter, uint256 value);
    event MultiSigConfigUpdated(address[] signers, uint256 requiredSignatures); // New: Multi-sig updates
    event MultiSigApproval(bytes32 indexed signerHash, bytes32 indexed operationHash); // New: Approval event

    // Errors
    error InvalidAddress();
    error InvalidAppointmentStatus();
    error NotAuthorized();
    error ContractPaused();
    error InsufficientFunds();
    error InvalidPageSize();
    error InvalidIndex();
    error InvalidVideoCallLink();
    error MultiSigNotApproved();
    error InvalidPercentage();
    error InvalidTimestamp();
    error CounterOverflow();
    error InvalidPaymentType();
    error ExternalCallFailed();
    error InvalidConfiguration();
    error DuplicateSigner();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the contract
    /// @param _core Core contract address
    /// @param _payments Payments contract address
    /// @param _disputeResolution Dispute resolution contract address
    /// @param _operations Operations contract address
    /// @param _multiSigSigners Multi-signature signers
    /// @param _requiredSignatures Required signatures
    /// @param _doctorFeePercentage Doctor fee percentage
    /// @param _reserveFundPercentage Reserve fund percentage
    /// @param _platformFeePercentage Platform fee percentage
    /// @param _disputeWindow Dispute window duration
    /// @param _maxBatchSize Maximum batch size
    /// @param _cancellationFeePercentage Cancellation fee percentage
    /// @param _reminderInterval Reminder interval
    /// @param _paymentConfirmationDeadline Payment confirmation deadline
    /// @param _invitationExpirationPeriod Invitation expiration period
    /// @param _maxDoctorsPerAppointment Maximum doctors per appointment
    function initialize(
        address _core,
        address _payments,
        address _disputeResolution,
        address _operations,
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
            _operations == address(0)) revert InvalidAddress();
        if (!_isContract(_core) || !_isContract(_payments) || !_isContract(_disputeResolution) ||
            !_isContract(_operations)) revert InvalidAddress();
        if (_multiSigSigners.length < _requiredSignatures || _requiredSignatures == 0) revert InvalidAddress();
        if (_doctorFeePercentage.add(_reserveFundPercentage).add(_platformFeePercentage) != 100) revert InvalidPercentage();
        if (_disputeWindow < MIN_DISPUTE_WINDOW) revert InvalidConfiguration();
        if (_reminderInterval < MIN_REMINDER_INTERVAL) revert InvalidConfiguration();
        if (_paymentConfirmationDeadline < MIN_PAYMENT_DEADLINE) revert InvalidConfiguration();
        if (_invitationExpirationPeriod < MIN_INVITATION_EXPIRATION) revert InvalidConfiguration();
        if (_maxBatchSize == 0 || _maxDoctorsPerAppointment == 0) revert InvalidConfiguration();

        for (uint256 i = 0; i < _multiSigSigners.length; i++) {
            if (_multiSigSigners[i] == address(0)) revert InvalidAddress();
            for (uint256 j = i + 1; j < _multiSigSigners.length; j++) {
                if (_multiSigSigners[i] == _multiSigSigners[j]) revert DuplicateSigner();
            }
        }

        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();

        core = TelemedicineCore(_core);
        payments = TelemedicinePayments(_payments);
        disputeResolution = TelemedicineDisputeResolution(_disputeResolution);
        operations = TelemedicineOperations(_operations);
        multiSigSigners = _multiSigSigners;
        requiredSignatures = _requiredSignatures;

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
        versionNumber = 1;

        appointmentCounter = 0;
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

    /// @notice Queues configuration update
    /// @param _parameter Parameter name
    /// @param _value Value
    function queueUpdateConfiguration(string calldata _parameter, uint256 _value) external onlyConfigAdmin {
        bytes memory data = abi.encodeWithSignature("executeUpdateConfiguration(string,uint256)", _parameter, _value);
        try core._queueTimeLock(
            TelemedicineCore.TimeLockAction.ConfigurationUpdate, // Assumes GovernanceManager enum
            address(this),
            0,
            data
        ) {} catch {
            revert ExternalCallFailed();
        }
    }

    /// @notice Executes configuration update
    /// @param _parameter Parameter name
    /// @param _value Value
    function executeUpdateConfiguration(string calldata _parameter, uint256 _value) external onlyConfigAdmin {
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
            if (_value < MIN_DISPUTE_WINDOW) revert InvalidConfiguration();
            disputeWindow = uint48(_value);
        } else if (paramHash == keccak256("maxBatchSize")) {
            if (_value == 0) revert InvalidConfiguration();
            maxBatchSize = _value;
        } else if (paramHash == keccak256("cancellationFeePercentage")) {
            if (_value > 100) revert InvalidPercentage();
            cancellationFeePercentage = _value;
        } else if (paramHash == keccak256("reminderInterval")) {
            if (_value < MIN_REMINDER_INTERVAL) revert InvalidConfiguration();
            reminderInterval = uint48(_value);
        } else if (paramHash == keccak256("paymentConfirmationDeadline")) {
            if (_value < MIN_PAYMENT_DEADLINE) revert InvalidConfiguration();
            paymentConfirmationDeadline = uint48(_value);
        } else if (paramHash == keccak256("invitationExpirationPeriod")) {
            if (_value < MIN_INVITATION_EXPIRATION) revert InvalidConfiguration();
            invitationExpirationPeriod = uint48(_value);
        } else if (paramHash == keccak256("maxDoctorsPerAppointment")) {
            if (_value == 0) revert InvalidConfiguration();
            maxDoctorsPerAppointment = _value;
        } else {
            revert InvalidConfiguration();
        }
        if (paramHash == keccak256("doctorFeePercentage") || paramHash == keccak256("reserveFundPercentage") || paramHash == keccak256("platformFeePercentage")) {
            if (doctorFeePercentage.add(reserveFundPercentage).add(platformFeePercentage) != 100) revert InvalidPercentage();
        }
        emit ConfigurationUpdated(_parameter, _value);
    }

    /// @notice Updates multi-signature configuration
    /// @param _newSigners New signers
    /// @param _newRequiredSignatures New required signatures
    function queueUpdateMultiSigConfig(address[] calldata _newSigners, uint256 _newRequiredSignatures) external onlyConfigAdmin {
        if (_newSigners.length < _newRequiredSignatures || _newRequiredSignatures == 0) revert InvalidAddress();
        for (uint256 i = 0; i < _newSigners.length; i++) {
            if (_newSigners[i] == address(0)) revert InvalidAddress();
            for (uint256 j = i + 1; j < _newSigners.length; j++) {
                if (_newSigners[i] == _newSigners[j]) revert DuplicateSigner();
            }
        }
        bytes memory data = abi.encodeWithSignature("executeUpdateMultiSigConfig(address[],uint256)", _newSigners, _newRequiredSignatures);
        try core._queueTimeLock(
            TelemedicineCore.TimeLockAction.ConfigurationUpdate,
            address(this),
            0,
            data
        ) {} catch {
            revert ExternalCallFailed();
        }
    }

    /// @notice Executes multi-signature configuration update
    /// @param _newSigners New signers
    /// @param _newRequiredSignatures New required signatures
    function executeUpdateMultiSigConfig(address[] calldata _newSigners, uint256 _newRequiredSignatures) external onlyConfigAdmin {
        multiSigSigners = _newSigners;
        requiredSignatures = _newRequiredSignatures;
        emit MultiSigConfigUpdated(_newSigners, _newRequiredSignatures);
    }

    /// @notice Books an appointment
    /// @param _doctors Doctor addresses
    /// @param _timestamp Scheduled timestamp
    /// @param _paymentType Payment type
    /// @param _isVideoCall Video call flag
    /// @param _videoCallLinkHash Hashed video call link
    function bookAppointment(
        address[] calldata _doctors,
        uint48 _timestamp,
        ITelemedicinePayments.PaymentType _paymentType,
        bool _isVideoCall,
        bytes32 _videoCallLinkHash
    ) external payable onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
        if (_doctors.length == 0 || _doctors.length > maxDoctorsPerAppointment) revert InvalidAddress();
        if (_isVideoCall && _videoCallLinkHash == bytes32(0)) revert InvalidVideoCallLink();
        try core.minBookingBuffer() returns (uint256 buffer) {
            if (_timestamp <= block.timestamp.add(buffer)) revert InvalidTimestamp();
        } catch {
            revert ExternalCallFailed();
        }
        if (appointmentCounter >= MAX_COUNTER) revert CounterOverflow();

        for (uint256 i = 0; i < _doctors.length; i++) {
            if (_doctors[i] == address(0)) revert InvalidAddress();
            try core.doctors(_doctors[i]) returns (TelemedicineCore.Doctor memory doctor) {
                if (!doctor.isVerified || !core.hasRole(core.DOCTOR_ROLE(), _doctors[i])) revert NotAuthorized();
            } catch {
                revert ExternalCallFailed();
            }
        }

        try core.decayPoints(msg.sender) {} catch {
            revert ExternalCallFailed();
        }
        uint256 baseFee;
        for (uint256 i = 0; i < _doctors.length; i++) {
            try core.getDoctorFee(_doctors[i]) returns (uint256 fee) {
                baseFee = baseFee.add(fee);
            } catch {
                revert ExternalCallFailed();
            }
        }
        uint256 discountedFee;
        try core._applyFeeDiscount(msg.sender, baseFee) returns (uint256 fee) {
            discountedFee = fee;
        } catch {
            revert ExternalCallFailed();
        }
        if (discountedFee > type(uint96).max) revert InsufficientFunds();
        bool isPriority;
        try core._isPriorityBooking(msg.sender) returns (bool priority) {
            isPriority = priority;
        } catch {
            revert ExternalCallFailed();
        }

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
            videoCallLinkHash: _isVideoCall ? _videoCallLinkHash : bytes32(0),
            disputeWindowEnd: 0,
            disputeOutcome: TelemedicineMedicalCore.DisputeOutcome.Unresolved
        });

        for (uint256 i = 0; i < _doctors.length; i++) {
            _addPendingAppointment(_doctors[i], newAppointmentId);
            if (isPriority) {
                doctorPriorityCounts[_doctors[i]] = doctorPriorityCounts[_doctors[i]].add(1);
            }
        }
        appointmentReminders[newAppointmentId] = Reminder(true, 0, 0);

        try core.patients(msg.sender) returns (TelemedicineCore.Patient storage patient) {
            try core.pointsForActions("appointment") returns (uint256 points) {
                patient.gamification.mediPoints = uint96(patient.gamification.mediPoints.add(points));
            } catch {
                revert ExternalCallFailed();
            }
            patient.lastActivityTimestamp = uint48(block.timestamp);
        } catch {
            revert ExternalCallFailed();
        }

        if (_paymentType == ITelemedicinePayments.PaymentType.ETH) {
            if (msg.value < discountedFee) revert InsufficientFunds();
            try core.updateReserveFund(reserveAmount) {} catch {
                revert ExternalCallFailed();
            }
            emit ReserveFundAllocated(newAppointmentId, reserveAmount, _paymentType);
            emit PlatformFeeAllocated(newAppointmentId, platformAmount, _paymentType);
            if (msg.value > discountedFee) {
                safeTransferETH(msg.sender, msg.value.sub(discountedFee));
            }
        } else if (_paymentType == ITelemedicinePayments.PaymentType.USDC || _paymentType == ITelemedicinePayments.PaymentType.SONIC) {
            try payments._processPayment(_paymentType, discountedFee) {} catch {
                revert ExternalCallFailed();
            }
            IERC20Upgradeable token = _paymentType == ITelemedicinePayments.PaymentType.USDC ? payments.usdcToken() : payments.sonicToken();
            try token.safeTransfer(address(core), reserveAmount) {} catch {
                revert InsufficientFunds();
            }
            try core.updateReserveFund(reserveAmount) {} catch {
                revert ExternalCallFailed();
            }
            emit ReserveFundAllocated(newAppointmentId, reserveAmount, _paymentType);
            emit PlatformFeeAllocated(newAppointmentId, platformAmount, _paymentType);
        } else {
            revert InvalidPaymentType();
        }

        try core._levelUp(msg.sender) {} catch {
            revert ExternalCallFailed();
        }
        bytes32[] memory doctorHashes = new bytes32[](_doctors.length);
        for (uint256 i = 0; i < _doctors.length; i++) {
            doctorHashes[i] = keccak256(abi.encode(_doctors[i]));
        }
        emit AppointmentBooked(newAppointmentId, keccak256(abi.encode(msg.sender)), doctorHashes, _timestamp);
    }

    /// @notice Cancels multiple appointments
    /// @param _appointmentIds Appointment IDs
    function batchCancelAppointments(uint256[] calldata _appointmentIds) external onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
        for (uint256 i = 0; i < _appointmentIds.length; i++) {
            uint256 _appointmentId = _appointmentIds[i];
            Appointment storage apt = appointments[_appointmentId];
            if (_appointmentId == 0 || _appointmentId > appointmentCounter) revert InvalidIndex();
            if (apt.patient != msg.sender) revert NotAuthorized();
            if (apt.status != AppointmentStatus.Pending && apt.status != AppointmentStatus.Confirmed) continue;

            uint256 cancellationFee;
            try core.minCancellationBuffer() returns (uint256 buffer) {
                if (apt.scheduledTimestamp <= block.timestamp.add(buffer)) {
                    cancellationFee = uint256(apt.fee).mul(cancellationFeePercentage).div(PERCENTAGE_DENOMINATOR);
                    if (cancellationFee < MIN_CANCELLATION_FEE && cancellationFee > 0) {
                        cancellationFee = MIN_CANCELLATION_FEE;
                    }
                    emit CancellationFeeCharged(_appointmentId, cancellationFee);
                }
            } catch {
                revert ExternalCallFailed();
            }

            apt.status = AppointmentStatus.Cancelled;
            for (uint256 j = 0; j < apt.doctors.length; j++) {
                _removePendingAppointment(apt.doctors[j], _appointmentId);
                if (apt.isPriority) {
                    doctorPriorityCounts[apt.doctors[j]] = doctorPriorityCounts[apt.doctors[j]].sub(1);
                }
            }
            appointmentReminders[_appointmentId].active = false;

            if (apt.fee > cancellationFee) {
                try payments._refundPatient(apt.patient, apt.fee.sub(cancellationFee), apt.paymentType) {} catch {
                    revert ExternalCallFailed();
                }
            }
            emit AppointmentStatusUpdated(_appointmentId, "Cancelled");
        }
    }

    /// @notice Reschedules multiple appointments
    /// @param _appointmentIds Appointment IDs
    /// @param _newTimestamps New timestamps
    function batchRescheduleAppointments(uint256[] calldata _appointmentIds, uint48[] calldata _newTimestamps)
        external onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
        if (_appointmentIds.length != _newTimestamps.length) revert InvalidIndex();
        try core.minBookingBuffer() returns (uint256 buffer) {
            for (uint256 i = 0; i < _appointmentIds.length; i++) {
                uint256 _appointmentId = _appointmentIds[i];
                uint48 _newTimestamp = _newTimestamps[i];
                Appointment storage apt = appointments[_appointmentId];
                if (_appointmentId == 0 || _appointmentId > appointmentCounter) revert InvalidIndex();
                if (apt.patient != msg.sender) revert NotAuthorized();
                if (apt.status != AppointmentStatus.Pending && apt.status != AppointmentStatus.Confirmed) continue;
                if (_newTimestamp <= block.timestamp.add(buffer)) revert InvalidTimestamp();

                apt.scheduledTimestamp = _newTimestamp;
                apt.status = AppointmentStatus.Rescheduled;
                appointmentReminders[_appointmentId].lastReminderTimestamp = 0;
                emit AppointmentStatusUpdated(_appointmentId, "Rescheduled");
            }
        } catch {
            revert ExternalCallFailed();
        }
    }

    /// @notice Confirms an appointment
    /// @param _appointmentId Appointment ID
    /// @param _overridePriority Override priority flag
    function confirmAppointment(uint256 _appointmentId, bool _overridePriority)
        public onlyRole(core.DOCTOR_ROLE()) whenNotPaused {
        Appointment storage apt = appointments[_appointmentId];
        if (_appointmentId == 0 || _appointmentId > appointmentCounter) revert InvalidIndex();
        bool isDoctor;
        for (uint256 i = 0; i < apt.doctors.length; i++) {
            if (apt.doctors[i] == msg.sender) {
                isDoctor = true;
                break;
            }
        }
        if (!isDoctor) revert NotAuthorized();
        if (apt.status != AppointmentStatus.Pending) revert InvalidAppointmentStatus();
        if (_overridePriority) {
            try core.hasRole(core.ADMIN_ROLE(), msg.sender) returns (bool hasRole) {
                if (!hasRole) revert NotAuthorized();
            } catch {
                revert ExternalCallFailed();
            }
        } else if (!apt.isPriority && doctorPriorityCounts[msg.sender] > 0) {
            revert InvalidAppointmentStatus();
        }

        apt.status = AppointmentStatus.Confirmed;
        _removePendingAppointment(msg.sender, _appointmentId);
        if (apt.isPriority) {
            doctorPriorityCounts[msg.sender] = doctorPriorityCounts[msg.sender].sub(1);
        }
        if (apt.isVideoCall) emit VideoCallStarted(_appointmentId, apt.videoCallLinkHash);
        emit AppointmentStatusUpdated(_appointmentId, "Confirmed");
    }

    /// @notice Confirms multiple appointments
    /// @param _startIndex Start index
    /// @param _pageSize Page size
    function batchConfirmAppointments(uint256 _startIndex, uint256 _pageSize)
        external onlyRole(core.DOCTOR_ROLE()) whenNotPaused {
        if (_pageSize > maxBatchSize || _pageSize == 0) revert InvalidPageSize();
        PendingAppointments storage pending = doctorPendingAppointments[msg.sender];
        if (_startIndex >= pending.count) revert InvalidIndex();

        uint256 endIndex = _startIndex.add(_pageSize) > pending.count ? pending.count : _startIndex.add(_pageSize);
        uint256[] memory confirmedIds = new uint256[](endIndex.sub(_startIndex));
        uint256 confirmedCount;

        for (uint256 i = _startIndex; i < endIndex; i++) {
            uint256 appointmentId = pending.ids[i];
            Appointment storage apt = appointments[appointmentId];
            if (apt.status != AppointmentStatus.Pending) continue;

            apt.status = AppointmentStatus.Confirmed;
            _removePendingAppointment(msg.sender, appointmentId);
            if (apt.isPriority) {
                doctorPriorityCounts[msg.sender] = doctorPriorityCounts[msg.sender].sub(1);
            }
            if (apt.isVideoCall) emit VideoCallStarted(appointmentId, apt.videoCallLinkHash);
            emit AppointmentStatusUpdated(appointmentId, "Confirmed");
            confirmedIds[confirmedCount] = appointmentId;
            confirmedCount = confirmedCount.add(1);
        }

        if (confirmedCount > 0) {
            uint256[] memory trimmedIds = new uint256[](confirmedCount);
            for (uint256 i = 0; i < confirmedCount; i++) {
                trimmedIds[i] = confirmedIds[i];
            }
            emit BatchAppointmentsConfirmed(keccak256(abi.encode(msg.sender)), trimmedIds);
        }
    }

    /// @notice Completes an appointment
    /// @param _appointmentId Appointment ID
    /// @param _ipfsSummaryHash Hashed IPFS summary
    /// @param _operationHash Operation hash
    function completeAppointment(uint256 _appointmentId, bytes32 _ipfsSummaryHash, bytes32 _operationHash)
        external onlyRole(core.DOCTOR_ROLE()) nonReentrant whenNotPaused onlyMultiSig(_operationHash) {
        bytes32 expectedHash = keccak256(abi.encodePacked(
            "completeAppointment",
            _appointmentId,
            _ipfsSummaryHash,
            msg.sender,
            block.timestamp,
            nonces[msg.sender] = nonces[msg.sender].add(1) % 1_000_000 // New: Cap nonces
        ));
        if (_operationHash != expectedHash) revert MultiSigNotApproved();

        Appointment storage apt = appointments[_appointmentId];
        if (_appointmentId == 0 || _appointmentId > appointmentCounter) revert InvalidIndex();
        bool isDoctor;
        for (uint256 i = 0; i < apt.doctors.length; i++) {
            if (apt.doctors[i] == msg.sender) {
                isDoctor = true;
                break;
            }
        }
        if (!isDoctor) revert NotAuthorized();
        if (apt.status != AppointmentStatus.Confirmed) revert InvalidAppointmentStatus();
        if (apt.scheduledTimestamp > block.timestamp) revert InvalidTimestamp();
        if (_ipfsSummaryHash == bytes32(0)) revert InvalidVideoCallLink();

        bool isDisputed;
        try disputeResolution.isDisputed(_appointmentId) returns (bool disputed) {
            isDisputed = disputed;
        } catch {
            revert ExternalCallFailed();
        }
        if (isDisputed) {
            TelemedicineMedicalCore.DisputeOutcome outcome;
            try disputeResolution.getDisputeOutcome(_appointmentId) returns (TelemedicineMedicalCore.DisputeOutcome o) {
                outcome = o;
            } catch {
                revert ExternalCallFailed();
            }
            if (outcome == TelemedicineMedicalCore.DisputeOutcome.Unresolved) revert InvalidAppointmentStatus();
            apt.disputeOutcome = outcome;
        }

        apt.status = AppointmentStatus.Completed;
        apt.disputeWindowEnd = uint48(block.timestamp).add(disputeWindow);
        appointmentReminders[_appointmentId].active = false;

        uint256 doctorPayment = uint256(apt.fee).mul(doctorFeePercentage).div(PERCENTAGE_DENOMINATOR).div(apt.doctors.length);
        for (uint256 i = 0; i < apt.doctors.length; i++) {
            try operations._releasePayment(apt.doctors[i], doctorPayment, apt.paymentType) {} catch {
                revert ExternalCallFailed();
            }
            emit DoctorPaid(_appointmentId, keccak256(abi.encode(apt.doctors[i])), doctorPayment, apt.paymentType);
        }

        if (apt.disputeOutcome != TelemedicineMedicalCore.DisputeOutcome.Unresolved) {
            try operations.notifyDisputeResolved(_appointmentId, "Appointment", apt.disputeOutcome) {} catch {
                revert ExternalCallFailed();
            }
        }
        emit AppointmentStatusUpdated(_appointmentId, "Completed");
        emit AppointmentCompleted(_appointmentId, _ipfsSummaryHash);
        _resetMultiSigApprovals(_operationHash);
    }

    /// @notice Triggers appointment reminder
    /// @param _appointmentId Appointment ID
    function triggerAppointmentReminder(uint256 _appointmentId) external whenNotPaused {
        Appointment storage apt = appointments[_appointmentId];
        Reminder storage reminder = appointmentReminders[_appointmentId];
        if (_appointmentId == 0 || _appointmentId > appointmentCounter) revert InvalidIndex();
        if (apt.status != AppointmentStatus.Confirmed) revert InvalidAppointmentStatus();
        if (!reminder.active) revert InvalidAppointmentStatus();
        if (apt.scheduledTimestamp <= block.timestamp) revert InvalidTimestamp();
        if (reminder.lastReminderTimestamp.add(reminderInterval) > block.timestamp) revert InvalidTimestamp();
        if (reminder.reminderCount >= 3) revert InvalidAppointmentStatus();

        reminder.lastReminderTimestamp = uint48(block.timestamp);
        reminder.reminderCount = reminder.reminderCount.add(1);
        emit AppointmentReminderSent(_appointmentId, keccak256(abi.encode(apt.patient)), uint48(block.timestamp));
    }

    /// @notice Approves critical operation
    /// @param _operationHash Operation hash
    function approveCriticalOperation(bytes32 _operationHash) external {
        bool isSigner;
        for (uint256 i = 0; i < multiSigSigners.length; i++) {
            if (multiSigSigners[i] == msg.sender) {
                isSigner = true;
                break;
            }
        }
        if (!isSigner) revert NotAuthorized();
        if (multiSigApprovals[msg.sender][_operationHash]) revert NotAuthorized();

        multiSigApprovals[msg.sender][_operationHash] = true;
        emit MultiSigApproval(keccak256(abi.encode(msg.sender)), _operationHash);
    }

    /// @notice Checks multi-signature approval
    /// @param _operationHash Operation hash
    /// @return True if approved
    function checkMultiSigApproval(bytes32 _operationHash) public view returns (bool) {
        uint256 approvalCount;
        for (uint256 i = 0; i < multiSigSigners.length; i++) {
            if (multiSigApprovals[multiSigSigners[i]][_operationHash]) {
                approvalCount = approvalCount.add(1);
            }
        }
        return approvalCount >= requiredSignatures;
    }

    // Internal Functions

    /// @notice Adds pending appointment
    /// @param _doctor Doctor address
    /// @param _appointmentId Appointment ID
    function _addPendingAppointment(address _doctor, uint256 _appointmentId) internal {
        try core.MAX_PENDING_APPOINTMENTS() returns (uint256 maxPending) {
            PendingAppointments storage pending = doctorPendingAppointments[_doctor];
            if (pending.count >= maxPending) revert InvalidPageSize();
            pending.appointmentIds[_appointmentId] = pending.count;
            pending.ids.push(_appointmentId);
            pending.count = pending.count.add(1);
        } catch {
            revert ExternalCallFailed();
        }
    }

    /// @notice Removes pending appointment
    /// @param _doctor Doctor address
    /// @param _appointmentId Appointment ID
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

    /// @notice Checks for pending priority appointments
    /// @param _doctor Doctor address
    /// @return True if exists
    function _hasPendingPriorityAppointments(address _doctor) internal view returns (bool) {
        return doctorPriorityCounts[_doctor] > 0;
    }

    /// @notice Resets multi-signature approvals
    /// @param _operationHash Operation hash
    function _resetMultiSigApprovals(bytes32 _operationHash) internal {
        for (uint256 i = 0; i < multiSigSigners.length; i++) {
            multiSigApprovals[multiSigSigners[i]][_operationHash] = false;
        }
    }

    /// @notice Transfers ETH safely
    /// @param _to Recipient
    /// @param _amount Amount
    function safeTransferETH(address _to, uint256 _amount) internal {
        if (_amount == 0) return;
        (bool success, ) = _to.call{value: _amount}("");
        if (!success) revert InsufficientFunds();
    }

    // View Functions

    /// @notice Gets appointment
    /// @param _appointmentId Appointment ID
    /// @return Appointment details
    function getAppointment(uint256 _appointmentId) external view onlyConfigAdmin returns (Appointment memory) {
        return appointments[_appointmentId];
    }

    /// @notice Gets pending appointments
    /// @param _doctor Doctor address
    /// @return Pending appointment IDs
    function getPendingAppointments(address _doctor) external view onlyConfigAdmin returns (uint256[] memory) {
        return doctorPendingAppointments[_doctor].ids;
    }

    /// @notice Gets reminder
    /// @param _appointmentId Appointment ID
    /// @return Reminder details
    function getReminder(uint256 _appointmentId) external view onlyConfigAdmin returns (Reminder memory) {
        return appointmentReminders[_appointmentId];
    }

    /// @notice Gets nonce
    /// @param _user User address
    /// @return Nonce
    function getNonce(address _user) external view onlyConfigAdmin returns (uint256) {
        return nonces[_user];
    }

    // Utility Functions

    /// @notice Checks if an address is a contract
    /// @param addr Address
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

    modifier onlyMultiSig(bytes32 _operationHash) {
        if (!checkMultiSigApproval(_operationHash)) revert MultiSigNotApproved();
        _;
    }

    // State Variables for Multi-Signature
    mapping(address => mapping(bytes32 => bool)) private multiSigApprovals; // New: Local multi-sig approvals

    receive() external payable {}

    // New: Storage gap
    uint256[50] private __gap;
}
