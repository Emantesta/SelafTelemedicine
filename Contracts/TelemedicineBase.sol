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
import {IERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import {TelemedicineOperations} from "./TelemedicineOperations.sol";

contract TelemedicineBase is Initializable, ReentrancyGuardUpgradeable, ChainlinkClient {
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
    error InvalidPercentage();

    // Contract dependencies
    TelemedicineCore public core;
    TelemedicinePayments public payments;
    TelemedicineDisputeResolution public disputeResolution;
    TelemedicineOperations public operations;

    // Chainlink Configuration
    address public chainlinkOracle;
    bytes32 public priceListJobId;
    uint256 public chainlinkFee;
    LinkTokenInterface public linkToken;
    uint48 public chainlinkRequestTimeout;
    bool public manualPriceOverride;

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
    mapping(address => PendingAppointments) public doctorPendingAppointments;
    mapping(uint256 => Reminder) public appointmentReminders;
    mapping(address => uint256) public nonces;
    address[] public multiSigSigners;
    uint256 public appointmentCounter;
    uint256 public requiredSignatures;

    // Enums
    enum AppointmentStatus { Pending, Confirmed, Completed, Cancelled, Rescheduled, Emergency, Disputed }
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
    event VideoCallStarted(uint256 indexed appointmentId, string videoCallLink);
    event BatchAppointmentsConfirmed(address indexed doctor, uint256[] appointmentIds);
    event DoctorPaid(uint256 indexed appointmentId, address indexed doctor, uint256 amount, TelemedicinePayments.PaymentType paymentType);
    event ReserveFundAllocated(uint256 indexed appointmentId, uint256 amount, TelemedicinePayments.PaymentType paymentType);
    event PlatformFeeAllocated(uint256 indexed appointmentId, uint256 amount, TelemedicinePayments.PaymentType paymentType);
    event AppointmentReminderSent(uint256 indexed appointmentId, address patient, uint48 timestamp);
    event CancellationFeeCharged(uint256 indexed appointmentId, uint256 amount);
    event ConfigurationUpdated(string parameter, uint256 value);

    function initialize(
        address _core,
        address _payments,
        address _disputeResolution,
        address _operations,
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
            _operations == address(0) || _chainlinkOracle == address(0) || _linkToken == address(0)) revert InvalidAddress();
        if (_multiSigSigners.length < _requiredSignatures || _requiredSignatures == 0) revert InvalidAddress();
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
        operations = TelemedicineOperations(_operations);
        chainlinkOracle = _chainlinkOracle;
        priceListJobId = _priceListJobId;
        linkToken = LinkTokenInterface(_linkToken);
        setChainlinkToken(_linkToken);
        chainlinkFee = 0.1 ether;
        chainlinkRequestTimeout = 30 minutes;
        manualPriceOverride = false;
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

        appointmentCounter = 0;
    }

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
        if (paramHash == keccak256("doctorFeePercentage") || paramHash == keccak256("reserveFundPercentage") || paramHash == keccak256("platformFeePercentage")) {
            if (doctorFeePercentage + reserveFundPercentage + platformFeePercentage != 100) revert InvalidPercentage();
        }
        emit ConfigurationUpdated(_parameter, _value);
    }

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
                if (!payments.usdcToken().transfer(address(core), reserveAmount)) revert InsufficientFunds();
                core.reserveFund = core.reserveFund + reserveAmount;
            } else if (_paymentType == TelemedicinePayments.PaymentType.SONIC) {
                if (!payments.sonicToken().transfer(address(core), reserveAmount)) revert InsufficientFunds();
                core.reserveFund = core.reserveFund + reserveAmount;
            }
            emit ReserveFundAllocated(newAppointmentId, reserveAmount, _paymentType);
            emit PlatformFeeAllocated(newAppointmentId, platformAmount, _paymentType);
        }

        core._levelUp(msg.sender);
        emit AppointmentBooked(newAppointmentId, msg.sender, _doctors, _timestamp, _videoCallLink);
    }

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
            operations._releasePayment(apt.doctors[i], doctorPayment, apt.paymentType);
            emit DoctorPaid(_appointmentId, apt.doctors[i], doctorPayment, apt.paymentType);
        }

        if (apt.disputeOutcome != DisputeOutcome.Unresolved) {
            operations.notifyDisputeResolved(_appointmentId, "Appointment", apt.disputeOutcome);
        }
        emit AppointmentStatusUpdated(_appointmentId, "Completed");
        emit AppointmentCompleted(_appointmentId, _ipfsSummary);
    }

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

    function _addPendingAppointment(address _doctor, uint256 _appointmentId) internal {
        PendingAppointments storage pending = doctorPendingAppointments[_doctor];
        if (pending.count >= core.MAX_PENDING_APPOINTMENTS()) revert InvalidPageSize();
        pending.appointmentIds[_appointmentId] = pending.count;
        pending.ids.push(_appointmentId);
        pending.count = pending.count + 1;
    }

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

    function _hasPendingPriorityAppointments(address _doctor) internal view returns (bool) {
        PendingAppointments storage pending = doctorPendingAppointments[_doctor];
        for (uint256 i = 0; i < pending.count; i++) {
            if (appointments[pending.ids[i]].isPriority) return true;
        }
        return false;
    }

    function _safeTransferETH(address _to, uint256 _amount) internal {
        (bool success, ) = _to.call{value: _amount}("");
        if (!success) revert InsufficientFunds();
    }

    modifier onlyRole(bytes32 role) {
        if (!core.hasRole(role, msg.sender)) revert NotAuthorized();
        _;
    }

    modifier whenNotPaused() {
        if (core.paused()) revert ContractPaused();
        _;
    }

    modifier onlyMultiSig(bytes32 _operationHash) {
        if (!operations.checkMultiSigApproval(_operationHash)) revert MultiSigNotApproved();
        _;
    }

    receive() external payable {}
}
