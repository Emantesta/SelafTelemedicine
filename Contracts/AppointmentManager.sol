<xaiArtifact artifact_id="2694b9c0-a8e7-4556-968d-5642ea1a50d2" artifact_version_id="87f049b5-e4c5-49ad-9b5d-e4f577184f02" title="AppointmentManager.sol" contentType="text/solidity">
// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
import {TelemedicineBase} from "./TelemedicineBase.sol";
import {IERC20} from "@openzeppelin
/contracts/token/ERC20/IERC20.sol";
contract AppointmentManager is TelemedicineBase {
    // Enums
    enum AppointmentStatus { Pending, Confirmed, Completed, Cancelled, Rescheduled, Emergency }
    enum PaymentType { ETH, USDC, SONIC }

// Structs
struct Appointment {
    uint256 id;
    address patient;
    address doctor;
    uint48 scheduledTimestamp;
    AppointmentStatus status;
    uint96 fee;
    PaymentType paymentType;
    bool isVideoCall;
    bool isPriority;
    string videoCallLink;
}

struct Doctor {
    bool isVerified;
    uint96 consultationFee;
    string licenseNumber;
}

struct Node {
    uint256 appointmentId;
    uint256 prev;
    uint256 next;
}

struct PendingAppointments {
    mapping(uint256 => Node) nodes; // Doubly-linked list for pending appointments
    uint256 head; // 0 if empty
    uint256 count;
}

// State Variables
mapping(address => Doctor) public doctors;
mapping(uint256 => Appointment) public appointments;
mapping(address => PendingAppointments) public doctorPendingAppointments;
mapping(address => uint256[]) public doctorPriorityAppointments; // Priority queue
mapping(address => mapping(uint48 => bool)) public doctorSchedules; // Tracks doctor availability
uint256 public appointmentCounter;
IERC20 public usdcToken; // USDC contract address
IERC20 public sonicToken; // SONIC contract address
address payable public treasury; // Where payments are sent

// Constants
uint256 public constant MAX_PENDING_APPOINTMENTS = 100;

// Events
event AppointmentBooked(uint256 indexed appointmentId, address patient, address doctor, uint256 timestamp, string videoCallLink);
event AppointmentStatusUpdated(uint256 indexed appointmentId, AppointmentStatus status);
event AppointmentCompleted(uint256 indexed appointmentId, string ipfsSummary);
event VideoCallStarted(uint256 indexed appointmentId, string videoCallLink);
event BatchAppointmentsConfirmed(address indexed doctor, uint256[] appointmentIds);
event BatchAppointmentsCancelled(address indexed patient, uint256[] appointmentIds);
event DoctorFeeUpdated(address indexed doctor, uint96 newFee);

// Initializer
function initialize(
    address _usdcToken,
    address _sonicToken,
    address payable _treasury,
    address _ethUsdPriceFeed,
    address _sonicUsdPriceFeed,
    address _entryPoint,
    address _paymaster,
    address _usdFiatOracle,
    address _dataAccessOracle,
    address _onRampProvider,
    address _offRampProvider,
    address[] memory _initialAdmins
) external initializer {
    initialize(
        _usdcToken,
        _sonicToken,
        _ethUsdPriceFeed,
        _sonicUsdPriceFeed,
        _entryPoint,
        _paymaster,
        _usdFiatOracle,
        _dataAccessOracle,
        _onRampProvider,
        _offRampProvider,
        _initialAdmins
    );
    usdcToken = IERC20(_usdcToken);
    sonicToken = IERC20(_sonicToken);
    treasury = _treasury;
    appointmentCounter = 1; // Start at 1 to avoid ID 0 confusion
}

// Book an appointment with payment
function bookAppointment(
    address _doctor,
    uint48 _timestamp,
    PaymentType _paymentType,
    bool _isVideoCall,
    string calldata _videoCallLink,
    uint256 _discountedFee,
    bool _isPriority
) external payable onlyRole(PATIENT_ROLE) nonReentrant returns (uint256) {
    require(doctors[_doctor].isVerified, "Doctor not verified");
    require(_timestamp > uint48(block.timestamp + minBookingBuffer), "Booking time too soon");
    require(_discountedFee <= type(uint96).max, "Fee exceeds uint96 maximum");
    require(!doctorSchedules[_doctor][_timestamp], "Doctor unavailable at this time");

    // Handle payment
    if (_paymentType == PaymentType.ETH) {
        require(msg.value == _discountedFee, "Incorrect ETH amount");
        (bool success, ) = treasury.call{value: msg.value}("");
        require(success, "ETH transfer failed");
    } else if (_paymentType == PaymentType.USDC) {
        require(usdcToken.transferFrom(msg.sender, treasury, _discountedFee), "USDC transfer failed");
    } else if (_paymentType == PaymentType.SONIC) {
        require(sonicToken.transferFrom(msg.sender, treasury, _discountedFee), "SONIC transfer failed");
    }

    uint256 newId = appointmentCounter++;
    appointments[newId] = Appointment(
        newId, msg.sender, _doctor, _timestamp, AppointmentStatus.Pending, uint96(_discountedFee),
        _paymentType, _isVideoCall, _isPriority, _isVideoCall ? _videoCallLink : ""
    );
    _addPendingAppointment(_doctor, newId);
    if (_isPriority) {
        doctorPriorityAppointments[_doctor].push(newId);
    }
    doctorSchedules[_doctor][_timestamp] = true;
    emit AppointmentBooked(newId, msg.sender, _doctor, _timestamp, _videoCallLink);
    return newId;
}

// Emergency booking with relaxed constraints
function emergencyBookAppointment(
    address _doctor,
    uint48 _timestamp,
    PaymentType _paymentType,
    bool _isVideoCall,
    string calldata _videoCallLink,
    uint256 _discountedFee
) external payable onlyRole(PATIENT_ROLE) nonReentrant returns (uint256) {
    require(doctors[_doctor].isVerified, "Doctor not verified");
    require(_discountedFee <= type(uint96).max, "Fee exceeds uint96 maximum");

    // Handle payment
    if (_paymentType == PaymentType.ETH) {
        require(msg.value == _discountedFee, "Incorrect ETH amount");
        (bool success, ) = treasury.call{value: msg.value}("");
        require(success, "ETH transfer failed");
    } else if (_paymentType == PaymentType.USDC) {
        require(usdcToken.transferFrom(msg.sender, treasury, _discountedFee), "USDC transfer failed");
    } else if (_paymentType == PaymentType.SONIC) {
        require(sonicToken.transferFrom(msg.sender, treasury, _discountedFee), "SONIC transfer failed");
    }

    uint256 newId = appointmentCounter++;
    appointments[newId] = Appointment(
        newId, msg.sender, _doctor, _timestamp, AppointmentStatus.Emergency, uint96(_discountedFee),
        _paymentType, _isVideoCall, true, _isVideoCall ? _videoCallLink : ""
    );
    _addPendingAppointment(_doctor, newId);
    doctorPriorityAppointments[_doctor].push(newId);
    doctorSchedules[_doctor][_timestamp] = true;
    emit AppointmentBooked(newId, msg.sender, _doctor, _timestamp, _videoCallLink);
    return newId;
}

// Cancel an appointment with refund
function cancelAppointment(uint256 _appointmentId) external onlyRole(PATIENT_ROLE) nonReentrant {
    Appointment storage apt = appointments[_appointmentId];
    require(apt.patient == msg.sender, "Not your appointment");
    require(apt.status == AppointmentStatus.Pending || apt.status == AppointmentStatus.Confirmed, "Cannot cancel: invalid status");
    require(apt.scheduledTimestamp > block.timestamp + minCancellationBuffer, "Too late to cancel");

    // Refund logic
    if (apt.paymentType == PaymentType.ETH) {
        refunds[msg.sender] += apt.fee;
    } else if (apt.paymentType == PaymentType.USDC) {
        require(usdcToken.transfer(msg.sender, apt.fee), "USDC refund failed");
    } else if (apt.paymentType == PaymentType.SONIC) {
        require(sonicToken.transfer(msg.sender, apt.fee), "SONIC refund failed");
    }

    apt.status = AppointmentStatus.Cancelled;
    _removePendingAppointment(apt.doctor, _appointmentId);
    doctorSchedules[apt.doctor][apt.scheduledTimestamp] = false;
    emit AppointmentStatusUpdated(_appointmentId, AppointmentStatus.Cancelled);
}

// Batch cancel appointments
function batchCancelAppointments(uint256[] calldata _appointmentIds) external onlyRole(PATIENT_ROLE) nonReentrant {
    for (uint256 i = 0; i < _appointmentIds.length; i++) {
        Appointment storage apt = appointments[_appointmentIds[i]];
        require(apt.patient == msg.sender, "Not your appointment");
        require(apt.status == AppointmentStatus.Pending || apt.status == AppointmentStatus.Confirmed, "Cannot cancel: invalid status");
        require(apt.scheduledTimestamp > block.timestamp + minCancellationBuffer, "Too late to cancel");

        if (apt.paymentType == PaymentType.ETH) {
            refunds[msg.sender] += apt.fee;
        } else if (apt.paymentType == PaymentType.USDC) {
            require(usdcToken.transfer(msg.sender, apt.fee), "USDC refund failed");
        } else if (apt.paymentType == PaymentType.SONIC) {
            require(sonicToken.transfer(msg.sender, apt.fee), "SONIC refund failed");
        }

        apt.status = AppointmentStatus.Cancelled;
        _removePendingAppointment(apt.doctor, _appointmentIds[i]);
        doctorSchedules[apt.doctor][apt.scheduledTimestamp] = false;
    }
    emit BatchAppointmentsCancelled(msg.sender, _appointmentIds);
}

// Confirm with optional video call link update
function confirmAppointment(uint256 _appointmentId, bool _overridePriority, string calldata _newVideoCallLink) external onlyRole(DOCTOR_ROLE) nonReentrant {
    Appointment storage apt = appointments[_appointmentId];
    require(apt.doctor == msg.sender, "Not your appointment");
    require(apt.status == AppointmentStatus.Pending || apt.status == AppointmentStatus.Emergency, "Appointment not pending");

    if (_overridePriority) {
        require(hasRole(ADMIN_ROLE, msg.sender), "Override requires admin privileges");
    } else if (!apt.isPriority) {
        require(!_hasPendingPriorityAppointments(apt.doctor), "Priority appointments pending");
    }

    apt.status = AppointmentStatus.Confirmed;
    if (apt.isVideoCall && bytes(_newVideoCallLink).length > 0) {
        apt.videoCallLink = _newVideoCallLink;
    }
    _removePendingAppointment(msg.sender, _appointmentId);
    if (apt.isPriority) {
        _removePriorityAppointment(msg.sender, _appointmentId);
    }
    if (apt.isVideoCall) emit VideoCallStarted(_appointmentId, apt.videoCallLink);
    emit AppointmentStatusUpdated(_appointmentId, AppointmentStatus.Confirmed);
}

// Batch confirm appointments
function batchConfirmAppointments(uint256[] calldata _appointmentIds) external onlyRole(DOCTOR_ROLE) nonReentrant {
    for (uint256 i = 0; i < _appointmentIds.length; i++) {
        Appointment storage apt = appointments[_appointmentIds[i]];
        require(apt.doctor == msg.sender, "Not your appointment");
        require(apt.status == AppointmentStatus.Pending || apt.status == AppointmentStatus.Emergency, "Appointment not pending");
        require(apt.isPriority || !_hasPendingPriorityAppointments(msg.sender), "Priority appointments pending");

        apt.status = AppointmentStatus.Confirmed;
        _removePendingAppointment(msg.sender, _appointmentIds[i]);
        if (apt.isPriority) {
            _removePriorityAppointment(msg.sender, _appointmentIds[i]);
        }
        if (apt.isVideoCall) emit VideoCallStarted(_appointmentIds[i], apt.videoCallLink);
        emit AppointmentStatusUpdated(_appointmentIds[i], AppointmentStatus.Confirmed);
    }
    emit BatchAppointmentsConfirmed(msg.sender, _appointmentIds);
}

// Complete an appointment
function completeAppointment(uint256 _appointmentId, string calldata _ipfsSummary) external onlyRole(DOCTOR_ROLE) nonReentrant {
    Appointment storage apt = appointments[_appointmentId];
    require(apt.doctor == msg.sender, "Not your appointment");
    require(apt.status == AppointmentStatus.Confirmed, "Appointment not confirmed");
    require(apt.scheduledTimestamp <= block.timestamp, "Appointment not yet started");

    apt.status = AppointmentStatus.Completed;
    emit AppointmentStatusUpdated(_appointmentId, AppointmentStatus.Completed);
    emit AppointmentCompleted(_appointmentId, _ipfsSummary);
}

// Reschedule with constraints
function rescheduleAppointment(uint256 _appointmentId, uint48 _newTimestamp, string calldata _newVideoCallLink) external nonReentrant {
    Appointment storage apt = appointments[_appointmentId];
    bool isPatient = hasRole(PATIENT_ROLE, msg.sender);
    bool isDoctor = hasRole(DOCTOR_ROLE, msg.sender);
    require((isPatient && apt.patient == msg.sender) || (isDoctor && apt.doctor == msg.sender), "Not authorized");
    require(apt.status == AppointmentStatus.Pending || apt.status == AppointmentStatus.Confirmed, "Cannot reschedule: invalid status");
    require(_newTimestamp > uint48(block.timestamp + minBookingBuffer), "New time too soon");
    require(_newTimestamp > uint48(block.timestamp + minCancellationBuffer), "New time too close to original");
    require(!doctorSchedules[apt.doctor][_newTimestamp], "Doctor unavailable at new time");

    if (apt.status == AppointmentStatus.Confirmed) {
        apt.status = AppointmentStatus.Pending;
        _addPendingAppointment(apt.doctor, _appointmentId);
        if (apt.isPriority) {
            doctorPriorityAppointments[apt.doctor].push(_appointmentId);
        }
    }
    doctorSchedules[apt.doctor][apt.scheduledTimestamp] = false;
    apt.scheduledTimestamp = _newTimestamp;
    doctorSchedules[apt.doctor][_newTimestamp] = true;
    if (apt.isVideoCall) apt.videoCallLink = _newVideoCallLink;

    emit AppointmentStatusUpdated(_appointmentId, AppointmentStatus.Rescheduled);
    emit AppointmentBooked(_appointmentId, apt.patient, apt.doctor, _newTimestamp, apt.videoCallLink);
}

// Verify a doctor
function verifyDoctor(address _doctor, string calldata _licenseNumber, uint256 _fee) external onlyRole(ADMIN_ROLE) {
    require(_doctor != address(0), "Doctor address cannot be zero");
    require(_fee <= type(uint96).max, "Fee exceeds uint96 maximum");
    doctors[_doctor] = Doctor(true, uint96(_fee), _licenseNumber);
    _grantRole(DOCTOR_ROLE, _doctor);
    emit AuditLog(block.timestamp, msg.sender, "Doctor Verified");
}

// Update doctor fee
function updateDoctorFee(address _doctor, uint96 _newFee) external onlyRole(ADMIN_ROLE) {
    require(doctors[_doctor].isVerified, "Doctor not verified");
    doctors[_doctor].consultationFee = _newFee;
    emit DoctorFeeUpdated(_doctor, _newFee);
}

// Add to pending list (doubly-linked list)
function _addPendingAppointment(address _doctor, uint256 _appointmentId) private {
    PendingAppointments storage pending = doctorPendingAppointments[_doctor];
    require(pending.count < MAX_PENDING_APPOINTMENTS, "Max pending appointments reached");

    pending.nodes[_appointmentId] = Node(_appointmentId, 0, pending.head);
    if (pending.head != 0) {
        pending.nodes[pending.head].prev = _appointmentId;
    }
    pending.head = _appointmentId;
    pending.count += 1;
}

// Remove from pending list
function _removePendingAppointment(address _doctor, uint256 _appointmentId) private {
    PendingAppointments storage pending = doctorPendingAppointments[_doctor];
    Node storage node = pending.nodes[_appointmentId];
    require(node.appointmentId != 0 || pending.count > 0, "Appointment not pending");

    if (node.prev != 0) {
        pending.nodes[node.prev].next = node.next;
    } else {
        pending.head = node.next;
    }
    if (node.next != 0) {
        pending.nodes[node.next].prev = node.prev;
    }
    delete pending.nodes[_appointmentId];
    pending.count -= 1;
}

// Remove from priority queue
function _removePriorityAppointment(address _doctor, uint256 _appointmentId) private {
    uint256[] storage priorityList = doctorPriorityAppointments[_doctor];
    for (uint256 i = 0; i < priorityList.length; i++) {
        if (priorityList[i] == _appointmentId) {
            priorityList[i] = priorityList[priorityList.length - 1];
            priorityList.pop();
            break;
        }
    }
}

// Check for priority appointments
function _hasPendingPriorityAppointments(address _doctor) private view returns (bool) {
    return doctorPriorityAppointments[_doctor].length > 0;
}

}
</xaiArtifact>

