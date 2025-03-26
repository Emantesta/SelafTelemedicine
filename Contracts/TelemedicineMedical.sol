// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
import {Initializable} from "@openzeppelin
/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin
/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {SafeMathUpgradeable} from "@openzeppelin
/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";
import {TelemedicineCore} from "./TelemedicineCore.sol";
import {TelemedicinePayments} from "./TelemedicinePayments.sol";
contract TelemedicineMedical is Initializable, ReentrancyGuardUpgradeable {
    using SafeMathUpgradeable for uint256;

TelemedicineCore public core;
TelemedicinePayments public payments;

mapping(uint256 => Appointment) public appointments;
mapping(uint256 => LabTestOrder) public labTestOrders;
mapping(uint256 => Prescription) public prescriptions;
mapping(uint256 => AISymptomAnalysis) public aiAnalyses;
mapping(address => PendingAppointments) public doctorPendingAppointments;

uint256 public appointmentCounter;
uint256 public labTestCounter;
uint256 public prescriptionCounter;
uint256 public aiAnalysisCounter;

// Constants for fee distribution
uint256 public constant DOCTOR_FEE_PERCENTAGE = 75; // 75% to doctor
uint256 public constant RESERVE_FUND_PERCENTAGE = 5; // 5% to reserve fund
uint256 public constant PLATFORM_FEE_PERCENTAGE = 20; // 20% to platform (remaining)
uint256 public constant PERCENTAGE_DENOMINATOR = 100; // For percentage calculations

enum AppointmentStatus { Pending, Confirmed, Completed, Cancelled, Rescheduled, Emergency }
enum LabTestStatus { Requested, Collected, ResultsUploaded, Reviewed }
enum PrescriptionStatus { Generated, Verified, Fulfilled, Revoked, Expired }

struct Appointment {
    uint256 id;
    address patient;
    address doctor;
    uint48 scheduledTimestamp;
    AppointmentStatus status;
    uint96 fee;
    TelemedicinePayments.PaymentType paymentType;
    bool isVideoCall;
    bool isPriority;
    string videoCallLink;
}

struct LabTestOrder {
    uint256 id;
    address patient;
    address doctor;
    address labTech;
    LabTestStatus status;
    uint48 orderedTimestamp;
    uint48 completedTimestamp;
    string testType;
    string sampleCollectionIpfsHash;
    string resultsIpfsHash;
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
    string medicationDetails;
    string prescriptionIpfsHash;
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

event AppointmentBooked(uint256 indexed appointmentId, address patient, address doctor, uint256 timestamp, string videoCallLink);
event AppointmentStatusUpdated(uint256 indexed appointmentId, string status);
event AppointmentCompleted(uint256 indexed appointmentId, string ipfsSummary);
event LabTestOrdered(uint256 indexed testId, address patient, address doctor, string testType, uint48 orderedAt);
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
event DataRewardClaimed(address indexed patient, uint256 amount);
event BatchAppointmentsConfirmed(address indexed doctor, uint256[] appointmentIds);
event DoctorPaid(uint256 indexed appointmentId, address indexed doctor, uint256 amount, TelemedicinePayments.PaymentType paymentType);
event ReserveFundAllocated(uint256 indexed appointmentId, uint256 amount, TelemedicinePayments.PaymentType paymentType);
event PlatformFeeAllocated(uint256 indexed appointmentId, uint256 amount, TelemedicinePayments.PaymentType paymentType);

function initialize(address _core, address _payments) external initializer {
    __ReentrancyGuard_init();
    core = TelemedicineCore(_core);
    payments = TelemedicinePayments(_payments);
}

function bookAppointment(
    address _doctor,
    uint48 _timestamp,
    TelemedicinePayments.PaymentType _paymentType,
    bool _isVideoCall,
    string calldata _videoCallLink
) external payable onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
    require(_doctor != address(0), "Invalid doctor address");
    require(core.doctors(_doctor).isVerified, "Doctor not verified");
    require(_timestamp > block.timestamp.add(core.minBookingBuffer()), "Booking time too soon");

    core.decayPoints(msg.sender);
    uint256 baseFee = core.getDoctorFee(_doctor);
    uint256 discountedFee = core._applyFeeDiscount(msg.sender, baseFee);
    require(discountedFee <= type(uint96).max, "Fee exceeds uint96 maximum");
    bool isPriority = core._isPriorityBooking(msg.sender);

    // Calculate fee distribution
    uint256 reserveAmount = discountedFee.mul(RESERVE_FUND_PERCENTAGE).div(PERCENTAGE_DENOMINATOR);
    uint256 platformAmount = discountedFee.mul(PLATFORM_FEE_PERCENTAGE).div(PERCENTAGE_DENOMINATOR);
    uint256 doctorAmount = discountedFee.sub(reserveAmount).sub(platformAmount); // 75%

    appointmentCounter = appointmentCounter.add(1);
    uint256 newAppointmentId = appointmentCounter;

    if (_paymentType == TelemedicinePayments.PaymentType.ETH) {
        require(msg.value >= discountedFee, "Insufficient ETH payment");
        core.reserveFund = core.reserveFund.add(reserveAmount);
        emit ReserveFundAllocated(newAppointmentId, reserveAmount, _paymentType);
        // Platform fee stays in this contract for now; could transfer to payments
        emit PlatformFeeAllocated(newAppointmentId, platformAmount, _paymentType);
        if (msg.value > discountedFee) {
            uint256 refund = msg.value.sub(discountedFee);
            (bool success, ) = msg.sender.call{value: refund}("");
            require(success, "ETH refund failed");
        }
    } else {
        payments._processPayment(_paymentType, discountedFee);
        if (_paymentType == TelemedicinePayments.PaymentType.USDC) {
            require(payments.usdcToken().transfer(address(core), reserveAmount), "USDC reserve transfer failed");
            core.reserveFund = core.reserveFund.add(reserveAmount);
        } else if (_paymentType == TelemedicinePayments.PaymentType.SONIC) {
            require(payments.sonicToken().transfer(address(core), reserveAmount), "SONIC reserve transfer failed");
            core.reserveFund = core.reserveFund.add(reserveAmount);
        }
        emit ReserveFundAllocated(newAppointmentId, reserveAmount, _paymentType);
        emit PlatformFeeAllocated(newAppointmentId, platformAmount, _paymentType);
    }

    appointments[newAppointmentId] = Appointment(
        newAppointmentId,
        msg.sender,
        _doctor,
        _timestamp,
        AppointmentStatus.Pending,
        uint96(discountedFee),
        _paymentType,
        _isVideoCall,
        isPriority,
        _isVideoCall ? _videoCallLink : ""
    );
    _addPendingAppointment(_doctor, newAppointmentId);

    TelemedicineCore.Patient storage patient = core.patients(msg.sender);
    patient.gamification.mediPoints = uint96(patient.gamification.mediPoints.add(core.pointsForActions("appointment")));
    patient.lastActivityTimestamp = uint48(block.timestamp);
    core._levelUp(msg.sender);
    emit AppointmentBooked(newAppointmentId, msg.sender, _doctor, _timestamp, _videoCallLink);
}

function cancelAppointment(uint256 _appointmentId) external onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
    Appointment storage apt = appointments[_appointmentId];
    require(apt.patient == msg.sender, "Not your appointment");
    require(apt.status == AppointmentStatus.Pending || apt.status == AppointmentStatus.Confirmed, "Cannot cancel: invalid status");
    require(apt.scheduledTimestamp > block.timestamp.add(core.minCancellationBuffer()), "Too late to cancel");

    apt.status = AppointmentStatus.Cancelled;
    _removePendingAppointment(apt.doctor, _appointmentId);
    payments._refundPatient(apt.patient, apt.fee, apt.paymentType);
    emit AppointmentStatusUpdated(_appointmentId, "Cancelled");
}

function rescheduleAppointment(uint256 _appointmentId, uint48 _newTimestamp) external onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
    Appointment storage apt = appointments[_appointmentId];
    require(apt.patient == msg.sender, "Not your appointment");
    require(apt.status == AppointmentStatus.Pending || apt.status == AppointmentStatus.Confirmed, "Cannot reschedule: invalid status");
    require(_newTimestamp > block.timestamp.add(core.minBookingBuffer()), "New time too soon");

    apt.scheduledTimestamp = _newTimestamp;
    apt.status = AppointmentStatus.Rescheduled;
    emit AppointmentStatusUpdated(_appointmentId, "Rescheduled");
}

function requestAISymptomAnalysis(string calldata _symptoms) external onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
    core.decayPoints(msg.sender);
    TelemedicineCore.Patient storage patient = core.patients(msg.sender);
    bool isFree = patient.gamification.currentLevel == core.maxLevel() && block.timestamp >= patient.lastFreeAnalysisTimestamp.add(core.freeAnalysisPeriod());

    if (!isFree) {
        require(core.getAIFundBalance() >= core.aiAnalysisCost(), "Insufficient AI fund");
        core.aiAnalysisFund = core.aiAnalysisFund.sub(core.aiAnalysisCost());
    } else {
        patient.lastFreeAnalysisTimestamp = uint48(block.timestamp);
        emit DataRewardClaimed(msg.sender, 0);
    }

    aiAnalysisCounter = aiAnalysisCounter.add(1);
    aiAnalyses[aiAnalysisCounter] = AISymptomAnalysis(aiAnalysisCounter, msg.sender, false, _symptoms, "");
    patient.gamification.mediPoints = uint96(patient.gamification.mediPoints.add(core.pointsForActions("aiAnalysis")));
    patient.lastActivityTimestamp = uint48(block.timestamp);
    core._levelUp(msg.sender);
    emit AISymptomAnalyzed(aiAnalysisCounter, msg.sender);
    _monetizeData(msg.sender);
}

function claimDataReward() external onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
    TelemedicineCore.Patient storage patient = core.patients(msg.sender);
    require(patient.dataSharing == TelemedicineCore.DataSharingStatus.Enabled, "Data sharing not enabled");
    require(block.timestamp >= patient.lastRewardTimestamp.add(1 days), "Reward not yet available");
    require(payments.sonicToken().balanceOf(address(payments)) >= core.dataMonetizationReward(), "Insufficient SONIC balance");

    patient.lastRewardTimestamp = uint48(block.timestamp);
    require(payments.sonicToken().transfer(msg.sender, core.dataMonetizationReward()), "SONIC transfer failed");
    emit DataRewardClaimed(msg.sender, core.dataMonetizationReward());
}

function confirmAppointment(uint256 _appointmentId, bool _overridePriority) public onlyRole(core.DOCTOR_ROLE()) whenNotPaused {
    Appointment storage apt = appointments[_appointmentId];
    require(apt.doctor == msg.sender, "Not your appointment");
    require(apt.status == AppointmentStatus.Pending, "Appointment not pending");

    if (_overridePriority) {
        require(core.hasRole(core.ADMIN_ROLE(), msg.sender), "Override requires admin privileges");
    } else if (!apt.isPriority) {
        require(!_hasPendingPriorityAppointments(msg.sender), "Priority appointments pending");
    }

    apt.status = AppointmentStatus.Confirmed;
    _removePendingAppointment(msg.sender, _appointmentId);
    if (apt.isVideoCall) emit VideoCallStarted(_appointmentId, apt.videoCallLink);
    emit AppointmentStatusUpdated(_appointmentId, "Confirmed");
}

function confirmPriorityAppointments() external onlyRole(core.DOCTOR_ROLE()) whenNotPaused {
    PendingAppointments storage pending = doctorPendingAppointments[msg.sender];
    uint256 i = 0;
    while (i < pending.count) {
        uint256 id = pending.ids[i];
        Appointment storage apt = appointments[id];
        if (apt.status == AppointmentStatus.Pending && apt.isPriority) {
            apt.status = AppointmentStatus.Confirmed;
            if (apt.isVideoCall) emit VideoCallStarted(id, apt.videoCallLink);
            emit AppointmentStatusUpdated(id, "Confirmed");
            _removePendingAppointment(msg.sender, id);
        } else {
            i = i.add(1);
        }
    }
}

function batchConfirmAppointments(uint256[] calldata _appointmentIds) external onlyRole(core.DOCTOR_ROLE()) whenNotPaused {
    require(_appointmentIds.length <= core.MAX_PENDING_APPOINTMENTS(), "Exceeds max batch size");
    for (uint256 i = 0; i < _appointmentIds.length; i = i.add(1)) {
        Appointment storage apt = appointments[_appointmentIds[i]];
        require(apt.doctor == msg.sender, "Not your appointment");
        require(apt.status == AppointmentStatus.Pending, "Appointment not pending");
        apt.status = AppointmentStatus.Confirmed;
        _removePendingAppointment(msg.sender, _appointmentIds[i]);
        if (apt.isVideoCall) emit VideoCallStarted(_appointmentIds[i], apt.videoCallLink);
        emit AppointmentStatusUpdated(_appointmentIds[i], "Confirmed");
    }
    emit BatchAppointmentsConfirmed(msg.sender, _appointmentIds);
}

function completeAppointment(uint256 _appointmentId, string calldata _ipfsSummary) external onlyRole(core.DOCTOR_ROLE()) nonReentrant whenNotPaused {
    Appointment storage apt = appointments[_appointmentId];
    require(apt.doctor == msg.sender, "Not your appointment");
    require(apt.status == AppointmentStatus.Confirmed, "Appointment not confirmed");
    require(apt.scheduledTimestamp <= block.timestamp, "Appointment not yet started");

    uint256 doctorPayment = uint256(apt.fee).mul(DOCTOR_FEE_PERCENTAGE).div(PERCENTAGE_DENOMINATOR);

    if (apt.paymentType == TelemedicinePayments.PaymentType.ETH) {
        require(address(this).balance >= doctorPayment, "Insufficient ETH balance");
        (bool success, ) = apt.doctor.call{value: doctorPayment}("");
        require(success, "ETH payment to doctor failed");
    } else if (apt.paymentType == TelemedicinePayments.PaymentType.USDC) {
        require(payments.usdcToken().balanceOf(address(this)) >= doctorPayment, "Insufficient USDC balance");
        require(payments.usdcToken().transfer(apt.doctor, doctorPayment), "USDC payment to doctor failed");
    } else if (apt.paymentType == TelemedicinePayments.PaymentType.SONIC) {
        require(payments.sonicToken().balanceOf(address(this)) >= doctorPayment, "Insufficient SONIC balance");
        require(payments.sonicToken().transfer(apt.doctor, doctorPayment), "SONIC payment to doctor failed");
    }

    apt.status = AppointmentStatus.Completed;
    emit DoctorPaid(_appointmentId, apt.doctor, doctorPayment, apt.paymentType);
    emit AppointmentStatusUpdated(_appointmentId, "Completed");
    emit AppointmentCompleted(_appointmentId, _ipfsSummary);
}

function orderLabTest(address _patient, string calldata _testType) external onlyRole(core.DOCTOR_ROLE()) whenNotPaused {
    require(_patient != address(0), "Invalid patient address");
    require(core.patients(_patient).isRegistered, "Patient not registered");
    labTestCounter = labTestCounter.add(1);
    labTestOrders[labTestCounter] = LabTestOrder(labTestCounter, _patient, msg.sender, address(0), LabTestStatus.Requested, uint48(block.timestamp), 0, _testType, "", "");
    emit LabTestOrdered(labTestCounter, _patient, msg.sender, _testType, uint48(block.timestamp));
    _monetizeData(_patient);
}

function reviewLabResults(uint256 _labTestId, string calldata _medicationDetails, string calldata _prescriptionIpfsHash) external onlyRole(core.DOCTOR_ROLE()) whenNotPaused {
    LabTestOrder storage order = labTestOrders[_labTestId];
    require(order.doctor == msg.sender, "Not your order");
    require(order.status == LabTestStatus.ResultsUploaded, "Results not uploaded");

    order.status = LabTestStatus.Reviewed;
    order.completedTimestamp = uint48(block.timestamp);

    prescriptionCounter = prescriptionCounter.add(1);
    bytes32 verificationCodeHash = keccak256(abi.encodePacked(prescriptionCounter, msg.sender, block.timestamp));
    prescriptions[prescriptionCounter] = Prescription(
        prescriptionCounter,
        order.patient,
        msg.sender,
        verificationCodeHash,
        PrescriptionStatus.Generated,
        address(0),
        uint48(block.timestamp),
        uint48(block.timestamp.add(30 days)),
        _medicationDetails,
        _prescriptionIpfsHash
    );
    emit PrescriptionIssued(prescriptionCounter, order.patient, msg.sender, verificationCodeHash, uint48(block.timestamp));
    _monetizeData(order.patient);
}

function reviewAISymptomAnalysis(uint256 _aiAnalysisId, string calldata _analysisIpfsHash) external onlyRole(core.DOCTOR_ROLE()) whenNotPaused {
    AISymptomAnalysis storage analysis = aiAnalyses[_aiAnalysisId];
    require(!analysis.doctorReviewed, "Already reviewed");
    analysis.analysisIpfsHash = _analysisIpfsHash;
    analysis.doctorReviewed = true;
}

function collectSample(uint256 _labTestId, string calldata _ipfsHash) external onlyRole(core.LAB_TECH_ROLE()) whenNotPaused {
    LabTestOrder storage order = labTestOrders[_labTestId];
    require(order.status == LabTestStatus.Requested, "Invalid status");
    order.labTech = msg.sender;
    order.sampleCollectionIpfsHash = _ipfsHash;
    order.status = LabTestStatus.Collected;
    emit LabTestCollected(_labTestId, _ipfsHash);
}

function uploadLabResults(uint256 _labTestId, string calldata _resultsIpfsHash) external onlyRole(core.LAB_TECH_ROLE()) whenNotPaused {
    LabTestOrder storage order = labTestOrders[_labTestId];
    require(order.labTech == msg.sender, "Not your order");
    require(order.status == LabTestStatus.Collected, "Sample not collected");
    order.resultsIpfsHash = _resultsIpfsHash;
    order.status = LabTestStatus.ResultsUploaded;
    emit LabTestUploaded(_labTestId, _resultsIpfsHash);
    _monetizeData(order.patient);
}

function verifyPrescription(uint256 _prescriptionId, bytes32 _verificationCodeHash) external onlyRole(core.PHARMACY_ROLE()) whenNotPaused {
    Prescription storage prescription = prescriptions[_prescriptionId];
    require(prescription.status == PrescriptionStatus.Generated, "Invalid status");
    require(prescription.verificationCodeHash == _verificationCodeHash, "Invalid verification code");
    require(block.timestamp <= prescription.expirationTimestamp, "Prescription expired");
    prescription.status = PrescriptionStatus.Verified;
    prescription.pharmacy = msg.sender;
    emit PrescriptionVerified(_prescriptionId, msg.sender);
}

function fulfillPrescription(uint256 _prescriptionId) external onlyRole(core.PHARMACY_ROLE()) whenNotPaused {
    Prescription storage prescription = prescriptions[_prescriptionId];
    require(prescription.pharmacy == msg.sender, "Not your prescription");
    require(prescription.status == PrescriptionStatus.Verified, "Not verified");
    require(block.timestamp <= prescription.expirationTimestamp, "Prescription expired");
    prescription.status = PrescriptionStatus.Fulfilled;
    emit PrescriptionFulfilled(_prescriptionId);
}

function _monetizeData(address _patient) internal {
    TelemedicineCore.Patient storage patient = core.patients(_patient);
    if (patient.dataSharing == TelemedicineCore.DataSharingStatus.Enabled && block.timestamp >= patient.lastRewardTimestamp.add(1 days)) {
        uint256 reward = core.dataMonetizationReward();
        if (payments.sonicToken().balanceOf(address(payments)) >= reward) {
            patient.lastRewardTimestamp = uint48(block.timestamp);
            require(payments.sonicToken().transfer(_patient, reward), "SONIC transfer failed");
            emit DataRewardClaimed(_patient, reward);
        }
    }
}

function _addPendingAppointment(address _doctor, uint256 _appointmentId) internal {
    PendingAppointments storage pending = doctorPendingAppointments[_doctor];
    require(pending.count < core.MAX_PENDING_APPOINTMENTS(), "Max pending appointments reached");
    pending.appointmentIds[_appointmentId] = pending.count;
    pending.ids.push(_appointmentId);
    pending.count = pending.count.add(1);
}

function _removePendingAppointment(address _doctor, uint256 _appointmentId) internal {
    PendingAppointments storage pending = doctorPendingAppointments[_doctor];
    uint256 index = pending.appointmentIds[_appointmentId];
    require(index < pending.count, "Invalid appointment index");

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

function getPendingAppointments(address _doctor, uint256 _start, uint256 _limit) external view returns (uint256[] memory) {
    PendingAppointments storage pending = doctorPendingAppointments[_doctor];
    require(_start <= pending.count, "Start index out of bounds");
    uint256 end = _start.add(_limit) > pending.count ? pending.count : _start.add(_limit);
    uint256[] memory result = new uint256[](end.sub(_start));
    for (uint256 i = _start; i < end; i = i.add(1)) {
        result[i.sub(_start)] = pending.ids[i];
    }
    return result;
}

modifier onlyRole(bytes32 role) {
    require(core.hasRole(role, msg.sender), "Unauthorized");
    _;
}

modifier whenNotPaused() {
    require(!core.paused(), "Pausable: paused");
    _;
}

receive() external payable {}

}
