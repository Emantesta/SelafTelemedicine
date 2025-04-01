// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {SafeMathUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";
import {TelemedicineCore} from "./TelemedicineCore.sol";
import {TelemedicinePayments} from "./TelemedicinePayments.sol";
import {TelemedicineDisputeResolution} from "./TelemedicineDisputeResolution.sol";
import {TelemedicineMedicalCore} from "./TelemedicineMedicalCore.sol";

contract TelemedicineMedicalServices is Initializable, ReentrancyGuardUpgradeable {
    using SafeMathUpgradeable for uint256;

    // Custom Errors
    error NotAuthorized();
    error ContractPaused();
    error InvalidAddress();
    error InvalidStatus();
    error InvalidTimestamp();
    error InsufficientFunds();
    error InvalidRating();
    error RatingWindowExpired();
    error AlreadyRated();
    error DisputeWindowActive();
    error InvalidPageSize();
    error InvalidIndex();
    error PriceExpired();
    error InvalidIpfsHash();
    error MultiSigNotApproved();
    error AlreadySigned();
    error AlreadyRegistered();
    error NotRegistered();
    error InvalidPrice();

    // Contract dependencies
    TelemedicineCore public core;
    TelemedicinePayments public payments;
    TelemedicineDisputeResolution public disputeResolution;
    TelemedicineMedicalCore public medicalCore;

    // Configuration Constants
    uint48 public constant DISPUTE_WINDOW = 24 hours;
    uint48 public constant RATING_WINDOW = 7 days;
    uint256 public constant MAX_RATING = 5;
    uint256 public constant MAX_BATCH_SIZE = 50;
    uint256 public constant PERCENTAGE_DENOMINATOR = 100;

    // State Variables
    mapping(address => mapping(string => PriceEntry)) private labTechPrices;
    mapping(address => mapping(string => PriceEntry)) private pharmacyPrices;
    mapping(address => string) private labTechPriceListIpfsHash;
    mapping(address => string) private pharmacyPriceListIpfsHash;
    mapping(address => uint256) private labTechIndex;
    mapping(address => uint256) private pharmacyIndex;
    mapping(address => mapping(uint256 => Rating)) private labTestRatings;
    mapping(address => mapping(uint256 => Rating)) private prescriptionRatings;
    mapping(address => uint256) private labTechRatingSum;
    mapping(address => uint256) private pharmacyRatingSum;
    mapping(address => uint256) private labTechRatingCount;
    mapping(address => uint256) private pharmacyRatingCount;
    mapping(address => mapping(bytes32 => bool)) public multiSigApprovals;

    address[] public labTechList;
    address[] public pharmacyList;
    address[] public multiSigSigners;
    uint256 public requiredSignatures;

    // Structs
    struct PriceEntry {
        uint256 price;
        uint48 timestamp;
    }

    struct Rating {
        uint256 value;
        uint48 timestamp;
        bool exists;
    }

    // Events
    event LabTechRegistered(address indexed labTech);
    event PharmacyRegistered(address indexed pharmacy);
    event LabTechPriceUpdated(address indexed labTech, string testTypeIpfsHash, uint256 price, uint48 timestamp);
    event PharmacyPriceUpdated(address indexed pharmacy, string medicationIpfsHash, uint256 price, uint48 timestamp);
    event LabTestRated(uint256 indexed testId, address indexed patient, address indexed labTech, uint256 rating);
    event PrescriptionRated(uint256 indexed prescriptionId, address indexed patient, address indexed pharmacy, uint256 rating);
    event DisputeInitiated(uint256 indexed serviceId, string serviceType, address patient, address provider);
    event DisputeResolved(uint256 indexed serviceId, string serviceType, TelemedicineMedicalCore.DisputeOutcome outcome);
    event DataRewardClaimed(address indexed patient, uint256 amount);
    event MultiSigApproval(address indexed signer, bytes32 indexed operationHash);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the medical services contract with dependencies and multi-sig configuration
    /// @param _core Address of the TelemedicineCore contract
    /// @param _payments Address of the TelemedicinePayments contract
    /// @param _disputeResolution Address of the TelemedicineDisputeResolution contract
    /// @param _medicalCore Address of the TelemedicineMedicalCore contract
    /// @param _multiSigSigners Array of multi-sig signer addresses
    /// @param _requiredSignatures Number of required signatures for multi-sig approval
    function initialize(
        address _core,
        address _payments,
        address _disputeResolution,
        address _medicalCore,
        address[] memory _multiSigSigners,
        uint256 _requiredSignatures
    ) external initializer {
        if (_core == address(0) || _payments == address(0) || _disputeResolution == address(0) || 
            _medicalCore == address(0)) revert InvalidAddress();
        if (_multiSigSigners.length < _requiredSignatures || _requiredSignatures == 0) revert InvalidAddress();

        __ReentrancyGuard_init();
        core = TelemedicineCore(_core);
        payments = TelemedicinePayments(_payments);
        disputeResolution = TelemedicineDisputeResolution(_disputeResolution);
        medicalCore = TelemedicineMedicalCore(_medicalCore);
        multiSigSigners = _multiSigSigners;
        requiredSignatures = _requiredSignatures;
    }

    // Provider Registration

    /// @notice Registers a lab technician
    function registerLabTech() external nonReentrant whenNotPaused onlyRole(core.LAB_TECH_ROLE()) {
        if (labTechIndex[msg.sender] != 0 && labTechList[labTechIndex[msg.sender] - 1] == msg.sender) 
            revert AlreadyRegistered();
        labTechList.push(msg.sender);
        labTechIndex[msg.sender] = labTechList.length;
        emit LabTechRegistered(msg.sender);
    }

    /// @notice Registers a pharmacy
    function registerPharmacy() external nonReentrant whenNotPaused onlyRole(core.PHARMACY_ROLE()) {
        if (pharmacyIndex[msg.sender] != 0 && pharmacyList[pharmacyIndex[msg.sender] - 1] == msg.sender) 
            revert AlreadyRegistered();
        pharmacyList.push(msg.sender);
        pharmacyIndex[msg.sender] = pharmacyList.length;
        emit PharmacyRegistered(msg.sender);
    }

    // Pricing Functions

    /// @notice Updates the price for a lab test type
    /// @param _testTypeIpfsHash IPFS hash of the test type
    /// @param _price Price in wei
    function updateLabTechPrice(string calldata _testTypeIpfsHash, uint256 _price) 
        external 
        onlyRole(core.LAB_TECH_ROLE()) 
        nonReentrant 
        whenNotPaused 
    {
        if (labTechIndex[msg.sender] == 0) revert NotRegistered();
        if (bytes(_testTypeIpfsHash).length == 0) revert InvalidIpfsHash();
        if (_price == 0) revert InvalidPrice();

        labTechPrices[msg.sender][_testTypeIpfsHash] = PriceEntry(_price, uint48(block.timestamp));
        emit LabTechPriceUpdated(msg.sender, _testTypeIpfsHash, _price, uint48(block.timestamp));
    }

    /// @notice Updates the price for a medication
    /// @param _medicationIpfsHash IPFS hash of the medication
    /// @param _price Price in wei
    function updatePharmacyPrice(string calldata _medicationIpfsHash, uint256 _price) 
        external 
        onlyRole(core.PHARMACY_ROLE()) 
        nonReentrant 
        whenNotPaused 
    {
        if (pharmacyIndex[msg.sender] == 0) revert NotRegistered();
        if (bytes(_medicationIpfsHash).length == 0) revert InvalidIpfsHash();
        if (_price == 0) revert InvalidPrice();

        pharmacyPrices[msg.sender][_medicationIpfsHash] = PriceEntry(_price, uint48(block.timestamp));
        emit PharmacyPriceUpdated(msg.sender, _medicationIpfsHash, _price, uint48(block.timestamp));
    }

    // Rating System

    /// @notice Rates a completed lab test
    /// @param _labTestId ID of the lab test
    /// @param _rating Rating value (1 to MAX_RATING)
    function rateLabTest(uint256 _labTestId, uint256 _rating) 
        external 
        onlyRole(core.PATIENT_ROLE()) 
        nonReentrant 
        whenNotPaused 
    {
        TelemedicineMedicalCore.LabTestOrder memory order = medicalCore.labTestOrders(_labTestId);
        if (msg.sender != order.patient) revert NotAuthorized();
        if (order.status != TelemedicineMedicalCore.LabTestStatus.Reviewed) revert InvalidStatus();
        if (_labTestId == 0 || _labTestId > medicalCore.labTestCounter()) revert InvalidIndex();
        if (_rating == 0 || _rating > MAX_RATING) revert InvalidRating();
        if (block.timestamp > order.completedTimestamp + RATING_WINDOW) revert RatingWindowExpired();
        if (labTestRatings[msg.sender][_labTestId].exists) revert AlreadyRated();

        labTestRatings[msg.sender][_labTestId] = Rating(_rating, uint48(block.timestamp), true);
        labTechRatingSum[order.labTech] = labTechRatingSum[order.labTech].add(_rating);
        labTechRatingCount[order.labTech] = labTechRatingCount[order.labTech].add(1);
        emit LabTestRated(_labTestId, msg.sender, order.labTech, _rating);
    }

    /// @notice Rates a fulfilled prescription
    /// @param _prescriptionId ID of the prescription
    /// @param _rating Rating value (1 to MAX_RATING)
    function ratePrescription(uint256 _prescriptionId, uint256 _rating) 
        external 
        onlyRole(core.PATIENT_ROLE()) 
        nonReentrant 
        whenNotPaused 
    {
        TelemedicineMedicalCore.Prescription memory prescription = medicalCore.prescriptions(_prescriptionId);
        if (msg.sender != prescription.patient) revert NotAuthorized();
        if (prescription.status != TelemedicineMedicalCore.PrescriptionStatus.Fulfilled) revert InvalidStatus();
        if (_prescriptionId == 0 || _prescriptionId > medicalCore.prescriptionCounter()) revert InvalidIndex();
        if (_rating == 0 || _rating > MAX_RATING) revert InvalidRating();
        if (block.timestamp > prescription.expirationTimestamp + RATING_WINDOW) revert RatingWindowExpired();
        if (prescriptionRatings[msg.sender][_prescriptionId].exists) revert AlreadyRated();

        prescriptionRatings[msg.sender][_prescriptionId] = Rating(_rating, uint48(block.timestamp), true);
        pharmacyRatingSum[prescription.pharmacy] = pharmacyRatingSum[prescription.pharmacy].add(_rating);
        pharmacyRatingCount[prescription.pharmacy] = pharmacyRatingCount[prescription.pharmacy].add(1);
        emit PrescriptionRated(_prescriptionId, msg.sender, prescription.pharmacy, _rating);
    }

    // Dispute Resolution

    /// @notice Initiates a dispute for a medical service (appointment, lab test, or prescription)
    /// @param _serviceId ID of the service to dispute
    /// @param _serviceType Type of service ("Appointment", "LabTest", or "Prescription")
    function initiateDispute(uint256 _serviceId, string calldata _serviceType) 
        external 
        onlyRole(core.PATIENT_ROLE()) 
        nonReentrant 
        whenNotPaused 
    {
        if (_serviceId == 0) revert InvalidIndex();
        if (disputeResolution.isDisputed(_serviceId)) revert DisputeWindowActive();

        if (keccak256(abi.encodePacked(_serviceType)) == keccak256(abi.encodePacked("Appointment"))) {
            if (_serviceId > medicalCore.appointmentCounter()) revert InvalidIndex();
            TelemedicineMedicalCore.Appointment memory apt = medicalCore.appointments(_serviceId);
            if (msg.sender != apt.patient) revert NotAuthorized();
            if (apt.status != TelemedicineMedicalCore.AppointmentStatus.Completed || 
                block.timestamp > apt.disputeWindowEnd) revert DisputeWindowActive();
            
            medicalCore.appointments(_serviceId).status = TelemedicineMedicalCore.AppointmentStatus.Disputed;
            disputeResolution.initiateDispute(
                apt.doctors[0], 
                address(0), 
                address(0), 
                TelemedicineDisputeResolution.DisputeType.Misdiagnosis, 
                _serviceId
            );
            emit DisputeInitiated(_serviceId, "Appointment", apt.patient, apt.doctors[0]);
        } 
        else if (keccak256(abi.encodePacked(_serviceType)) == keccak256(abi.encodePacked("LabTest"))) {
            if (_serviceId > medicalCore.labTestCounter()) revert InvalidIndex();
            TelemedicineMedicalCore.LabTestOrder memory order = medicalCore.labTestOrders(_serviceId);
            if (msg.sender != order.patient) revert NotAuthorized();
            if (order.status != TelemedicineMedicalCore.LabTestStatus.Reviewed || 
                block.timestamp > order.disputeWindowEnd) revert DisputeWindowActive();
            
            medicalCore.labTestOrders(_serviceId).status = TelemedicineMedicalCore.LabTestStatus.Disputed;
            disputeResolution.initiateDispute(
                address(0), 
                order.labTech, 
                address(0), 
                TelemedicineDisputeResolution.DisputeType.LabError, 
                _serviceId
            );
            emit DisputeInitiated(_serviceId, "LabTest", order.patient, order.labTech);
        } 
        else if (keccak256(abi.encodePacked(_serviceType)) == keccak256(abi.encodePacked("Prescription"))) {
            if (_serviceId > medicalCore.prescriptionCounter()) revert InvalidIndex();
            TelemedicineMedicalCore.Prescription memory prescription = medicalCore.prescriptions(_serviceId);
            if (msg.sender != prescription.patient) revert NotAuthorized();
            if (prescription.status != TelemedicineMedicalCore.PrescriptionStatus.Fulfilled || 
                block.timestamp > prescription.disputeWindowEnd) revert DisputeWindowActive();
            
            medicalCore.prescriptions(_serviceId).status = TelemedicineMedicalCore.PrescriptionStatus.Disputed;
            disputeResolution.initiateDispute(
                address(0), 
                address(0), 
                prescription.pharmacy, 
                TelemedicineDisputeResolution.DisputeType.PharmacyError, 
                _serviceId
            );
            emit DisputeInitiated(_serviceId, "Prescription", prescription.patient, prescription.pharmacy);
        } 
        else {
            revert InvalidStatus();
        }
    }

    // Data Monetization

    /// @notice Allows MedicalCore to trigger data reward claims
    /// @param _patient Address of the patient claiming the reward
    function monetizeData(address _patient) external onlyMedicalCore {
        TelemedicineCore.Patient storage patient = core.patients(_patient);
        if (patient.dataSharing == TelemedicineCore.DataSharingStatus.Enabled && 
            block.timestamp >= patient.lastRewardTimestamp.add(1 days)) {
            uint256 reward = core.dataMonetizationReward();
            if (payments.sonicToken().balanceOf(address(payments)) >= reward) {
                patient.lastRewardTimestamp = uint48(block.timestamp);
                if (!payments.sonicToken().transfer(_patient, reward)) revert("SONIC transfer failed");
                emit DataRewardClaimed(_patient, reward);
            }
        }
    }

    /// @notice Allows patients to claim data monetization rewards
    function claimDataReward() external onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
        TelemedicineCore.Patient storage patient = core.patients(msg.sender);
        if (patient.dataSharing != TelemedicineCore.DataSharingStatus.Enabled) revert NotAuthorized();
        if (block.timestamp < patient.lastRewardTimestamp.add(1 days)) revert InvalidTimestamp();
        if (payments.sonicToken().balanceOf(address(payments)) < core.dataMonetizationReward()) revert InsufficientFunds();

        patient.lastRewardTimestamp = uint48(block.timestamp);
        if (!payments.sonicToken().transfer(msg.sender, core.dataMonetizationReward())) revert("SONIC transfer failed");
        emit DataRewardClaimed(msg.sender, core.dataMonetizationReward());
    }

    // Multi-sig Functions

    /// @notice Approves a critical operation with multi-sig
    /// @param _operationHash Hash of the operation to approve
    function approveCriticalOperation(bytes32 _operationHash) external {
        bool isSigner = false;
        for (uint256 i = 0; i < multiSigSigners.length; i++) {
            if (multiSigSigners[i] == msg.sender) {
                isSigner = true;
                break;
            }
        }
        if (!isSigner) revert NotAuthorized();
        if (multiSigApprovals[msg.sender][_operationHash]) revert AlreadySigned();

        multiSigApprovals[msg.sender][_operationHash] = true;
        emit MultiSigApproval(msg.sender, _operationHash);
    }

    /// @notice Checks if an operation has enough multi-sig approvals
    /// @param _operationHash Hash of the operation to check
    /// @return True if the required number of signatures is met
    function checkMultiSigApproval(bytes32 _operationHash) public view returns (bool) {
        uint256 approvalCount = 0;
        for (uint256 i = 0; i < multiSigSigners.length; i++) {
            if (multiSigApprovals[multiSigSigners[i]][_operationHash]) {
                approvalCount = approvalCount.add(1);
            }
        }
        return approvalCount >= requiredSignatures;
    }

    // View Functions

    /// @notice Checks if a lab technician is registered
    /// @param _labTech Address of the lab technician
    /// @return True if registered
    function isLabTechRegistered(address _labTech) external view returns (bool) {
        return labTechIndex[_labTech] != 0 && labTechList[labTechIndex[_labTech] - 1] == _labTech;
    }

    /// @notice Checks if a pharmacy is registered
    /// @param _pharmacy Address of the pharmacy
    /// @return True if registered
    function isPharmacyRegistered(address _pharmacy) external view returns (bool) {
        return pharmacyIndex[_pharmacy] != 0 && pharmacyList[pharmacyIndex[_pharmacy] - 1] == _pharmacy;
    }

    /// @notice Retrieves pending appointments for a doctor
    /// @param _doctor Address of the doctor
    /// @param _page Page number
    /// @param _pageSize Size of each page
    /// @return appointmentIds Array of appointment IDs, totalPages Total number of pages
    function getPendingAppointments(address _doctor, uint256 _page, uint256 _pageSize) 
        external 
        view 
        returns (uint256[] memory appointmentIds, uint256 totalPages) 
    {
        if (_pageSize == 0 || _pageSize > MAX_BATCH_SIZE) revert InvalidPageSize();
        if (_doctor == address(0)) revert InvalidAddress();

        TelemedicineMedicalCore.PendingAppointments storage pending = medicalCore.doctorPendingAppointments(_doctor);
        totalPages = (pending.count + _pageSize - 1) / _pageSize;
        if (_page >= totalPages) return (new uint256[](0), totalPages);

        uint256 start = _page * _pageSize;
        uint256 end = (start + _pageSize > pending.count) ? pending.count : start + _pageSize;
        appointmentIds = new uint256[](end - start);

        for (uint256 i = start; i < end; i = i.add(1)) {
            appointmentIds[i - start] = pending.ids[i];
        }
    }

    /// @notice Retrieves a paginated list of lab technicians
    /// @param _page Page number
    /// @param _pageSize Size of each page
    /// @return labTechs Array of lab tech addresses, totalPages Total number of pages
    function getLabTechs(uint256 _page, uint256 _pageSize) 
        external 
        view 
        returns (address[] memory labTechs, uint256 totalPages) 
    {
        if (_pageSize == 0 || _pageSize > MAX_BATCH_SIZE) revert InvalidPageSize();
        totalPages = (labTechList.length + _pageSize - 1) / _pageSize;
        if (_page >= totalPages) return (new address[](0), totalPages);

        uint256 start = _page * _pageSize;
        uint256 end = (start + _pageSize > labTechList.length) ? labTechList.length : start + _pageSize;
        labTechs = new address[](end - start);

        for (uint256 i = start; i < end; i = i.add(1)) {
            labTechs[i - start] = labTechList[i];
        }
    }

    /// @notice Retrieves a paginated list of pharmacies
    /// @param _page Page number
    /// @param _pageSize Size of each page
    /// @return pharmacies Array of pharmacy addresses, totalPages Total number of pages
    function getPharmacies(uint256 _page, uint256 _pageSize) 
        external 
        view 
        returns (address[] memory pharmacies, uint256 totalPages) 
    {
        if (_pageSize == 0 || _pageSize > MAX_BATCH_SIZE) revert InvalidPageSize();
        totalPages = (pharmacyList.length + _pageSize - 1) / _pageSize;
        if (_page >= totalPages) return (new address[](0), totalPages);

        uint256 start = _page * _pageSize;
        uint256 end = (start + _pageSize > pharmacyList.length) ? pharmacyList.length : start + _pageSize;
        pharmacies = new address[](end - start);

        for (uint256 i = start; i < end; i = i.add(1)) {
            pharmacies[i - start] = pharmacyList[i];
        }
    }

    /// @notice Retrieves the price for a lab test type
    /// @param _labTech Address of the lab technician
    /// @param _testTypeIpfsHash IPFS hash of the test type
    /// @return price Price in wei, isValid Whether the price is still valid
    function getLabTechPrice(address _labTech, string calldata _testTypeIpfsHash) 
        external 
        view 
        returns (uint256 price, bool isValid) 
    {
        if (_labTech == address(0)) revert InvalidAddress();
        if (bytes(_testTypeIpfsHash).length == 0) revert InvalidIpfsHash();
        PriceEntry storage entry = labTechPrices[_labTech][_testTypeIpfsHash];
        if (entry.price > 0 && block.timestamp <= entry.timestamp + 30 days) {
            return (entry.price, true);
        }
        return (0, false);
    }

    /// @notice Retrieves the price for a medication
    /// @param _pharmacy Address of the pharmacy
    /// @param _medicationIpfsHash IPFS hash of the medication
    /// @return price Price in wei, isValid Whether the price is still valid
    function getPharmacyPrice(address _pharmacy, string calldata _medicationIpfsHash) 
        external 
        view 
        returns (uint256 price, bool isValid) 
    {
        if (_pharmacy == address(0)) revert InvalidAddress();
        if (bytes(_medicationIpfsHash).length == 0) revert InvalidIpfsHash();
        PriceEntry storage entry = pharmacyPrices[_pharmacy][_medicationIpfsHash];
        if (entry.price > 0 && block.timestamp <= entry.timestamp + 30 days) {
            return (entry.price, true);
        }
        return (0, false);
    }

    /// @notice Retrieves details of a lab test order
    /// @param _labTestId ID of the lab test
    /// @return status, orderedTimestamp, completedTimestamp, patientCost, disputeOutcome
    function getLabTestDetails(uint256 _labTestId) 
        external 
        view 
        returns (
            TelemedicineMedicalCore.LabTestStatus status,
            uint48 orderedTimestamp,
            uint48 completedTimestamp,
            uint256 patientCost,
            TelemedicineMedicalCore.DisputeOutcome disputeOutcome
        ) 
    {
        TelemedicineMedicalCore.LabTestOrder storage order = medicalCore.labTestOrders(_labTestId);
        bool isAuthorized = msg.sender == order.patient || 
                           msg.sender == order.doctor || 
                           msg.sender == order.labTech || 
                           core.hasRole(core.ADMIN_ROLE(), msg.sender);
        if (!isAuthorized) revert NotAuthorized();
        if (_labTestId == 0 || _labTestId > medicalCore.labTestCounter()) revert InvalidIndex();

        return (
            order.status,
            order.orderedTimestamp,
            order.completedTimestamp,
            order.patientCost,
            order.disputeOutcome
        );
    }

    /// @notice Retrieves details of a prescription
    /// @param _prescriptionId ID of the prescription
    /// @return status, generatedTimestamp, expirationTimestamp, patientCost, disputeOutcome
    function getPrescriptionDetails(uint256 _prescriptionId) 
        external 
        view 
        returns (
            TelemedicineMedicalCore.PrescriptionStatus status,
            uint48 generatedTimestamp,
            uint48 expirationTimestamp,
            uint256 patientCost,
            TelemedicineMedicalCore.DisputeOutcome disputeOutcome
        ) 
    {
        TelemedicineMedicalCore.Prescription storage prescription = medicalCore.prescriptions(_prescriptionId);
        bool isAuthorized = msg.sender == prescription.patient || 
                           msg.sender == prescription.doctor || 
                           msg.sender == prescription.pharmacy || 
                           core.hasRole(core.ADMIN_ROLE(), msg.sender);
        if (!isAuthorized) revert NotAuthorized();
        if (_prescriptionId == 0 || _prescriptionId > medicalCore.prescriptionCounter()) revert InvalidIndex();

        return (
            prescription.status,
            prescription.generatedTimestamp,
            prescription.expirationTimestamp,
            prescription.patientCost,
            prescription.disputeOutcome
        );
    }

    /// @notice Retrieves the average rating and count for a lab technician
    /// @param _labTech Address of the lab technician
    /// @return averageRating Average rating, ratingCount Number of ratings
    function getLabTechRating(address _labTech) 
        external 
        view 
        returns (uint256 averageRating, uint256 ratingCount) 
    {
        if (_labTech == address(0)) revert InvalidAddress();
        ratingCount = labTechRatingCount[_labTech];
        if (ratingCount == 0) return (0, 0);
        averageRating = labTechRatingSum[_labTech].div(ratingCount);
    }

    /// @notice Retrieves the average rating and count for a pharmacy
    /// @param _pharmacy Address of the pharmacy
    /// @return averageRating Average rating, ratingCount Number of ratings
    function getPharmacyRating(address _pharmacy) 
        external 
        view 
        returns (uint256 averageRating, uint256 ratingCount) 
    {
        if (_pharmacy == address(0)) revert InvalidAddress();
        ratingCount = pharmacyRatingCount[_pharmacy];
        if (ratingCount == 0) return (0, 0);
        averageRating = pharmacyRatingSum[_pharmacy].div(ratingCount);
    }

    // Callback Functions

    /// @notice Notifies and updates the contract when a dispute is resolved
    /// @param _serviceId ID of the service
    /// @param _serviceType Type of service ("Appointment", "LabTest", or "Prescription")
    /// @param _outcome Outcome of the dispute
    function notifyDisputeResolved(
        uint256 _serviceId, 
        string memory _serviceType, 
        TelemedicineMedicalCore.DisputeOutcome _outcome
    ) external onlyMedicalCore {
        if (_serviceId == 0) revert InvalidIndex();
        
        if (keccak256(abi.encodePacked(_serviceType)) == keccak256(abi.encodePacked("Appointment"))) {
            TelemedicineMedicalCore.Appointment storage apt = medicalCore.appointments(_serviceId);
            if (apt.status != TelemedicineMedicalCore.AppointmentStatus.Disputed) revert InvalidStatus();
            apt.disputeOutcome = _outcome;
            apt.status = TelemedicineMedicalCore.AppointmentStatus.Completed; // Revert to Completed post-resolution
        } 
        else if (keccak256(abi.encodePacked(_serviceType)) == keccak256(abi.encodePacked("LabTest"))) {
            TelemedicineMedicalCore.LabTestOrder storage order = medicalCore.labTestOrders(_serviceId);
            if (order.status != TelemedicineMedicalCore.LabTestStatus.Disputed) revert InvalidStatus();
            order.disputeOutcome = _outcome;
            order.status = TelemedicineMedicalCore.LabTestStatus.Reviewed; // Revert to Reviewed post-resolution
        } 
        else if (keccak256(abi.encodePacked(_serviceType)) == keccak256(abi.encodePacked("Prescription"))) {
            TelemedicineMedicalCore.Prescription storage prescription = medicalCore.prescriptions(_serviceId);
            if (prescription.status != TelemedicineMedicalCore.PrescriptionStatus.Disputed) revert InvalidStatus();
            prescription.disputeOutcome = _outcome;
            prescription.status = TelemedicineMedicalCore.PrescriptionStatus.Fulfilled; // Revert to Fulfilled post-resolution
        } 
        else {
            revert InvalidStatus();
        }

        emit DisputeResolved(_serviceId, _serviceType, _outcome);
    }

    /// @notice Notifies the contract of a data reward claim
    /// @param _patient Address of the patient
    /// @param _amount Amount of the reward
    function notifyDataRewardClaimed(address _patient, uint256 _amount) external onlyMedicalCore {
        emit DataRewardClaimed(_patient, _amount);
    }

    // Modifiers

    /// @notice Restricts access to a specific role
    /// @param role The role required to call the function
    modifier onlyRole(bytes32 role) {
        if (!core.hasRole(role, msg.sender)) revert NotAuthorized();
        _;
    }

    /// @notice Ensures the contract is not paused
    modifier whenNotPaused() {
        if (core.paused()) revert ContractPaused();
        _;
    }

    /// @notice Restricts access to the TelemedicineMedicalCore contract
    modifier onlyMedicalCore() {
        if (msg.sender != address(medicalCore)) revert NotAuthorized();
        _;
    }
}
