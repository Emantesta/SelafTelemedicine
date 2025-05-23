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
import {TelemedicineMedicalCore} from "./TelemedicineMedicalCore.sol";

/// @title TelemedicineMedicalServices
/// @notice Manages lab technician and pharmacy services, pricing, ratings, disputes, and data monetization
/// @dev UUPS upgradeable, integrates with TelemedicineCore, Payments, DisputeResolution, and MedicalCore
/// @dev Optimized for Sonic Blockchain. Prices in Sonic USDC (6 decimals); rewards in Sonic $S (18 decimals, validated in TelemedicinePayments).
contract TelemedicineMedicalServices is Initializable, UUPSUpgradeable, ReentrancyGuardUpgradeable {
    using SafeMathUpgradeable for uint256;
    using SafeERC20Upgradeable for IERC20Upgradeable;

    // Custom Errors
    error NotAuthorized();
    error ContractPaused();
    error PricingPaused();
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
    error InvalidMultiSigConfig();
    error ExternalCallFailed();
    error InvalidEvidenceHash();

    // Contract dependencies
    TelemedicineCore public core;
    TelemedicinePayments public payments;
    TelemedicineDisputeResolution public disputeResolution;
    TelemedicineMedicalCore public medicalCore;

    // Configuration Constants
    uint48 public constant RATING_WINDOW = 7 days;
    uint256 public constant MAX_RATING = 5;
    uint256 public maxBatchSize;
    uint256 public constant PERCENTAGE_DENOMINATOR = 100;
    uint256 public constant MAX_SIGNERS = 10;
    uint256 public constant MIN_IPFS_HASH_LENGTH = 46;
    uint48 public priceExpirationPeriod;
    uint256 public constant MIN_PRICE = 10_000; // 0.01 USDC (10^4 units, 6 decimals)
    uint256 public constant MAX_PRICE = 10_000_000_000; // 10,000 USDC (10^10 units, 6 decimals)
    bool public pricingPaused;

    // State Variables
    mapping(address => mapping(string => PriceEntry)) private labTechPrices;
    mapping(address => mapping(string => PriceEntry)) private pharmacyPrices;
    mapping(address => bytes32) private labTechPriceListIpfsHash;
    mapping(address => bytes32) private pharmacyPriceListIpfsHash;
    mapping(address => uint256) private labTechIndex;
    mapping(address => uint256) private pharmacyIndex;
    mapping(address => mapping(uint256 => Rating)) private labTestRatings;
    mapping(address => mapping(uint256 => Rating)) private prescriptionRatings;
    mapping(address => uint256) private labTechRatingSum;
    mapping(address => uint256) private pharmacyRatingSum;
    mapping(address => uint256) private labTechRatingCount;
    mapping(address => uint256) private pharmacyRatingCount;
    mapping(bytes32 => MultiSigOperation) private operations;

    address[] public labTechList;
    address[] public pharmacyList;
    address[] public multiSigSigners;
    uint256 public requiredSignatures;

    // Structs
    struct PriceEntry {
        uint192 price; // Price in Sonic USDC units (6 decimals)
        uint48 timestamp; // Packed with price (192 + 48 = 240 bits)
        bool active;
    }

    struct Rating {
        uint8 value; // Rating value (1-5)
        uint48 timestamp; // Packed with value (8 + 48 = 56 bits)
        bool exists;
    }

    struct MultiSigOperation {
        uint256 approvalCount;
        mapping(address => bool) approvals;
        address[] newSigners;
        uint256 newRequiredSignatures;
    }

    // Events
    event LabTechRegistered(address indexed labTech);
    event PharmacyRegistered(address indexed pharmacy);
    event LabTechPriceUpdated(address indexed labTech, string indexed testTypeIpfsHash, uint256 price, uint48 timestamp); // Price in USDC
    event PharmacyPriceUpdated(address indexed pharmacy, string indexed medicationIpfsHash, uint256 price, uint48 timestamp); // Price in USDC
    event LabTechPricesBatchUpdated(address indexed labTech, uint256 count);
    event PharmacyPricesBatchUpdated(address indexed pharmacy, uint256 count);
    event LabTestRated(uint256 indexed labTestId, address indexed patient, address indexed labTech, uint256 rating);
    event PrescriptionRated(uint256 indexed prescriptionId, address indexed patient, address indexed pharmacy, uint256 rating);
    event LabTestsBatchRated(address indexed patient, uint256 count);
    event PrescriptionsBatchRated(address indexed patient, uint256 count);
    event DisputeInitiated(uint256 indexed serviceId, string indexed serviceType, address indexed patient, address provider, string evidenceIpfsHash);
    event DisputeResolved(uint256 indexed serviceId, string indexed serviceType, TelemedicineMedicalCore.DisputeOutcome outcome);
    event DataRewardClaimed(address indexed patient, uint256 amount); // Amount in Sonic $S
    event MultiSigApproval(address indexed signer, bytes32 indexed operationHash);
    event MultiSigSignersUpdated(address[] newSigners, uint256 newRequiredSignatures);
    event PriceExpirationPeriodUpdated(uint48 newPeriod);
    event MaxBatchSizeUpdated(uint256 newSize);
    event PricingPaused(bool paused);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the medical services contract
    /// @param _core Address of the TelemedicineCore contract (Sonic-specific)
    /// @param _payments Address of the TelemedicinePayments contract (Sonic-specific, manages USDC and $S)
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
        if (_multiSigSigners.length < _requiredSignatures || _requiredSignatures == 0 ||
            _multiSigSigners.length > MAX_SIGNERS) revert InvalidMultiSigConfig();
        for (uint256 i = 0; i < _multiSigSigners.length; i++) {
            if (_multiSigSigners[i] == address(0)) revert InvalidAddress();
            for (uint256 j = i + 1; j < _multiSigSigners.length; j++) {
                if (_multiSigSigners[i] == _multiSigSigners[j]) revert InvalidMultiSigConfig();
            }
        }

        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        core = TelemedicineCore(_core);
        payments = TelemedicinePayments(_payments);
        disputeResolution = TelemedicineDisputeResolution(_disputeResolution);
        medicalCore = TelemedicineMedicalCore(_medicalCore);
        multiSigSigners = _multiSigSigners;
        requiredSignatures = _requiredSignatures;
        priceExpirationPeriod = 30 days;
        maxBatchSize = 50;
        pricingPaused = false;

        emit PriceExpirationPeriodUpdated(30 days);
        emit MaxBatchSizeUpdated(50);
        emit PricingPaused(false);
    }

    /// @notice Authorizes contract upgrades (admin only)
    function _authorizeUpgrade(address newImplementation) internal override onlyRole(core.ADMIN_ROLE()) {}

    // Provider Registration

    function registerLabTech() external nonReentrant whenNotPaused onlyRole(core.LAB_TECH_ROLE()) {
        if (labTechIndex[msg.sender] != 0 && labTechList[labTechIndex[msg.sender] - 1] == msg.sender) 
            revert AlreadyRegistered();
        labTechList.push(msg.sender);
        labTechIndex[msg.sender] = labTechList.length;
        emit LabTechRegistered(msg.sender);
    }

    function registerPharmacy() external nonReentrant whenNotPaused onlyRole(core.PHARMACY_ROLE()) {
        if (pharmacyIndex[msg.sender] != 0 && pharmacyList[pharmacyIndex[msg.sender] - 1] == msg.sender) 
            revert AlreadyRegistered();
        pharmacyList.push(msg.sender);
        pharmacyIndex[msg.sender] = pharmacyList.length;
        emit PharmacyRegistered(msg.sender);
    }

    // Pricing Functions

    modifier whenPricingNotPaused() {
        if (pricingPaused) revert PricingPaused();
        _;
    }

    /// @notice Updates the price for a lab test type
    /// @param _testTypeIpfsHash IPFS hash of the test type
    /// @param _price Price in Sonic USDC units (6 decimals)
    function updateLabTechPrice(string calldata _testTypeIpfsHash, uint256 _price) 
        external 
        onlyRole(core.LAB_TECH_ROLE()) 
        nonReentrant 
        whenNotPaused 
        whenPricingNotPaused 
    {
        if (labTechIndex[msg.sender] == 0) revert NotRegistered();
        if (bytes(_testTypeIpfsHash).length < MIN_IPFS_HASH_LENGTH) revert InvalidIpfsHash();
        if (_price < MIN_PRICE || _price > MAX_PRICE) revert InvalidPrice(); // Validates USDC price

        labTechPrices[msg.sender][_testTypeIpfsHash] = PriceEntry(uint192(_price), uint48(block.timestamp), true);
        emit LabTechPriceUpdated(msg.sender, _testTypeIpfsHash, _price, uint48(block.timestamp));
    }

    /// @notice Updates the price for a medication
    /// @param _medicationIpfsHash IPFS hash of the medication
    /// @param _price Price in Sonic USDC units (6 decimals)
    function updatePharmacyPrice(string calldata _medicationIpfsHash, uint256 _price) 
        external 
        onlyRole(core.PHARMACY_ROLE()) 
        nonReentrant 
        whenNotPaused 
        whenPricingNotPaused 
    {
        if (pharmacyIndex[msg.sender] == 0) revert NotRegistered();
        if (bytes(_medicationIpfsHash).length < MIN_IPFS_HASH_LENGTH) revert InvalidIpfsHash();
        if (_price < MIN_PRICE || _price > MAX_PRICE) revert InvalidPrice(); // Validates USDC price

        pharmacyPrices[msg.sender][_medicationIpfsHash] = PriceEntry(uint192(_price), uint48(block.timestamp), true);
        emit PharmacyPriceUpdated(msg.sender, _medicationIpfsHash, _price, uint48(block.timestamp));
    }

    /// @notice Batch updates prices for multiple lab test types
    /// @param _testTypeIpfsHashes Array of IPFS hashes
    /// @param _prices Array of prices in Sonic USDC units (6 decimals)
    function batchUpdateLabTechPrices(string[] calldata _testTypeIpfsHashes, uint256[] calldata _prices) 
        external 
        onlyRole(core.LAB_TECH_ROLE()) 
        nonReentrant 
        whenNotPaused 
        whenPricingNotPaused 
    {
        if (labTechIndex[msg.sender] == 0) revert NotRegistered();
        if (_testTypeIpfsHashes.length != _prices.length || _testTypeIpfsHashes.length > maxBatchSize) 
            revert InvalidPageSize();
        for (uint256 i = 0; i < _testTypeIpfsHashes.length; ) {
            if (bytes(_testTypeIpfsHashes[i]).length < MIN_IPFS_HASH_LENGTH) revert InvalidIpfsHash();
            if (_prices[i] < MIN_PRICE || _prices[i] > MAX_PRICE) revert InvalidPrice(); // Validates USDC price
            labTechPrices[msg.sender][_testTypeIpfsHashes[i]] = PriceEntry(uint192(_prices[i]), uint48(block.timestamp), true);
            emit LabTechPriceUpdated(msg.sender, _testTypeIpfsHashes[i], _prices[i], uint48(block.timestamp));
            unchecked { i++; }
        }
        emit LabTechPricesBatchUpdated(msg.sender, _testTypeIpfsHashes.length);
    }

    /// @notice Batch updates prices for multiple medications
    /// @param _medicationIpfsHashes Array of IPFS hashes
    /// @param _prices Array of prices in Sonic USDC units (6 decimals)
    function batchUpdatePharmacyPrices(string[] calldata _medicationIpfsHashes, uint256[] calldata _prices) 
        external 
        onlyRole(core.PHARMACY_ROLE()) 
        nonReentrant 
        whenNotPaused 
        whenPricingNotPaused 
    {
        if (pharmacyIndex[msg.sender] == 0) revert NotRegistered();
        if (_medicationIpfsHashes.length != _prices.length || _medicationIpfsHashes.length > maxBatchSize) 
            revert InvalidPageSize();
        for (uint256 i = 0; i < _medicationIpfsHashes.length; ) {
            if (bytes(_medicationIpfsHashes[i]).length < MIN_IPFS_HASH_LENGTH) revert InvalidIpfsHash();
            if (_prices[i] < MIN_PRICE || _prices[i] > MAX_PRICE) revert InvalidPrice(); // Validates USDC price
            pharmacyPrices[msg.sender][_medicationIpfsHashes[i]] = PriceEntry(uint192(_prices[i]), uint48(block.timestamp), true);
            emit PharmacyPriceUpdated(msg.sender, _medicationIpfsHashes[i], _prices[i], uint48(block.timestamp));
            unchecked { i++; }
        }
        emit PharmacyPricesBatchUpdated(msg.sender, _medicationIpfsHashes.length);
    }

    function updatePriceExpirationPeriod(uint48 _newPeriod) external onlyRole(core.ADMIN_ROLE()) {
        if (_newPeriod < 7 days) revert InvalidTimestamp();
        priceExpirationPeriod = _newPeriod;
        emit PriceExpirationPeriodUpdated(_newPeriod);
    }

    function updateMaxBatchSize(uint256 _newSize) external onlyRole(core.ADMIN_ROLE()) {
        if (_newSize < 1 || _newSize > 100) revert InvalidPageSize();
        maxBatchSize = _newSize;
        emit MaxBatchSizeUpdated(_newSize);
    }

    function togglePricingPause(bool _paused) external onlyRole(core.ADMIN_ROLE()) {
        pricingPaused = _paused;
        emit PricingPaused(_paused);
    }

    // Rating System

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

        labTestRatings[msg.sender][_labTestId] = Rating(uint8(_rating), uint48(block.timestamp), true);
        labTechRatingSum[order.labTech] = labTechRatingSum[order.labTech].add(_rating);
        labTechRatingCount[order.labTech] = labTechRatingCount[order.labTech].add(1);
        emit LabTestRated(_labTestId, msg.sender, order.labTech, _rating);
    }

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

        prescriptionRatings[msg.sender][_prescriptionId] = Rating(uint8(_rating), uint48(block.timestamp), true);
        pharmacyRatingSum[prescription.pharmacy] = pharmacyRatingSum[prescription.pharmacy].add(_rating);
        pharmacyRatingCount[prescription.pharmacy] = pharmacyRatingCount[prescription.pharmacy].add(1);
        emit PrescriptionRated(_prescriptionId, msg.sender, prescription.pharmacy, _rating);
    }

    function batchRateLabTests(uint256[] calldata _labTestIds, uint256[] calldata _ratings) 
        external 
        onlyRole(core.PATIENT_ROLE()) 
        nonReentrant 
        whenNotPaused 
    {
        if (_labTestIds.length != _ratings.length || _labTestIds.length > maxBatchSize) revert InvalidPageSize();
        mapping(uint256 => Rating) storage ratings = labTestRatings[msg.sender];
        uint256 count = _labTestIds.length;

        for (uint256 i = 0; i < count; ) {
            uint256 labTestId = _labTestIds[i];
            uint256 rating = _ratings[i];
            TelemedicineMedicalCore.LabTestOrder memory order = medicalCore.labTestOrders(labTestId);
            if (msg.sender != order.patient) revert NotAuthorized();
            if (order.status != TelemedicineMedicalCore.LabTestStatus.Reviewed) revert InvalidStatus();
            if (labTestId == 0 || labTestId > medicalCore.labTestCounter()) revert InvalidIndex();
            if (rating == 0 || rating > MAX_RATING) revert InvalidRating();
            if (block.timestamp > order.completedTimestamp + RATING_WINDOW) revert RatingWindowExpired();
            if (ratings[labTestId].exists) revert AlreadyRated();

            ratings[labTestId] = Rating(uint8(rating), uint48(block.timestamp), true);
            labTechRatingSum[order.labTech] = labTechRatingSum[order.labTech].add(rating);
            labTechRatingCount[order.labTech] = labTechRatingCount[order.labTech].add(1);
            emit LabTestRated(labTestId, msg.sender, order.labTech, rating);
            unchecked { i++; }
        }
        emit LabTestsBatchRated(msg.sender, count);
    }

    function batchRatePrescriptions(uint256[] calldata _prescriptionIds, uint256[] calldata _ratings) 
        external 
        onlyRole(core.PATIENT_ROLE()) 
        nonReentrant 
        whenNotPaused 
    {
        if (_prescriptionIds.length != _ratings.length || _prescriptionIds.length > maxBatchSize) revert InvalidPageSize();
        mapping(uint256 => Rating) storage ratings = prescriptionRatings[msg.sender];
        uint256 count = _prescriptionIds.length;

        for (uint256 i = 0; i < count; ) {
            uint256 prescriptionId = _prescriptionIds[i];
            uint256 rating = _ratings[i];
            TelemedicineMedicalCore.Prescription memory prescription = medicalCore.prescriptions(prescriptionId);
            if (msg.sender != prescription.patient) revert NotAuthorized();
            if (prescription.status != TelemedicineMedicalCore.PrescriptionStatus.Fulfilled) revert InvalidStatus();
            if (prescriptionId == 0 || prescriptionId > medicalCore.prescriptionCounter()) revert InvalidIndex();
            if (rating == 0 || rating > MAX_RATING) revert InvalidRating();
            if (block.timestamp > prescription.expirationTimestamp + RATING_WINDOW) revert RatingWindowExpired();
            if (ratings[prescriptionId].exists) revert AlreadyRated();

            ratings[prescriptionId] = Rating(uint8(rating), uint48(block.timestamp), true);
            pharmacyRatingSum[prescription.pharmacy] = pharmacyRatingSum[prescription.pharmacy].add(rating);
            pharmacyRatingCount[prescription.pharmacy] = pharmacyRatingCount[prescription.pharmacy].add(1);
            emit PrescriptionRated(prescriptionId, msg.sender, prescription.pharmacy, rating);
            unchecked { i++; }
        }
        emit PrescriptionsBatchRated(msg.sender, count);
    }

    // Dispute Resolution

    function initiateDispute(uint256 _serviceId, string calldata _serviceType, string calldata _evidenceIpfsHash) 
        external 
        onlyRole(core.PATIENT_ROLE()) 
        nonReentrant 
        whenNotPaused 
    {
        if (_serviceId == 0) revert InvalidIndex();
        if (disputeResolution.isDisputed(_serviceId)) revert DisputeWindowActive();
        if (bytes(_evidenceIpfsHash).length < MIN_IPFS_HASH_LENGTH) revert InvalidEvidenceHash();

        bytes32 serviceTypeHash = keccak256(abi.encodePacked(_serviceType));
        uint48 disputeWindow = core.disputeWindow();

        if (serviceTypeHash == keccak256(abi.encodePacked("Appointment"))) {
            if (_serviceId > medicalCore.appointmentCounter()) revert InvalidIndex();
            TelemedicineMedicalCore.Appointment memory apt = medicalCore.appointments(_serviceId);
            if (msg.sender != apt.patient) revert NotAuthorized();
            if (apt.status != TelemedicineMedicalCore.AppointmentStatus.Completed || 
                block.timestamp > apt.disputeWindowEnd) revert DisputeWindowActive();
            
            medicalCore.appointments(_serviceId).status = TelemedicineMedicalCore.AppointmentStatus.Disputed;
            try disputeResolution.initiateDispute(
                apt.doctors[0], 
                address(0), 
                address(0), 
                TelemedicineDisputeResolution.DisputeType.Misdiagnosis, 
                _serviceId,
                _serviceType,
                _evidenceIpfsHash
            ) {
                emit DisputeInitiated(_serviceId, _serviceType, apt.patient, apt.doctors[0], _evidenceIpfsHash);
            } catch {
                revert ExternalCallFailed();
            }
        } else if (serviceTypeHash == keccak256(abi.encodePacked("LabTest"))) {
            if (_serviceId > medicalCore.labTestCounter()) revert InvalidIndex();
            TelemedicineMedicalCore.LabTestOrder memory order = medicalCore.labTestOrders(_serviceId);
            if (msg.sender != order.patient) revert NotAuthorized();
            if (order.status != TelemedicineMedicalCore.LabTestStatus.Reviewed || 
                block.timestamp > order.disputeWindowEnd) revert DisputeWindowActive();
            
            medicalCore.labTestOrders(_serviceId).status = TelemedicineMedicalCore.LabTestStatus.Disputed;
            try disputeResolution.initiateDispute(
                address(0), 
                order.labTech, 
                address(0), 
                TelemedicineDisputeResolution.DisputeType.LabError, 
                _serviceId,
                _serviceType,
                _evidenceIpfsHash
            ) {
                emit DisputeInitiated(_serviceId, _serviceType, order.patient, order.labTech, _evidenceIpfsHash);
            } catch {
                revert ExternalCallFailed();
            }
        } else if (serviceTypeHash == keccak256(abi.encodePacked("Prescription"))) {
            if (_serviceId > medicalCore.prescriptionCounter()) revert InvalidIndex();
            TelemedicineMedicalCore.Prescription memory prescription = medicalCore.prescriptions(_serviceId);
            if (msg.sender != prescription.patient) revert NotAuthorized();
            if (prescription.status != TelemedicineMedicalCore.PrescriptionStatus.Fulfilled || 
                block.timestamp > prescription.disputeWindowEnd) revert DisputeWindowActive();
            
            medicalCore.prescriptions(_serviceId).status = TelemedicineMedicalCore.PrescriptionStatus.Disputed;
            try disputeResolution.initiateDispute(
                address(0), 
                address(0), 
                prescription.pharmacy, 
                TelemedicineDisputeResolution.DisputeType.PharmacyError, 
                _serviceId,
                _serviceType,
                _evidenceIpfsHash
            ) {
                emit DisputeInitiated(_serviceId, _serviceType, prescription.patient, prescription.pharmacy, _evidenceIpfsHash);
            } catch {
                revert ExternalCallFailed();
            }
        } else {
            revert InvalidStatus();
        }
    }

    // Data Monetization

    /// @notice Allows MedicalCore to trigger data reward claims
    /// @param _patient Address of the patient
    /// @param _amount Reward amount in Sonic $S units (18 decimals)
    /// @dev Queues payment via TelemedicinePayments; validation handled there
    function monetizeData(address _patient, uint256 _amount) external onlyMedicalCore {
        TelemedicineCore.Patient memory patient = core.patients(_patient);
        if (patient.dataSharing != TelemedicineCore.DataSharingStatus.Enabled) revert NotAuthorized();
        if (block.timestamp < patient.lastActivityTimestamp + 1 days) revert InvalidTimestamp();

        try payments.queuePayment(_patient, _amount, ITelemedicinePayments.PaymentType.SONIC) {
            emit DataRewardClaimed(_patient, _amount);
        } catch {
            revert ExternalCallFailed();
        }
    }

    /// @notice Allows patients to claim data monetization rewards
    /// @dev Queues payment via TelemedicinePayments; validation handled there
    function claimDataReward() external onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
        TelemedicineCore.Patient memory patient = core.patients(msg.sender);
        if (patient.dataSharing != TelemedicineCore.DataSharingStatus.Enabled) revert NotAuthorized();
        if (block.timestamp < patient.lastActivityTimestamp + 1 days) revert InvalidTimestamp();

        uint256 reward = core.dataMonetizationReward(); // In Sonic $S units
        try payments.queuePayment(msg.sender, reward, ITelemedicinePayments.PaymentType.SONIC) {
            emit DataRewardClaimed(msg.sender, reward);
        } catch {
            revert ExternalCallFailed();
        }
    }

    // Multi-Sig Functions

    function proposeMultiSigUpdate(address[] calldata _newSigners, uint256 _newRequiredSignatures) 
        external 
        onlyRole(core.ADMIN_ROLE()) 
    {
        if (_newSigners.length < _newRequiredSignatures || _newRequiredSignatures == 0 ||
            _newSigners.length > MAX_SIGNERS) revert InvalidMultiSigConfig();
        for (uint256 i = 0; i < _newSigners.length; i++) {
            if (_newSigners[i] == address(0)) revert InvalidAddress();
            for (uint256 j = i + 1; j < _newSigners.length; j++) {
                if (_newSigners[i] == _newSigners[j]) revert InvalidMultiSigConfig();
            }
        }

        bytes32 operationHash = keccak256(abi.encodePacked(_newSigners, _newRequiredSignatures, block.timestamp));
        MultiSigOperation storage operation = operations[operationHash];
        operation.newSigners = _newSigners;
        operation.newRequiredSignatures = _newRequiredSignatures;
        operation.approvals[msg.sender] = true;
        operation.approvalCount = 1;
        emit MultiSigApproval(msg.sender, operationHash);
    }

    function approveCriticalOperation(bytes32 _operationHash) external {
        bool isSigner = false;
        for (uint256 i = 0; i < multiSigSigners.length; ) {
            if (multiSigSigners[i] == msg.sender) {
                isSigner = true;
                break;
            }
            unchecked { i++; }
        }
        if (!isSigner) revert NotAuthorized();
        MultiSigOperation storage operation = operations[_operationHash];
        if (operation.approvals[msg.sender]) revert AlreadySigned();

        operation.approvals[msg.sender] = true;
        operation.approvalCount = operation.approvalCount.add(1);
        emit MultiSigApproval(msg.sender, _operationHash);

        if (operation.approvalCount >= requiredSignatures && operation.newSigners.length > 0) {
            multiSigSigners = operation.newSigners;
            requiredSignatures = operation.newRequiredSignatures;
            emit MultiSigSignersUpdated(operation.newSigners, operation.newRequiredSignatures);
            delete operations[_operationHash];
        }
    }

    function checkMultiSigApproval(bytes32 _operationHash) public view returns (bool) {
        return operations[_operationHash].approvalCount >= requiredSignatures;
    }

    // View Functions

    function isLabTechRegistered(address _labTech) external view returns (bool) {
        return labTechIndex[_labTech] != 0 && labTechList[labTechIndex[_labTech] - 1] == _labTech;
    }

    function isPharmacyRegistered(address _pharmacy) external view returns (bool) {
        return pharmacyIndex[_pharmacy] != 0 && pharmacyList[pharmacyIndex[_pharmacy] - 1] == _pharmacy;
    }

    function getPendingAppointments(address _doctor, uint256 _page, uint256 _pageSize) 
        external 
        view 
        returns (uint256[] memory appointmentIds, uint256 totalPages) 
    {
        if (_pageSize == 0 || _pageSize > maxBatchSize) revert InvalidPageSize();
        if (_doctor == address(0)) revert InvalidAddress();

        TelemedicineMedicalCore.PendingAppointments memory pending = medicalCore.doctorPendingAppointments(_doctor);
        totalPages = (pending.count + _pageSize - 1) / _pageSize;
        if (_page >= totalPages) return (new uint256[](0), totalPages);

        uint256 start = _page * _pageSize;
        uint256 end = start + _pageSize > pending.count ? pending.count : start + _pageSize;
        appointmentIds = new uint256[](end - start);

        for (uint256 i = start; i < end; ) {
            appointmentIds[i - start] = pending.ids[i];
            unchecked { i++; }
        }
    }

    function getLabTechs(uint256 _page, uint256 _pageSize) 
        external 
        view 
        returns (address[] memory labTechs, uint256 totalPages) 
    {
        if (_pageSize == 0 || _pageSize > maxBatchSize) revert InvalidPageSize();
        totalPages = (labTechList.length + _pageSize - 1) / _pageSize;
        if (_page >= totalPages) return (new address[](0), totalPages);

        uint256 start = _page * _pageSize;
        uint256 end = start + _pageSize > labTechList.length ? labTechList.length : start + _pageSize;
        labTechs = new address[](end - start);

        for (uint256 i = start; i < end; ) {
            labTechs[i - start] = labTechList[i];
            unchecked { i++; }
        }
    }

    function getPharmacies(uint256 _page, uint256 _pageSize) 
        external 
        view 
        returns (address[] memory pharmacies, uint256 totalPages) 
    {
        if (_pageSize == 0 || _pageSize > maxBatchSize) revert InvalidPageSize();
        totalPages = (pharmacyList.length + _pageSize - 1) / _pageSize;
        if (_page >= totalPages) return (new address[](0), totalPages);

        uint256 start = _page * _pageSize;
        uint256 end = start + _pageSize > pharmacyList.length ? pharmacyList.length : start + _pageSize;
        pharmacies = new address[](end - start);

        for (uint256 i = start; i < end; ) {
            pharmacies[i - start] = pharmacyList[i];
            unchecked { i++; }
        }
    }

    /// @notice Retrieves the price for a lab test type
    /// @param _labTech Address of the lab technician
    /// @param _testTypeIpfsHash IPFS hash of the test type
    /// @return price Price in Sonic USDC units (6 decimals), isValid Whether the price is still valid
    function getLabTechPrice(address _labTech, string calldata _testTypeIpfsHash) 
        external 
        view 
        returns (uint256 price, bool isValid) 
    {
        if (_labTech == address(0)) revert InvalidAddress();
        if (bytes(_testTypeIpfsHash).length < MIN_IPFS_HASH_LENGTH) revert InvalidIpfsHash();
        PriceEntry storage entry = labTechPrices[_labTech][_testTypeIpfsHash];
        if (entry.price > 0 && block.timestamp <= entry.timestamp + priceExpirationPeriod && entry.active) {
            return (entry.price, true);
        }
        return (0, false);
    }

    /// @notice Retrieves the price for a medication
    /// @param _pharmacy Address of the pharmacy
    /// @param _medicationIpfsHash IPFS hash of the medication
    /// @return price Price in Sonic USDC units (6 decimals), isValid Whether the price is still valid
    function getPharmacyPrice(address _pharmacy, string calldata _medicationIpfsHash) 
        external 
        view 
        returns (uint256 price, bool isValid) 
    {
        if (_pharmacy == address(0)) revert InvalidAddress();
        if (bytes(_medicationIpfsHash).length < MIN_IPFS_HASH_LENGTH) revert InvalidIpfsHash();
        PriceEntry storage entry = pharmacyPrices[_pharmacy][_medicationIpfsHash];
        if (entry.price > 0 && block.timestamp <= entry.timestamp + priceExpirationPeriod && entry.active) {
            return (entry.price, true);
        }
        return (0, false);
    }

    function getLabTestDetails(uint256 _labTestId) 
        external 
        view 
        returns (
            TelemedicineMedicalCore.LabTestStatus status,
            uint48 orderedTimestamp,
            uint48 completedTimestamp,
            uint256 patientCost, // Cost in Sonic USDC
            TelemedicineMedicalCore.DisputeOutcome disputeOutcome
        ) 
    {
        TelemedicineMedicalCore.LabTestOrder memory order = medicalCore.labTestOrders(_labTestId);
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

    function getPrescriptionDetails(uint256 _prescriptionId) 
        external 
        view 
        returns (
            TelemedicineMedicalCore.PrescriptionStatus status,
            uint48 generatedTimestamp,
            uint48 expirationTimestamp,
            uint256 patientCost, // Cost in Sonic USDC
            TelemedicineMedicalCore.DisputeOutcome disputeOutcome
        ) 
    {
        TelemedicineMedicalCore.Prescription memory prescription = medicalCore.prescriptions(_prescriptionId);
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

    function notifyDisputeResolved(
        uint256 _serviceId, 
        string memory _serviceType, 
        TelemedicineMedicalCore.DisputeOutcome _outcome
    ) external onlyMedicalCore {
        if (_serviceId == 0) revert InvalidIndex();
        
        bytes32 serviceTypeHash = keccak256(abi.encodePacked(_serviceType));
        if (serviceTypeHash == keccak256(abi.encodePacked("Appointment"))) {
            TelemedicineMedicalCore.Appointment storage apt = medicalCore.appointments(_serviceId);
            if (apt.status != TelemedicineMedicalCore.AppointmentStatus.Disputed) revert InvalidStatus();
            apt.disputeOutcome = _outcome;
            apt.status = TelemedicineMedicalCore.AppointmentStatus.Completed;
        } else if (serviceTypeHash == keccak256(abi.encodePacked("LabTest"))) {
            TelemedicineMedicalCore.LabTestOrder storage order = medicalCore.labTestOrders(_serviceId);
            if (order.status != TelemedicineMedicalCore.LabTestStatus.Disputed) revert InvalidStatus();
            order.disputeOutcome = _outcome;
            order.status = TelemedicineMedicalCore.LabTestStatus.Reviewed;
        } else if (serviceTypeHash == keccak256(abi.encodePacked("Prescription"))) {
            TelemedicineMedicalCore.Prescription storage prescription = medicalCore.prescriptions(_serviceId);
            if (prescription.status != TelemedicineMedicalCore.PrescriptionStatus.Disputed) revert InvalidStatus();
            prescription.disputeOutcome = _outcome;
            prescription.status = TelemedicineMedicalCore.PrescriptionStatus.Fulfilled;
        } else {
            revert InvalidStatus();
        }

        emit DisputeResolved(_serviceId, _serviceType, _outcome);
    }

    function notifyDataRewardClaimed(address _patient, uint256 _amount) external onlyMedicalCore {
        emit DataRewardClaimed(_patient, _amount);
    }

    // Modifiers

    modifier onlyRole(bytes32 role) {
        if (!core.hasRole(role, msg.sender)) revert NotAuthorized();
        _;
    }

    modifier whenNotPaused() {
        if (core.paused()) revert ContractPaused();
        _;
    }

    modifier onlyMedicalCore() {
        if (msg.sender != address(medicalCore)) revert NotAuthorized();
        _;
    }

    // Storage gap
    uint256[49] private __gap; // Increased to 49 after removing MIN_REWARD, MAX_REWARD
}
