// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import {SafeMathUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";
import {ChainlinkClient, Chainlink} from "@chainlink/contracts/src/v0.8/ChainlinkClient.sol";
import {LinkTokenInterface} from "@chainlink/contracts/src/v0.8/interfaces/LinkTokenInterface.sol";

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
    using Chainlink for Chainlink.Request;

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
    error InvalidPercentage();

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

    // Constants
    uint256 public constant MAX_ADMINS = 10;

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
    address[] public multiSigSigners;
    uint256 public requiredSignatures;

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

    // Enums
    enum DataSharingStatus { Disabled, Enabled }
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
        minReserveBalance = 1 ether;
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

    // Fallback
    receive() external payable {
        emit ReserveFundDeposited(msg.sender, msg.value);
        reserveFund = reserveFund.add(msg.value);
        _checkMinBalance();
    }
}
