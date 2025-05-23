// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import {ChainlinkClient, Chainlink} from "@chainlink/contracts/src/v0.8/ChainlinkClient.sol";
import {LinkTokenInterface} from "@chainlink/contracts/src/v0.8/interfaces/LinkTokenInterface.sol";

interface IERC20Upgradeable {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title TelemedicinePayments Interface
/// @notice Handles payment processing, refunds, $S reward validation, and cancellation of pending payments
interface ITelemedicinePayments {
    enum PaymentType { ETH, USDC, SONIC }
    function _processPayment(PaymentType paymentType, uint256 amount) external payable;
    function _refundPatient(address patient, uint256 amount, PaymentType paymentType) external;
    function usdcToken() external view returns (IERC20Upgradeable);
    function sonicToken() external view returns (IERC20Upgradeable);
    function sonicNativeToken() external view returns (IERC20Upgradeable);
    function queuePayment(address recipient, uint256 amount, PaymentType paymentType) external;
    function getRewardBounds() external view returns (uint256 minReward, uint256 maxReward);
    function cancelPendingPayment(address recipient, uint256 paymentId) external returns (bool);
}

/// @title TelemedicineDisputeResolution Interface
/// @notice Manages dispute status and outcomes for medical services
interface TelemedicineDisputeResolution {
    function isDisputed(uint256 id) external view returns (bool);
    function getDisputeOutcome(uint256 id) external view returns (DisputeOutcome);
}

/// @title TelemedicineMedicalServices Interface
/// @notice Manages lab tech and pharmacy registration, locality-based searches, and data monetization
interface TelemedicineMedicalServices {
    function hasLabTechInLocality(string calldata locality) external view returns (bool);
    function hasPharmacyInLocality(string calldata locality) external view returns (bool);
    function registerLabTech(address labTech) external;
    function registerPharmacy(address pharmacy) external;
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

/// @title TelemedicineCore
/// @notice Core contract for the telemedicine platform on Sonic Blockchain
/// @dev UUPS upgradeable, integrates with Chainlink, and manages roles, patients, and gamification
/// @dev $S reward validation is centralized in ITelemedicinePayments via queuePayment
contract TelemedicineCore is Initializable, UUPSUpgradeable, AccessControlUpgradeable, ReentrancyGuardUpgradeable, PausableUpgradeable, ChainlinkClient {
    using Chainlink for Chainlink.Request;

    // Roles
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant DOCTOR_ROLE = keccak256("DOCTOR_ROLE");
    bytes32 public constant PATIENT_ROLE = keccak256("PATIENT_ROLE");
    bytes32 public constant LAB_TECH_ROLE = keccak256("LAB_TECH_ROLE");
    bytes32 public constant PHARMACY_ROLE = keccak256("PHARMACY_ROLE");

    // Configuration Variables with Validation Ranges
    uint256 public minBookingBuffer; // Minimum: 5 minutes
    uint256 public minCancellationBuffer; // Minimum: 30 minutes
    uint256 public verificationTimeout; // Minimum: 1 day, Maximum: 30 days
    uint256 public dataMonetizationReward; // Minimum: 1e18
    uint256 public aiAnalysisCost; // Minimum: 0.001 ether
    uint256 public pointsPerLevel; // Minimum: 10
    uint8 public maxLevel; // Maximum: 50
    uint256 public decayRate; // Maximum: 50%
    uint256 public decayPeriod; // Minimum: 7 days
    uint256 public freeAnalysisPeriod; // Minimum: 7 days
    uint256 public minReserveBalance; // Minimum: 0.1 ether
    uint256 public versionNumber;
    uint256 public doctorFeePercentage; // 0-100%
    uint256 public reserveFundPercentage; // 0-100%
    uint256 public platformFeePercentage; // 0-100%
    uint256 public constant PERCENTAGE_DENOMINATOR = 100;
    uint48 public disputeWindow; // Minimum: 1 day
    uint256 public maxBatchSize; // Minimum: 10
    uint256 public cancellationFeePercentage; // 0-100%
    uint48 public reminderInterval; // Minimum: 1 hour
    uint48 public paymentConfirmationDeadline; // Minimum: 1 day
    uint48 public invitationExpirationPeriod; // Minimum: 7 days
    uint256 public maxDoctorsPerAppointment; // Minimum: 1, Maximum: 5

    // Chainlink Configuration
    address public chainlinkOracle;
    bytes32 public priceListJobId;
    uint256 public chainlinkFee; // Minimum: 0.01 ether
    LinkTokenInterface public linkToken;

    // Constants
    uint256 public constant MAX_ADMINS = 10;
    uint256 public constant MIN_LINK_BALANCE = 1 ether;

    // State Variables
    mapping(address => Patient) public patients;
    mapping(address => Doctor) public doctors;
    mapping(address => LabTechnician) public labTechnicians;
    mapping(address => Pharmacy) public pharmacies;
    mapping(uint8 => uint256) public discountLevels;
    mapping(string => uint256) public pointsForActions;
    address[] public admins;
    uint256 public aiAnalysisFund;
    uint256 public reserveFundETH; // Tracks ETH reserve fund
    uint256 public reserveFundUSDC; // Tracks USDC reserve fund
    uint256 public reserveFundSONIC; // Tracks SONIC reserve fund
    mapping(bytes32 => uint256) public chainlinkRequestToPrice;
    mapping(address => mapping(uint256 => PendingPayment)) public pendingPayments; // recipient => paymentId => PendingPayment
    uint256 public nextPaymentId; // Tracks next available payment ID

    // Structs
    struct Patient {
        bool isRegistered;
        bytes32 medicalHistoryHash;
        GamificationData gamification;
        DataSharingStatus dataSharing;
        uint48 registrationTimestamp;
        uint48 lastActivityTimestamp;
        uint48 lastFreeAnalysisTimestamp;
        uint48 lastRewardTimestamp;
        bytes32 encryptedSymmetricKeyHash;
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

    struct PendingPayment {
        uint256 amount;
        ITelemedicinePayments.PaymentType paymentType;
        uint48 queuedTimestamp;
        bool isActive;
    }

    // Enums
    enum DataSharingStatus { Disabled, Enabled }
    enum DisputeOutcome { Unresolved, PatientFavored, ProviderFavored, MutualAgreement }

    enum ConfigParameter {
        DoctorFeePercentage,
        ReserveFundPercentage,
        PlatformFeePercentage,
        DisputeWindow,
        MaxBatchSize,
        CancellationFeePercentage,
        ReminderInterval,
        PaymentConfirmationDeadline,
        InvitationExpirationPeriod,
        MaxDoctorsPerAppointment,
        ChainlinkFee,
        MinBookingBuffer,
        MinCancellationBuffer,
        VerificationTimeout,
        DataMonetizationReward,
        AIAnalysisCost,
        PointsPerLevel,
        DecayRate,
        DecayPeriod,
        FreeAnalysisPeriod,
        MinReserveBalance
    }

    // External Contracts
    ITelemedicinePayments public payments;
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
    event ReserveFundDeposited(address indexed sender, uint256 amount, ITelemedicinePayments.PaymentType paymentType);
    event MinBalanceAlert(address indexed contractAddress, uint256 balance, ITelemedicinePayments.PaymentType paymentType);
    event AuditLog(uint256 indexed timestamp, address indexed actor, string action);
    event DisputeResolutionUpdated(address indexed oldAddress, address indexed newAddress);
    event ConfigurationUpdated(ConfigParameter parameter, uint256 value);
    event ChainlinkPriceReceived(bytes32 requestId, uint256 price);
    event ReserveFundUpdated(ITelemedicinePayments.PaymentType paymentType, uint256 newBalance);
    event DataRewardClaimed(address indexed patient, uint256 reward, uint256 paymentId);
    event PendingPaymentCanceled(address indexed recipient, uint256 paymentId);

    // Custom Errors
    error TelemedicineCore__InvalidAddress();
    error TelemedicineCore__InvalidStatus();
    error TelemedicineCore__InvalidTimestamp();
    error TelemedicineCore__InsufficientFunds();
    error TelemedicineCore__InvalidPercentage();
    error TelemedicineCore__NotAuthorized();
    error TelemedicineCore__ContractPaused();
    error TelemedicineCore__InvalidAdminCount();
    error TelemedicineCore__UnknownParameter();
    error TelemedicineCore__InvalidMultiSigConfig();
    error TelemedicineCore__InvalidParameterValue();
    error TelemedicineCore__InsufficientLinkBalance();
    error TelemedicineCore__TokenTransferFailed();
    error TelemedicineCore__InvalidRewardAmount();
    error TelemedicineCore__InvalidPaymentId();
    error TelemedicineCore__PaymentNotActive();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the contract with initial admins and external contract addresses
    function initialize(
        address[] memory _initialAdmins,
        address _payments,
        address _disputeResolution,
        address _services,
        address _chainlinkOracle,
        bytes32 _priceListJobId,
        address _linkToken
    ) external initializer {
        if (_initialAdmins.length < 2 || _initialAdmins.length > MAX_ADMINS) revert TelemedicineCore__InvalidAdminCount();
        if (_payments == address(0) || _disputeResolution == address(0) || _services == address(0) ||
            _chainlinkOracle == address(0) || _linkToken == address(0)) revert TelemedicineCore__InvalidAddress();

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

        _grantBatchRoles(ADMIN_ROLE, _initialAdmins);
        admins = _initialAdmins;

        minBookingBuffer = 15 minutes;
        minCancellationBuffer = 1 hours;
        verificationTimeout = 7 days;
        dataMonetizationReward = 10 * 10**18; // 10 $S
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
        nextPaymentId = 1; // Initialize payment ID counter

        discountLevels[3] = 5;
        discountLevels[5] = 10;
        pointsForActions["appointment"] = 20;
        pointsForActions["aiAnalysis"] = 10;

        payments = ITelemedicinePayments(_payments);
        disputeResolution = TelemedicineDisputeResolution(_disputeResolution);
        services = TelemedicineMedicalServices(_services);
        chainlinkOracle = _chainlinkOracle;
        priceListJobId = _priceListJobId;
        linkToken = LinkTokenInterface(_linkToken);
        chainlinkFee = 0.1 ether;

        _validatePercentages();
        emit AuditLog(block.timestamp, msg.sender, "Contract Initialized");
    }

    /// @notice Authorizes contract upgrades (admin only)
    function _authorizeUpgrade(address newImplementation) internal override onlyRole(ADMIN_ROLE) {
        versionNumber += 1;
        emit AuditLog(block.timestamp, msg.sender, "Contract Upgraded");
    }

    /// @notice Updates configuration parameters (admin only)
    function updateConfiguration(ConfigParameter _parameter, uint256 _value) external onlyRole(ADMIN_ROLE) {
        if (_parameter == ConfigParameter.DoctorFeePercentage) {
            if (_value > 100) revert TelemedicineCore__InvalidPercentage();
            doctorFeePercentage = _value;
            _validatePercentages();
        } else if (_parameter == ConfigParameter.ReserveFundPercentage) {
            if (_value > 100) revert TelemedicineCore__InvalidPercentage();
            reserveFundPercentage = _value;
            _validatePercentages();
        } else if (_parameter == ConfigParameter.PlatformFeePercentage) {
            if (_value > 100) revert TelemedicineCore__InvalidPercentage();
            platformFeePercentage = _value;
            _validatePercentages();
        } else if (_parameter == ConfigParameter.DisputeWindow) {
            if (_value < 1 days || _value > 30 days) revert TelemedicineCore__InvalidParameterValue();
            disputeWindow = uint48(_value);
        } else if (_parameter == ConfigParameter.MaxBatchSize) {
            if (_value < 10) revert TelemedicineCore__InvalidParameterValue();
            maxBatchSize = _value;
        } else if (_parameter == ConfigParameter.CancellationFeePercentage) {
            if (_value > 100) revert TelemedicineCore__InvalidPercentage();
            cancellationFeePercentage = _value;
        } else if (_parameter == ConfigParameter.ReminderInterval) {
            if (_value < 1 hours) revert TelemedicineCore__InvalidParameterValue();
            reminderInterval = uint48(_value);
        } else if (_parameter == ConfigParameter.PaymentConfirmationDeadline) {
            if (_value < 1 days) revert TelemedicineCore__InvalidParameterValue();
            paymentConfirmationDeadline = uint48(_value);
        } else if (_parameter == ConfigParameter.InvitationExpirationPeriod) {
            if (_value < 7 days) revert TelemedicineCore__InvalidParameterValue();
            invitationExpirationPeriod = uint48(_value);
        } else if (_parameter == ConfigParameter.MaxDoctorsPerAppointment) {
            if (_value < 1 || _value > 5) revert TelemedicineCore__InvalidParameterValue();
            maxDoctorsPerAppointment = _value;
        } else if (_parameter == ConfigParameter.ChainlinkFee) {
            if (_value < 0.01 ether) revert TelemedicineCore__InvalidParameterValue();
            chainlinkFee = _value;
        } else if (_parameter == ConfigParameter.MinBookingBuffer) {
            if (_value < 5 minutes) revert TelemedicineCore__InvalidParameterValue();
            minBookingBuffer = _value;
        } else if (_parameter == ConfigParameter.MinCancellationBuffer) {
            if (_value < 30 minutes) revert TelemedicineCore__InvalidParameterValue();
            minCancellationBuffer = _value;
        } else if (_parameter == ConfigParameter.VerificationTimeout) {
            if (_value < 1 days || _value > 30 days) revert TelemedicineCore__InvalidParameterValue();
            verificationTimeout = _value;
        } else if (_parameter == ConfigParameter.DataMonetizationReward) {
            if (_value < 1e18) revert TelemedicineCore__InvalidParameterValue();
            dataMonetizationReward = _value;
        } else if (_parameter == ConfigParameter.AIAnalysisCost) {
            if (_value < 0.001 ether) revert TelemedicineCore__InvalidParameterValue();
            aiAnalysisCost = _value;
        } else if (_parameter == ConfigParameter.PointsPerLevel) {
            if (_value < 10) revert TelemedicineCore__InvalidParameterValue();
            pointsPerLevel = _value;
        } else if (_parameter == ConfigParameter.DecayRate) {
            if (_value > 50) revert TelemedicineCore__InvalidParameterValue();
            decayRate = _value;
        } else if (_parameter == ConfigParameter.DecayPeriod) {
            if (_value < 7 days) revert TelemedicineCore__InvalidParameterValue();
            decayPeriod = _value;
        } else if (_parameter == ConfigParameter.FreeAnalysisPeriod) {
            if (_value < 7 days) revert TelemedicineCore__InvalidParameterValue();
            freeAnalysisPeriod = _value;
        } else if (_parameter == ConfigParameter.MinReserveBalance) {
            if (_value < 0.1 ether) revert TelemedicineCore__InvalidParameterValue();
            minReserveBalance = _value;
        } else {
            revert TelemedicineCore__UnknownParameter();
        }
        emit ConfigurationUpdated(_parameter, _value);
    }

    /// @notice Registers a new patient with a hash of the encrypted symmetric key
    function registerPatient(bytes32 _encryptedSymmetricKeyHash) external whenNotPaused {
        if (patients[msg.sender].isRegistered) revert TelemedicineCore__InvalidStatus();
        patients[msg.sender] = Patient(
            true,
            bytes32(0),
            GamificationData(0, 1),
            DataSharingStatus.Disabled,
            uint48(block.timestamp),
            uint48(block.timestamp),
            0,
            0,
            _encryptedSymmetricKeyHash
        );
        _grantRole(PATIENT_ROLE, msg.sender);
        emit PatientRegistered(msg.sender);
    }

    /// @notice Toggles data monetization for a patient
    function toggleDataMonetization(bool _enable) external onlyRole(PATIENT_ROLE) whenNotPaused {
        Patient storage patient = patients[msg.sender];
        if (!patient.isRegistered) revert TelemedicineCore__InvalidStatus();
        if (_enable && patient.dataSharing == DataSharingStatus.Disabled) {
            patient.dataSharing = DataSharingStatus.Enabled;
            patient.lastActivityTimestamp = uint48(block.timestamp);
            patient.lastRewardTimestamp = uint48(block.timestamp);
        } else if (!_enable && patient.dataSharing == DataSharingStatus.Enabled) {
            _claimDataReward(msg.sender);
            patient.dataSharing = DataSharingStatus.Disabled;
            patient.lastRewardTimestamp = 0;
        }
        emit DataMonetizationOptIn(msg.sender, _enable);
    }

    /// @notice Claims data monetization reward for a patient
    function claimDataReward() external onlyRole(PATIENT_ROLE) whenNotPaused {
        _claimDataReward(msg.sender);
    }

    /// @notice Decays patient points based on inactivity
    function decayPoints(address _patient) external whenNotPaused {
        if (!hasRole(PATIENT_ROLE, _patient)) revert TelemedicineCore__NotAuthorized();
        _decayPoints(_patient);
    }

    /// @notice Claims a free AI analysis for a patient
    function claimFreeAnalysis() external onlyRole(PATIENT_ROLE) whenNotPaused {
        Patient storage patient = patients[msg.sender];
        if (!patient.isRegistered) revert TelemedicineCore__InvalidStatus();
        if (block.timestamp < patient.lastFreeAnalysisTimestamp + freeAnalysisPeriod) revert TelemedicineCore__InvalidTimestamp();
        if (aiAnalysisFund < aiAnalysisCost) revert TelemedicineCore__InsufficientFunds();

        patient.lastFreeAnalysisTimestamp = uint48(block.timestamp);
        aiAnalysisFund -= aiAnalysisCost;
        emit FreeAnalysisClaimed(msg.sender);
    }

    /// @notice Verifies a doctor (admin only)
    function verifyDoctor(address _doctor, string calldata _licenseNumber, uint256 _fee) external onlyRole(ADMIN_ROLE) {
        if (_doctor == address(0)) revert TelemedicineCore__InvalidAddress();
        if (_fee > type(uint96).max) revert TelemedicineCore__InsufficientFunds();
        doctors[_doctor] = Doctor(true, uint96(_fee), _licenseNumber);
        _grantRole(DOCTOR_ROLE, _doctor);
        emit DoctorVerified(_doctor);
    }

    /// @notice Verifies a lab technician (admin only)
    function verifyLabTechnician(address _labTech, string calldata _licenseNumber) external onlyRole(ADMIN_ROLE) {
        if (_labTech == address(0)) revert TelemedicineCore__InvalidAddress();
        labTechnicians[_labTech] = LabTechnician(true, _licenseNumber);
        _grantRole(LAB_TECH_ROLE, _labTech);
        services.registerLabTech(_labTech);
        emit LabTechnicianVerified(_labTech);
    }

    /// @notice Registers a pharmacy (admin only)
    function registerPharmacy(address _pharmacy, string calldata _licenseNumber) external onlyRole(ADMIN_ROLE) {
        if (_pharmacy == address(0)) revert TelemedicineCore__InvalidAddress();
        pharmacies[_pharmacy] = Pharmacy(true, _licenseNumber);
        _grantRole(PHARMACY_ROLE, _pharmacy);
        services.registerPharmacy(_pharmacy);
        emit PharmacyRegistered(_pharmacy);
    }

    /// @notice Deposits funds into the AI analysis fund (admin only)
    function depositAIFund() external payable onlyRole(ADMIN_ROLE) {
        if (msg.value == 0) revert TelemedicineCore__InsufficientFunds();
        aiAnalysisFund += msg.value;
        emit AIFundDeposited(msg.sender, msg.value);
    }

    /// @notice Deposits funds into the reserve fund for a specific payment type (admin only)
    function depositReserveFund(ITelemedicinePayments.PaymentType _paymentType) external payable onlyRole(ADMIN_ROLE) {
        if (_paymentType == ITelemedicinePayments.PaymentType.ETH) {
            if (msg.value == 0) revert TelemedicineCore__InsufficientFunds();
            reserveFundETH += msg.value;
            emit ReserveFundDeposited(msg.sender, msg.value, _paymentType);
            _checkMinBalance(_paymentType);
        } else {
            IERC20Upgradeable token;
            uint256 amount;
            if (_paymentType == ITelemedicinePayments.PaymentType.USDC) {
                token = payments.usdcToken();
                amount = token.balanceOf(msg.sender);
                if (amount == 0) revert TelemedicineCore__InsufficientFunds();
                try token.transferFrom(msg.sender, address(this), amount) returns (bool success) {
                    if (!success) revert TelemedicineCore__TokenTransferFailed();
                    reserveFundUSDC += amount;
                } catch {
                    revert TelemedicineCore__TokenTransferFailed();
                }
            } else if (_paymentType == ITelemedicinePayments.PaymentType.SONIC) {
                token = payments.sonicNativeToken();
                amount = token.balanceOf(msg.sender);
                if (amount == 0) revert TelemedicineCore__InsufficientFunds();
                try token.transferFrom(msg.sender, address(this), amount) returns (bool success) {
                    if (!success) revert TelemedicineCore__TokenTransferFailed();
                    reserveFundSONIC += amount;
                } catch {
                    revert TelemedicineCore__TokenTransferFailed();
                }
            } else {
                revert TelemedicineCore__InvalidStatus();
            }
            emit ReserveFundDeposited(msg.sender, amount, _paymentType);
            _checkMinBalance(_paymentType);
        }
    }

    /// @notice Updates the reserve fund balance for a specific payment type (payments only)
    function updateReserveFund(ITelemedicinePayments.PaymentType _paymentType, uint256 _amount) external {
        if (msg.sender != address(payments)) revert TelemedicineCore__NotAuthorized();
        if (_paymentType == ITelemedicinePayments.PaymentType.ETH) {
            reserveFundETH = _amount;
        } else if (_paymentType == ITelemedicinePayments.PaymentType.USDC) {
            reserveFundUSDC = _amount;
        } else if (_paymentType == ITelemedicinePayments.PaymentType.SONIC) {
            reserveFundSONIC = _amount;
        } else {
            revert TelemedicineCore__InvalidStatus();
        }
        _checkMinBalance(_paymentType);
        emit ReserveFundUpdated(_paymentType, _amount);
    }

    /// @notice Batch updates reserve fund balances for multiple payment types (payments only)
    /// @dev Optimized for gas by minimizing storage writes and reusing variables
    function batchUpdateReserveFund(ITelemedicinePayments.PaymentType[] calldata _paymentTypes, uint256[] calldata _amounts) external {
        if (msg.sender != address(payments)) revert TelemedicineCore__NotAuthorized();
        uint256 length = _paymentTypes.length;
        if (length != _amounts.length || length > maxBatchSize) revert TelemedicineCore__InvalidParameterValue();

        // Cache storage variables to reduce SLOADs
        uint256 ethBalance = reserveFundETH;
        uint256 usdcBalance = reserveFundUSDC;
        uint256 sonicBalance = reserveFundSONIC;

        for (uint256 i = 0; i < length; ++i) {
            ITelemedicinePayments.PaymentType paymentType = _paymentTypes[i];
            uint256 amount = _amounts[i];
            if (paymentType == ITelemedicinePayments.PaymentType.ETH) {
                ethBalance = amount;
            } else if (paymentType == ITelemedicinePayments.PaymentType.USDC) {
                usdcBalance = amount;
            } else if (paymentType == ITelemedicinePayments.PaymentType.SONIC) {
                sonicBalance = amount;
            } else {
                revert TelemedicineCore__InvalidStatus();
            }
            // Defer balance check to reduce redundant calls
        }

        // Batch storage writes
        reserveFundETH = ethBalance;
        reserveFundUSDC = usdcBalance;
        reserveFundSONIC = sonicBalance;

        // Batch balance checks
        if (ethBalance < minReserveBalance) {
            emit MinBalanceAlert(address(this), ethBalance, ITelemedicinePayments.PaymentType.ETH);
        }
        if (usdcBalance < minReserveBalance) {
            emit MinBalanceAlert(address(this), usdcBalance, ITelemedicinePayments.PaymentType.USDC);
        }
        if (sonicBalance < minReserveBalance) {
            emit MinBalanceAlert(address(this), sonicBalance, ITelemedicinePayments.PaymentType.SONIC);
        }

        // Emit single event for batch update
        emit AuditLog(block.timestamp, msg.sender, "Batch Reserve Fund Updated");
    }

    /// @notice Updates the dispute resolution contract (admin only)
    function setDisputeResolution(address _disputeResolution) external onlyRole(ADMIN_ROLE) {
        if (_disputeResolution == address(0)) revert TelemedicineCore__InvalidAddress();
        address oldAddress = address(disputeResolution);
        disputeResolution = TelemedicineDisputeResolution(_disputeResolution);
        emit DisputeResolutionUpdated(oldAddress, _disputeResolution);
    }

    /// @notice Pauses the contract (admin only)
    function pause() external onlyRole(ADMIN_ROLE) {
        _pause();
        emit AuditLog(block.timestamp, msg.sender, "Contract Paused");
    }

    /// @notice Unpauses the contract (admin only)
    function unpause() external onlyRole(ADMIN_ROLE) {
        _unpause();
        emit AuditLog(block.timestamp, msg.sender, "Contract Unpaused");
    }

    /// @notice Requests a price feed from Chainlink oracle (admin only)
    function requestPriceFeed(string calldata _serviceId) external onlyRole(ADMIN_ROLE) returns (bytes32) {
        if (linkToken.balanceOf(address(this)) < MIN_LINK_BALANCE) revert TelemedicineCore__InsufficientLinkBalance();

        Chainlink.Request memory request = buildChainlinkRequest(
            priceListJobId,
            address(this),
            this.fulfill.selector
        );
        request.add("serviceId", _serviceId);
        request.add("field", "price");
        bytes32 requestId = sendChainlinkRequestTo(chainlinkOracle, request, chainlinkFee);
        return requestId;
    }

    /// @notice Handles Chainlink oracle response
    function fulfill(bytes32 _requestId, uint256 _price) public recordChainlinkFulfillment(_requestId) {
        chainlinkRequestToPrice[_requestId] = _price;
        emit ChainlinkPriceReceived(_requestId, _price);
    }

    /// @notice Grants roles to multiple accounts in a single transaction (admin only)
    function grantBatchRoles(bytes32 _role, address[] calldata _accounts) external onlyRole(ADMIN_ROLE) {
        if (_accounts.length > maxBatchSize) revert TelemedicineCore__InvalidParameterValue();
        _grantBatchRoles(_role, _accounts);
    }

    /// @notice Configures discount levels for patient tiers (admin only)
    function setDiscountLevel(uint8 _level, uint256 _discountPercentage) external onlyRole(ADMIN_ROLE) {
        if (_level == 0 || _level > maxLevel) revert TelemedicineCore__InvalidParameterValue();
        if (_discountPercentage > 100) revert TelemedicineCore__InvalidPercentage();
        discountLevels[_level] = _discountPercentage;
    }

    /// @notice Retrieves details of a pending payment for auditing
    /// @param _recipient The address of the payment recipient (e.g., patient)
    /// @param _paymentId The unique ID of the pending payment
    /// @return amount The payment amount
    /// @return paymentType The payment type (ETH, USDC, SONIC)
    /// @return queuedTimestamp When the payment was queued
    /// @return isActive Whether the payment is still active
    function getPendingPayment(address _recipient, uint256 _paymentId)
        external
        view
        returns (uint256 amount, ITelemedicinePayments.PaymentType paymentType, uint48 queuedTimestamp, bool isActive)
    {
        PendingPayment memory payment = pendingPayments[_recipient][_paymentId];
        if (!payment.isActive && payment.amount == 0) revert TelemedicineCore__InvalidPaymentId();
        return (payment.amount, payment.paymentType, payment.queuedTimestamp, payment.isActive);
    }

    /// @notice Cancels a pending reward payment (patient or admin only)
    /// @param _paymentId The unique ID of the pending payment
    function cancelPendingPayment(uint256 _paymentId) external whenNotPaused {
        if (!hasRole(PATIENT_ROLE, msg.sender) && !hasRole(ADMIN_ROLE, msg.sender)) revert TelemedicineCore__NotAuthorized();
        PendingPayment storage payment = pendingPayments[msg.sender][_paymentId];
        if (!payment.isActive) revert TelemedicineCore__PaymentNotActive();

        bool success = payments.cancelPendingPayment(msg.sender, _paymentId);
        if (!success) revert TelemedicineCore__InvalidPaymentId();

        payment.isActive = false;
        emit PendingPaymentCanceled(msg.sender, _paymentId);
    }

    // Internal Functions

    /// @notice Validates fee percentages sum to 100
    function _validatePercentages() private view {
        if (doctorFeePercentage + reserveFundPercentage + platformFeePercentage != PERCENTAGE_DENOMINATOR)
            revert TelemedicineCore__InvalidPercentage();
    }

    /// @notice Claims data monetization reward for a patient
    function _claimDataReward(address _patient) internal {
        Patient storage patient = patients[_patient];
        if (patient.dataSharing != DataSharingStatus.Enabled) revert TelemedicineCore__InvalidStatus();
        if (block.timestamp < patient.lastRewardTimestamp + 1 days) revert TelemedicineCore__InvalidTimestamp();

        uint256 timeElapsed = block.timestamp - patient.lastRewardTimestamp;
        uint256 reward = (timeElapsed * dataMonetizationReward) / 1 days;

        // Validate reward bounds
        (uint256 minReward, uint256 maxReward) = payments.getRewardBounds();
        if (reward < minReward || reward > maxReward) revert TelemedicineCore__InvalidRewardAmount();

        // Assign payment ID and store pending payment
        uint256 paymentId = nextPaymentId++;
        pendingPayments[_patient][paymentId] = PendingPayment({
            amount: reward,
            paymentType: ITelemedicinePayments.PaymentType.SONIC,
            queuedTimestamp: uint48(block.timestamp),
            isActive: true
        });

        // Queue reward payment
        try payments.queuePayment(_patient, reward, ITelemedicinePayments.PaymentType.SONIC) {
            patient.lastRewardTimestamp = uint48(block.timestamp);
            pendingPayments[_patient][paymentId].isActive = false; // Mark as processed
            uint256 newPoints = patient.gamification.mediPoints + reward;
            patient.gamification.mediPoints = uint96(newPoints > type(uint96).max ? type(uint96).max : newPoints);
            patient.lastActivityTimestamp = uint48(block.timestamp);
            _levelUp(_patient);
            services.notifyDataRewardClaimed(_patient, reward);
            emit DataRewardClaimed(_patient, reward, paymentId);
        } catch {
            // Keep payment pending for later cancellation
        }
    }

    /// @notice Decays patient points based on inactivity
    function _decayPoints(address _patient) internal {
        Patient storage patient = patients[_patient];
        if (!patient.isRegistered) revert TelemedicineCore__InvalidStatus();

        uint256 timeElapsed = block.timestamp - patient.lastActivityTimestamp;
        if (timeElapsed >= decayPeriod && patient.gamification.mediPoints > 0) {
            uint256 periods = timeElapsed / decayPeriod;
            uint256 decayedPoints = (patient.gamification.mediPoints * decayRate * periods) / 100;
            decayedPoints = decayedPoints > patient.gamification.mediPoints ? patient.gamification.mediPoints : decayedPoints;
            patient.gamification.mediPoints = uint96(patient.gamification.mediPoints - decayedPoints);
            patient.lastActivityTimestamp = uint48(block.timestamp);
            emit PointsDecayed(_patient, decayedPoints);
        }
    }

    /// @notice Applies a discount based on patient level
    function _applyFeeDiscount(address _patient, uint256 _baseFee) internal view returns (uint256) {
        uint8 level = patients[_patient].gamification.currentLevel;
        uint256 discountPercentage = discountLevels[level];
        if (discountPercentage == 0) return _baseFee;
        uint256 discount = (_baseFee * discountPercentage) / 100;
        return _baseFee - discount;
    }

    /// @notice Checks if a patient qualifies for priority booking
    function _isPriorityBooking(address _patient) internal view returns (bool) {
        return patients[_patient].gamification.currentLevel >= 5;
    }

    /// @notice Levels up a patient based on points
    function _levelUp(address _patient) internal {
        Patient storage patient = patients[_patient];
        GamificationData storage gamification = patient.gamification;
        uint256 pointsNeeded = uint256(gamification.currentLevel + 1) * pointsPerLevel;
        if (gamification.mediPoints >= pointsNeeded && gamification.currentLevel < maxLevel) {
            gamification.currentLevel += 1;
            emit LevelUp(_patient, gamification.currentLevel);
        }
    }

    /// @notice Checks if the reserve balance for a payment type is below the minimum
    function _checkMinBalance(ITelemedicinePayments.PaymentType _paymentType) internal {
        uint256 balance = getReserveFundBalance(_paymentType);
        if (balance < minReserveBalance) {
            emit MinBalanceAlert(address(this), balance, _paymentType);
        }
    }

    /// @notice Internal function to grant roles in batch
    function _grantBatchRoles(bytes32 _role, address[] memory _accounts) internal {
        for (uint256 i = 0; i < _accounts.length; i++) {
            if (_accounts[i] == address(0)) revert TelemedicineCore__InvalidAddress();
            _grantRole(_role, _accounts[i]);
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

    function getReserveFundBalance(ITelemedicinePayments.PaymentType _paymentType) public view returns (uint256) {
        if (_paymentType == ITelemedicinePayments.PaymentType.ETH) {
            return reserveFundETH;
        } else if (_paymentType == ITelemedicinePayments.PaymentType.USDC) {
            return reserveFundUSDC;
        } else if (_paymentType == ITelemedicinePayments.PaymentType.SONIC) {
            return reserveFundSONIC;
        }
        revert TelemedicineCore__InvalidStatus();
    }

    function getLinkBalance() external view returns (uint256) {
        return linkToken.balanceOf(address(this));
    }

    function paused() external view returns (bool) {
        return super.paused();
    }

    /// @notice Checks if an address is a config admin
    function isConfigAdmin(address _account) external view returns (bool) {
        return hasRole(ADMIN_ROLE, _account);
    }

    // Modifiers
    modifier onlyRole(bytes32 role) {
        if (!hasRole(role, msg.sender)) revert TelemedicineCore__NotAuthorized();
        _;
    }

    modifier whenNotPaused() {
        if (super.paused()) revert TelemedicineCore__ContractPaused();
        _;
    }

    // Fallback
    receive() external payable onlyRole(ADMIN_ROLE) {
        reserveFundETH += msg.value;
        emit ReserveFundDeposited(msg.sender, msg.value, ITelemedicinePayments.PaymentType.ETH);
        _checkMinBalance(ITelemedicinePayments.PaymentType.ETH);
    }

    // Storage gap for future upgrades
    uint256[49] private __gap; // Reduced by 1 due to nextPaymentId
}
