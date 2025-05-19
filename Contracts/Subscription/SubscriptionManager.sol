// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import {ITelemedicineCore} from "./Interfaces/ITelemedicineCore.sol";
import {ITelemedicinePayments} from "./Interfaces/ITelemedicinePayments.sol";
import {ITelemedicineOperations} from "./Interfaces/ITelemedicineOperations.sol";
import {PaymentProcessor} from "./PaymentProcessor.sol";

/// @title SubscriptionManager
/// @notice Manages patient subscriptions, appointment bookings, and payment processing
/// @dev UUPS upgradeable, integrates with TelemedicineCore, TelemedicineOperations, and PaymentProcessor
contract SubscriptionManager is Initializable, UUPSUpgradeable, ReentrancyGuardUpgradeable, PausableUpgradeable {
    // Custom Errors
    error InvalidAddress();
    error InvalidFee();
    error InvalidLimit();
    error PaymentMethodNotSupported();
    error InvalidTier();
    error NotPatient();
    error NotDoctor();
    error InvalidPoints();
    error SubscriptionNotActive();
    error SubscriptionTooNew();
    error NotAuthorized();
    error ContractPaused();
    error InvalidCoreImplementation();
    error InvalidOperationsImplementation();
    error FeeTooHigh();
    error InvalidBookingTime();
    error InsufficientRefund();
    error ExternalCallFailed();

    // Constants
    uint256 public constant MIN_FEE_USDC = 1 * 10**6; // New: 1 USDC minimum
    uint256 public constant MAX_FEE_USDC = 1000 * 10**6; // New: 1000 USDC maximum
    uint256 public constant MIN_MONTH_DURATION = 7 days; // New: Minimum 7 days
    uint256 public constant MIN_SUBSCRIPTION_DURATION = 1 days; // New: Minimum 1 day

    // State Variables
    ITelemedicineCore public immutable core;
    ITelemedicineOperations public immutable operations;
    PaymentProcessor public immutable paymentProcessor;
    uint256 public monthlyFeeUSDC;
    uint256 public annualFeeUSDC;
    uint256 public perConsultFeeUSDC;
    uint8 public subscriptionConsultsLimitBasic;
    uint8 public subscriptionConsultsLimitPremium;
    uint256 public monthDuration;
    uint256 public minSubscriptionDuration;
    uint256 public versionNumber; // New: Track contract version

    // Enums and Structs
    enum SubscriptionTier { None, Basic, Premium }
    struct Subscription {
        bool isActive;
        uint256 expiry;
        uint256 consultsUsed;
        uint256 lastReset;
        SubscriptionTier tier;
        uint256 startTimestamp;
        uint256 originalFee; // New: Track original fee for refunds
    }

    // Storage
    mapping(address => Subscription) public subscriptions;

    // Events
    event Subscribed(address indexed patient, bool isAnnual, SubscriptionTier tier, uint256 expiry);
    event SubscriptionCancelled(address indexed patient, uint256 refundAmount, ITelemedicinePayments.PaymentType paymentType);
    event AppointmentBooked(address indexed patient, address indexed doctor, ITelemedicinePayments.PaymentType paymentType, bool usedSubscription); // Updated: Use enum
    event ConsultCharged(address indexed patient, uint256 amount, ITelemedicinePayments.PaymentType paymentType); // Updated: Use enum
    event ConfigurationUpdated(string indexed parameter, uint256 value);
    event PaymentMethodUpdated(ITelemedicinePayments.PaymentType paymentType, bool enabled); // New: Consistent with PaymentProcessor

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the contract with core, operations, and payment processor
    /// @param _core Address of TelemedicineCore
    /// @param _operations Address of TelemedicineOperations
    /// @param _paymentProcessor Address of PaymentProcessor
    function initialize(
        address _core,
        address _operations,
        address _paymentProcessor
    ) external initializer {
        if (_core == address(0) || _operations == address(0) || _paymentProcessor == address(0)) revert InvalidAddress();

        // Updated: Try-catch for version checks
        try ITelemedicineCore(_core).version() returns (uint256 coreVersion) {
            if (coreVersion < 1) revert InvalidCoreImplementation();
        } catch {
            revert InvalidCoreImplementation();
        }
        try ITelemedicineOperations(_operations).version() returns (uint256 operationsVersion) {
            if (operationsVersion < 1) revert InvalidOperationsImplementation();
        } catch {
            revert InvalidOperationsImplementation();
        }

        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        __Pausable_init();

        core = ITelemedicineCore(_core);
        operations = ITelemedicineOperations(_operations);
        paymentProcessor = PaymentProcessor(_paymentProcessor);

        uint8 usdcDecimals = paymentProcessor.tokenDecimals(ITelemedicinePayments.PaymentType.USDC);
        monthlyFeeUSDC = 20 * 10**usdcDecimals;
        annualFeeUSDC = 200 * 10**usdcDecimals;
        perConsultFeeUSDC = 10 * 10**usdcDecimals;
        subscriptionConsultsLimitBasic = 3;
        subscriptionConsultsLimitPremium = 6;
        monthDuration = 30 days;
        minSubscriptionDuration = 7 days;
        versionNumber = 1;
    }

    /// @notice Subscribes a patient to a tier
    /// @param isAnnual True for annual, false for monthly
    /// @param tier Subscription tier (Basic, Premium)
    /// @param paymentType Payment type (ETH, USDC, SONIC)
    function subscribe(
        bool isAnnual,
        SubscriptionTier tier,
        ITelemedicinePayments.PaymentType paymentType
    ) external payable nonReentrant whenNotPaused onlyPatient {
        if (!_isPaymentMethodSupported(paymentType)) revert PaymentMethodNotSupported();
        if (tier != SubscriptionTier.Basic && tier != SubscriptionTier.Premium) revert InvalidTier();

        uint256 baseFee = isAnnual ? annualFeeUSDC : monthlyFeeUSDC;
        if (baseFee < MIN_FEE_USDC || baseFee > MAX_FEE_USDC) revert FeeTooHigh();
        uint256 duration = isAnnual ? 365 days : monthDuration;

        // Updated: Try-catch for fee discount
        uint256 discountedFee;
        try core._applyFeeDiscount(msg.sender, baseFee) returns (uint256 fee) {
            if (fee == 0 || fee > baseFee) revert InvalidFee();
            discountedFee = fee;
        } catch {
            revert ExternalCallFailed();
        }

        // Updated: Try-catch for payment processing
        try paymentProcessor.processSubscriptionPayment{value: msg.value}(msg.sender, discountedFee, paymentType, duration) {
            Subscription storage sub = subscriptions[msg.sender];
            if (sub.isActive && block.timestamp < sub.expiry) {
                sub.expiry += duration;
            } else {
                sub.isActive = true;
                sub.expiry = block.timestamp + duration;
                sub.consultsUsed = 0;
                sub.lastReset = block.timestamp;
                sub.tier = tier;
                sub.startTimestamp = block.timestamp;
                sub.originalFee = discountedFee; // New: Store discounted fee
            }

            // Updated: Try-catch for points awarding
            string memory action = isAnnual ? "annualSubscription" : "monthlySubscription";
            try core.pointsForActions(action) returns (uint256 points) {
                if (points == 0) revert InvalidPoints();
                try core.patients(msg.sender) returns (ITelemedicineCore.Patient memory patient) {
                    if (patient.gamification.mediPoints + points > paymentProcessor.maxMediPoints()) revert InvalidPoints();
                    core._awardPoints(msg.sender, uint96(points));
                } catch {
                    revert ExternalCallFailed();
                }
            } catch {
                revert ExternalCallFailed();
            }

            emit Subscribed(msg.sender, isAnnual, tier, sub.expiry);
        } catch {
            revert ExternalCallFailed();
        }
    }

    /// @notice Batch subscribes multiple patients
    /// @param patients Array of patient addresses
    /// @param isAnnual Array of annual/monthly flags
    /// @param tiers Array of subscription tiers
    /// @param paymentTypes Array of payment types
    function batchSubscribe(
        address[] calldata patients,
        bool[] calldata isAnnual,
        SubscriptionTier[] calldata tiers,
        ITelemedicinePayments.PaymentType[] calldata paymentTypes
    ) external payable nonReentrant whenNotPaused onlyConfigAdmin {
        if (patients.length != isAnnual.length || patients.length != tiers.length || patients.length != paymentTypes.length) 
            revert InvalidInput();

        uint256 totalValue = msg.value;
        for (uint256 i = 0; i < patients.length; i++) {
            if (!_isPaymentMethodSupported(paymentTypes[i])) continue;
            if (tiers[i] != SubscriptionTier.Basic && tiers[i] != SubscriptionTier.Premium) continue;
            if (!core.hasRole(core.PATIENT_ROLE(), patients[i])) continue;

            uint256 baseFee = isAnnual[i] ? annualFeeUSDC : monthlyFeeUSDC;
            if (baseFee < MIN_FEE_USDC || baseFee > MAX_FEE_USDC) continue;
            uint256 duration = isAnnual[i] ? 365 days : monthDuration;

            try core._applyFeeDiscount(patients[i], baseFee) returns (uint256 discountedFee) {
                if (discountedFee == 0 || discountedFee > baseFee) continue;
                try paymentProcessor.processSubscriptionPayment{value: totalValue}(patients[i], discountedFee, paymentTypes[i], duration) {
                    Subscription storage sub = subscriptions[patients[i]];
                    if (sub.isActive && block.timestamp < sub.expiry) {
                        sub.expiry += duration;
                    } else {
                        sub.isActive = true;
                        sub.expiry = block.timestamp + duration;
                        sub.consultsUsed = 0;
                        sub.lastReset = block.timestamp;
                        sub.tier = tiers[i];
                        sub.startTimestamp = block.timestamp;
                        sub.originalFee = discountedFee;
                    }

                    string memory action = isAnnual[i] ? "annualSubscription" : "monthlySubscription";
                    try core.pointsForActions(action) returns (uint256 points) {
                        if (points == 0) continue;
                        try core.patients(patients[i]) returns (ITelemedicineCore.Patient memory patient) {
                            if (patient.gamification.mediPoints + points > paymentProcessor.maxMediPoints()) continue;
                            core._awardPoints(patients[i], uint96(points));
                        } catch {
                            continue;
                        }
                    } catch {
                        continue;
                    }

                    emit Subscribed(patients[i], isAnnual[i], tiers[i], sub.expiry);
                    totalValue -= discountedFee;
                } catch {
                    continue;
                }
            } catch {
                continue;
            }
        }
    }

    /// @notice Cancels a patient’s subscription
    /// @param paymentType Payment type for refund
    function cancelSubscription(ITelemedicinePayments.PaymentType paymentType) external nonReentrant whenNotPaused onlyPatient {
        Subscription storage sub = subscriptions[msg.sender];
        if (!sub.isActive || block.timestamp >= sub.expiry) revert SubscriptionNotActive();
        if (block.timestamp < sub.startTimestamp + minSubscriptionDuration) revert SubscriptionTooNew();

        uint256 remainingTime = sub.expiry - block.timestamp;
        uint256 duration = sub.tier == SubscriptionTier.Basic ? monthDuration : 365 days;
        // Updated: Use originalFee for accurate refund
        uint256 refundAmount = (sub.originalFee * remainingTime) / duration;
        if (refundAmount == 0) revert InsufficientRefund();

        sub.isActive = false;
        sub.expiry = block.timestamp;
        sub.consultsUsed = 0;
        sub.originalFee = 0;

        // Updated: Try-catch for payment release
        try paymentProcessor.releasePayment(msg.sender, refundAmount, paymentType) {
            emit SubscriptionCancelled(msg.sender, refundAmount, paymentType);
        } catch {
            revert ExternalCallFailed();
        }
    }

    /// @notice Books an appointment with a doctor
    /// @param doctorAddress Doctor’s address
    /// @param paymentType Payment type (ETH, USDC, SONIC)
    function bookAppointment(
        address doctorAddress,
        ITelemedicinePayments.PaymentType paymentType
    ) external payable nonReentrant whenNotPaused onlyPatient {
        // Updated: Try-catch for doctor role check
        try core.hasRole(core.DOCTOR_ROLE(), doctorAddress) returns (bool isDoctor) {
            if (!isDoctor) revert Not Doctor();
        } catch {
            revert ExternalCallFailed();
        }
        if (!_isPaymentMethodSupported(paymentType)) revert PaymentMethodNotSupported();

        // Updated: Validate booking time
        uint48 bookingTime = uint48(block.timestamp + core.minBookingBuffer());
        if (bookingTime <= block.timestamp) revert InvalidBookingTime();

        // Updated: Cache subscription
        Subscription storage sub = subscriptions[msg.sender];
        bool usedSubscription = _checkAndChargeConsult(msg.sender, sub);

        // Updated: Process payment if not using subscription
        uint256 discountedFee;
        if (!usedSubscription) {
            try core.doctors(doctorAddress) returns (ITelemedicineCore.Doctor memory doctor) {
                try core._applyFeeDiscount(msg.sender, doctor.consultationFee) returns (uint256 fee) {
                    if (fee == 0 || fee > doctor.consultationFee) revert InvalidFee();
                    discountedFee = fee;
                    try paymentProcessor.processPayment{value: msg.value}(msg.sender, discountedFee, paymentType) {
                        emit ConsultCharged(msg.sender, discountedFee, paymentType);
                    } catch {
                        revert ExternalCallFailed();
                    }
                } catch {
                    revert ExternalCallFailed();
                }
            } catch {
                revert ExternalCallFailed();
            }
        }

        // Updated: Try-catch for booking
        try operations.bookAppointment{value: paymentType == ITelemedicinePayments.PaymentType.ETH ? msg.value : 0}(
            doctorAddress,
            bookingTime,
            paymentType,
            usedSubscription,
            ""
        ) {
            // Updated: Try-catch for points awarding
            try core.pointsForActions("appointment") returns (uint256 points) {
                if (points == 0) revert InvalidPoints();
                try core.patients(msg.sender) returns (ITelemedicineCore.Patient memory patient) {
                    if (patient.gamification.mediPoints + points > paymentProcessor.maxMediPoints()) revert InvalidPoints();
                    core._awardPoints(msg.sender, uint96(points));
                } catch {
                    revert ExternalCallFailed();
                }
            } catch {
                revert ExternalCallFailed();
            }

            emit AppointmentBooked(msg.sender, doctorAddress, paymentType, usedSubscription);
        } catch {
            revert ExternalCallFailed();
        }
    }

    /// @notice Batch books appointments
    /// @param doctorAddresses Array of doctor addresses
    /// @param paymentTypes Array of payment types
    function batchBookAppointments(
        address[] calldata doctorAddresses,
        ITelemedicinePayments.PaymentType[] calldata paymentTypes
    ) external payable nonReentrant whenNotPaused onlyPatient {
        if (doctorAddresses.length != paymentTypes.length) revert InvalidInput();
        uint256 totalValue = msg.value;
        Subscription storage sub = subscriptions[msg.sender];

        for (uint256 i = 0; i < doctorAddresses.length; i++) {
            try core.hasRole(core.DOCTOR_ROLE(), doctorAddresses[i]) returns (bool isDoctor) {
                if (!isDoctor) continue;
            } catch {
                continue;
            }
            if (!_isPaymentMethodSupported(paymentTypes[i])) continue;

            uint48 bookingTime = uint48(block.timestamp + core.minBookingBuffer());
            if (bookingTime <= block.timestamp) continue;

            bool usedSubscription = _checkAndChargeConsult(msg.sender, sub);
            uint256 discountedFee;
            if (!usedSubscription) {
                try core.doctors(doctorAddresses[i]) returns (ITelemedicineCore.Doctor memory doctor) {
                    try core._applyFeeDiscount(msg.sender, doctor.consultationFee) returns (uint256 fee) {
                        if (fee == 0 || fee > doctor.consultationFee) continue;
                        discountedFee = fee;
                        try paymentProcessor.processPayment{value: totalValue}(msg.sender, discountedFee, paymentTypes[i]) {
                            emit ConsultCharged(msg.sender, discountedFee, paymentTypes[i]);
                        } catch {
                            continue;
                        }
                    } catch {
                        continue;
                    }
                } catch {
                    continue;
                }
            }

            try operations.bookAppointment{value: paymentTypes[i] == ITelemedicinePayments.PaymentType.ETH ? discountedFee : 0}(
                doctorAddresses[i],
                bookingTime,
                paymentTypes[i],
                usedSubscription,
                ""
            ) {
                try core.pointsForActions("appointment") returns (uint256 points) {
                    if (points == 0) continue;
                    try core.patients(msg.sender) returns (ITelemedicineCore.Patient memory patient) {
                        if (patient.gamification.mediPoints + points > paymentProcessor.maxMediPoints()) continue;
                        core._awardPoints(msg.sender, uint96(points));
                    } catch {
                        continue;
                    }
                } catch {
                    continue;
                }

                emit AppointmentBooked(msg.sender, doctorAddresses[i], paymentTypes[i], usedSubscription);
                if (!usedSubscription && paymentTypes[i] == ITelemedicinePayments.PaymentType.ETH) {
                    totalValue -= discountedFee;
                }
            } catch {
                continue;
            }
        }
    }

    /// @notice Updates configuration parameters
    /// @param parameter Parameter name
    /// @param value New value
    function updateConfiguration(string memory parameter, uint256 value) external onlyConfigAdmin {
        uint8 usdcDecimals = paymentProcessor.tokenDecimals(ITelemedicinePayments.PaymentType.USDC);
        if (keccak256(abi.encodePacked(parameter)) == keccak256(abi.encodePacked("monthlyFeeUSDC"))) {
            if (value < MIN_FEE_USDC || value > MAX_FEE_USDC) revert InvalidFee();
            monthlyFeeUSDC = value;
        } else if (keccak256(abi.encodePacked(parameter)) == keccak256(abi.encodePacked("annualFeeUSDC"))) {
            if (value < MIN_FEE_USDC * 10 || value > MAX_FEE_USDC * 10) revert InvalidFee();
            annualFeeUSDC = value;
        } else if (keccak256(abi.encodePacked(parameter)) == keccak256(abi.encodePacked("perConsultFeeUSDC"))) {
            if (value < MIN_FEE_USDC || value > MAX_FEE_USDC / 2) revert InvalidFee();
            perConsultFeeUSDC = value;
        } else if (keccak256(abi.encodePacked(parameter)) == keccak256(abi.encodePacked("subscriptionConsultsLimitBasic"))) {
            if (value > 10) revert InvalidLimit();
            subscriptionConsultsLimitBasic = uint8(value);
        } else if (keccak256(abi.encodePacked(parameter)) == keccak256(abi.encodePacked("subscriptionConsultsLimitPremium"))) {
            if (value > 20) revert InvalidLimit();
            subscriptionConsultsLimitPremium = uint8(value);
        } else if (keccak256(abi.encodePacked(parameter)) == keccak256(abi.encodePacked("monthDuration"))) {
            if (value < MIN_MONTH_DURATION) revert InvalidLimit();
            monthDuration = value;
        } else if (keccak256(abi.encodePacked(parameter)) == keccak256(abi.encodePacked("minSubscriptionDuration"))) {
            if (value < MIN_SUBSCRIPTION_DURATION) revert InvalidLimit();
            minSubscriptionDuration = value;
        } else {
            revert InvalidConfiguration();
        }
        emit ConfigurationUpdated(parameter, value);
    }

    /// @notice Checks if a payment method is supported
    /// @param paymentType Payment type to check
    /// @return True if supported
    function _isPaymentMethodSupported(ITelemedicinePayments.PaymentType paymentType) internal view returns (bool) {
        try paymentProcessor.isPaymentMethodSupported(paymentType) returns (bool isSupported) {
            return isSupported;
        } catch {
            return false;
        }
    }

    /// @notice Gets subscription status for a patient
    /// @param patient Patient address
    /// @return isActive, expiry, consultsUsed, tier
    function getSubscriptionStatus(address patient) external view onlyPatientOrAdmin returns (bool, uint256, uint256, SubscriptionTier) {
        Subscription memory sub = subscriptions[patient];
        bool active = sub.isActive && block.timestamp < sub.expiry;
        return (active, sub.expiry, sub.consultsUsed, sub.tier);
    }

    /// @notice Checks and charges a consultation
    /// @param patient Patient address
    /// @param sub Subscription data
    /// @return True if subscription consult used
    function _checkAndChargeConsult(address patient, Subscription storage sub) internal returns (bool) {
        if (sub.isActive && block.timestamp >= sub.lastReset + monthDuration) {
            sub.consultsUsed = 0;
            sub.lastReset = block.timestamp;
        }

        if (!sub.isActive || block.timestamp >= sub.expiry) {
            sub.isActive = false;
            return false;
        }

        uint8 consultLimit = sub.tier == SubscriptionTier.Basic ? subscriptionConsultsLimitBasic : subscriptionConsultsLimitPremium;
        if (sub.consultsUsed < consultLimit) {
            sub.consultsUsed++;
            return true;
        }

        // Updated: Try-catch for consult payment
        try core._applyFeeDiscount(patient, perConsultFeeUSDC) returns (uint256 discountedFee) {
            if (discountedFee == 0 || discountedFee > perConsultFeeUSDC) revert InvalidFee();
            try paymentProcessor.processPayment(patient, discountedFee, ITelemedicinePayments.PaymentType.USDC) {
                emit ConsultCharged(patient, discountedFee, ITelemedicinePayments.PaymentType.USDC);
            } catch {
                revert ExternalCallFailed();
            }
        } catch {
            revert ExternalCallFailed();
        }
        return false;
    }

    /// @notice Authorizes contract upgrades
    /// @param newImplementation New implementation address
    function _authorizeUpgrade(address newImplementation) internal override onlyConfigAdmin {
        if (!_isContract(newImplementation)) revert InvalidAddress();
        versionNumber++;
    }

    /// @notice Checks if an address is a contract
    /// @param addr Address to check
    /// @return True if the address is a contract
    function _isContract(address addr) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(addr)
        }
        return size > 0;
    }

    // Modifiers

    /// @notice Restricts to patients
    modifier onlyPatient() {
        try core.hasRole(core.PATIENT_ROLE(), msg.sender) returns (bool hasRole) {
            if (!hasRole) revert NotPatient();
            _;
        } catch {
            revert ExternalCallFailed();
        }
    }

    /// @notice Restricts to config admins
    modifier onlyConfigAdmin() {
        try paymentProcessor.isConfigAdmin(msg.sender) returns (bool isAdmin) {
            if (!isAdmin) revert NotAuthorized();
            _;
        } catch {
            revert ExternalCallFailed();
        }
    }

    /// @notice Restricts to patients or config admins
    modifier onlyPatientOrAdmin() {
        try core.hasRole(core.PATIENT_ROLE(), msg.sender) returns (bool isPatient) {
            if (isPatient) {
                _;
                return;
            }
        } catch {
            revert ExternalCallFailed();
        }
        try paymentProcessor.isConfigAdmin(msg.sender) returns (bool isAdmin) {
            if (!isAdmin) revert NotAuthorized();
            _;
        } catch {
            revert ExternalCallFailed();
        }
    }

    /// @notice Checks pause state and syncs with core
    modifier whenNotPaused() {
        // Updated: Auto-sync pause state
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

    // New: Storage gap for future upgrades
    uint256[50] private __gap;

    // Errors for new functionality
    error InvalidInput();
    error InvalidConfiguration();
}
