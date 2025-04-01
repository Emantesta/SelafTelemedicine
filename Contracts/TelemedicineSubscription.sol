// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import {SafeMathUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";
import {IERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import {SafeERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import {TelemedicineCore} from "./TelemedicineCore.sol";
import {TelemedicinePayments} from "./TelemedicinePayments.sol";

contract TelemedicineSubscription is Initializable, UUPSUpgradeable, ReentrancyGuardUpgradeable, PausableUpgradeable {
    using SafeMathUpgradeable for uint256;
    using SafeERC20Upgradeable for IERC20Upgradeable;

    TelemedicineCore public core;
    TelemedicinePayments public payments;

    // Configurable Payment Parameters
    uint96 public monthlyFeeUSDC; // $20 in USDC (6 decimals)
    uint96 public annualFeeUSDC; // $200 in USDC (6 decimals)
    uint96 public perConsultFeeUSDC; // $10 in USDC (6 decimals)
    uint8 public subscriptionConsultsLimit; // Max consults per subscription period
    uint256 public monthDuration; // Duration of a month in seconds

    // Constants
    uint256 public constant MONTH_DURATION = 30 days;
    uint256 public constant YEAR_DURATION = 365 days;

    // Supported payment methods (aligned with TelemedicinePayments.PaymentType)
    mapping(string => bool) public isPaymentMethodSupported; // e.g., "ETH" => true

    // Structs
    struct Subscription {
        bool isActive;
        uint256 expiry;
        uint256 consultsUsed;
        uint256 lastReset;
    }

    // Mappings
    mapping(address => Subscription) public subscriptions;
    mapping(address => uint256) public patientConsults;

    // Events
    /// @notice Emitted when a patient subscribes to a plan
    /// @param patient The address of the patient
    /// @param isAnnual True if annual plan, false if monthly
    /// @param expiry The subscription expiry timestamp
    event Subscribed(address indexed patient, bool isAnnual, uint256 expiry);

    /// @notice Emitted when an appointment is booked
    /// @param patient The address of the patient
    /// @param doctor The address of the doctor
    /// @param paymentMethod The payment method used
    event AppointmentBooked(address indexed patient, address indexed doctor, string paymentMethod);

    /// @notice Emitted when a consultation is charged
    /// @param patient The address of the patient
    /// @param amount The amount charged
    /// @param currency The currency used (ETH, USDC, SONIC)
    event ConsultCharged(address indexed patient, uint256 amount, string currency);

    /// @notice Emitted when a configuration parameter is updated
    /// @param parameter The name of the parameter
    /// @param value The new value
    event ConfigurationUpdated(string indexed parameter, uint256 value);

    /// @notice Emitted when a payment method is added
    /// @param methodName The name of the payment method
    event PaymentMethodAdded(string methodName);

    /// @notice Emitted when a payment method is removed
    /// @param methodName The name of the payment method
    event PaymentMethodRemoved(string methodName);

    /// @notice Emitted when a payment is queued due to insufficient funds
    /// @param paymentId The ID of the queued payment
    /// @param recipient The recipient of the payment
    /// @param amount The amount queued
    /// @param paymentType The type of payment (ETH, USDC, SONIC)
    event PaymentQueued(uint256 indexed paymentId, address recipient, uint256 amount, TelemedicinePayments.PaymentType paymentType);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the contract with core and payments addresses
    /// @param _core Address of the TelemedicineCore contract
    /// @param _payments Address of the TelemedicinePayments contract
    function initialize(address _core, address _payments) external initializer {
        if (_core == address(0)) revert TelemedicinePayments.InvalidAddress();
        if (_payments == address(0)) revert TelemedicinePayments.InvalidAddress();

        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        __Pausable_init();

        core = TelemedicineCore(_core);
        payments = TelemedicinePayments(_payments);

        monthlyFeeUSDC = 20 * 10**6; // $20 in USDC
        annualFeeUSDC = 200 * 10**6; // $200 in USDC
        perConsultFeeUSDC = 10 * 10**6; // $10 in USDC
        subscriptionConsultsLimit = 3;
        monthDuration = MONTH_DURATION;

        isPaymentMethodSupported["ETH"] = true;
        isPaymentMethodSupported["USDC"] = true;
        isPaymentMethodSupported["SONIC"] = true;
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyRole(core.ADMIN_ROLE()) {}

    // Config setters (onlyAdmin)
    /// @notice Sets the monthly subscription fee in USDC
    /// @param _fee The new fee amount
    function setMonthlyFeeUSDC(uint96 _fee) external onlyRole(core.ADMIN_ROLE()) {
        if (_fee == 0) revert TelemedicinePayments.InvalidStatus();
        monthlyFeeUSDC = _fee;
        emit ConfigurationUpdated("monthlyFeeUSDC", _fee);
    }

    /// @notice Sets the annual subscription fee in USDC
    /// @param _fee The new fee amount
    function setAnnualFeeUSDC(uint96 _fee) external onlyRole(core.ADMIN_ROLE()) {
        if (_fee == 0) revert TelemedicinePayments.InvalidStatus();
        annualFeeUSDC = _fee;
        emit ConfigurationUpdated("annualFeeUSDC", _fee);
    }

    /// @notice Sets the per-consult fee in USDC
    /// @param _fee The new fee amount
    function setPerConsultFeeUSDC(uint96 _fee) external onlyRole(core.ADMIN_ROLE()) {
        if (_fee == 0) revert TelemedicinePayments.InvalidStatus();
        perConsultFeeUSDC = _fee;
        emit ConfigurationUpdated("perConsultFeeUSDC", _fee);
    }

    /// @notice Sets the subscription consult limit
    /// @param _limit The new consult limit
    function setSubscriptionConsultsLimit(uint8 _limit) external onlyRole(core.ADMIN_ROLE()) {
        subscriptionConsultsLimit = _limit;
        emit ConfigurationUpdated("subscriptionConsultsLimit", _limit);
    }

    /// @notice Sets the month duration
    /// @param _duration The new duration in seconds
    function setMonthDuration(uint256 _duration) external onlyRole(core.ADMIN_ROLE()) {
        if (_duration == 0) revert TelemedicinePayments.InvalidStatus();
        monthDuration = _duration;
        emit ConfigurationUpdated("monthDuration", _duration);
    }

    /// @notice Adds a supported payment method
    /// @param _methodName The name of the payment method
    function addPaymentMethod(string memory _methodName) external onlyRole(core.ADMIN_ROLE()) {
        if (isPaymentMethodSupported[_methodName]) revert TelemedicinePayments.InvalidStatus();
        isPaymentMethodSupported[_methodName] = true;
        emit PaymentMethodAdded(_methodName);
    }

    /// @notice Removes a supported payment method
    /// @param _methodName The name of the payment method
    function removePaymentMethod(string memory _methodName) external onlyRole(core.ADMIN_ROLE()) {
        if (!isPaymentMethodSupported[_methodName]) revert TelemedicinePayments.InvalidStatus();
        isPaymentMethodSupported[_methodName] = false;
        emit PaymentMethodRemoved(_methodName);
    }

    /// @notice Subscribes a patient to a plan
    /// @param isAnnual True for annual plan, false for monthly
    function subscribe(bool isAnnual) external payable onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
        uint256 baseFee = isAnnual ? annualFeeUSDC : monthlyFeeUSDC;
        uint256 duration = isAnnual ? YEAR_DURATION : monthDuration;
        uint256 discountedFee = _applyFeeDiscount(msg.sender, baseFee);

        TelemedicinePayments.PaymentType paymentType = msg.value > 0 ? TelemedicinePayments.PaymentType.ETH : TelemedicinePayments.PaymentType.USDC;
        _processPayment(paymentType, discountedFee);

        Subscription storage sub = subscriptions[msg.sender];
        if (sub.isActive && block.timestamp < sub.expiry) {
            sub.expiry = sub.expiry.add(duration);
        } else {
            sub.isActive = true;
            sub.expiry = block.timestamp.add(duration);
            sub.consultsUsed = 0;
            sub.lastReset = block.timestamp;
        }

        // Award gamification points (cached for gas optimization)
        TelemedicineCore.GamificationData storage gamification = core.patients(msg.sender).gamification;
        unchecked {
            gamification.mediPoints = uint96(
                gamification.mediPoints.add(
                    core.pointsForActions(isAnnual ? "annualSubscription" : "monthlySubscription")
                )
            );
        }
        _levelUp(msg.sender);

        emit Subscribed(msg.sender, isAnnual, sub.expiry);
    }

    // Internal function to check and charge consult
    function _checkAndChargeConsult(address patient) internal returns (bool) {
        Subscription storage sub = subscriptions[patient];

        if (sub.isActive && block.timestamp >= sub.lastReset.add(monthDuration)) {
            sub.consultsUsed = 0;
            sub.lastReset = block.timestamp;
        }

        if (!sub.isActive || block.timestamp >= sub.expiry) {
            sub.isActive = false;
            return false;
        }

        if (sub.consultsUsed < subscriptionConsultsLimit) {
            unchecked { sub.consultsUsed = sub.consultsUsed.add(1); }
            return true;
        }

        uint256 discountedFee = _applyFeeDiscount(patient, perConsultFeeUSDC);
        _processPayment(TelemedicinePayments.PaymentType.USDC, discountedFee);
        emit ConsultCharged(patient, discountedFee, "USDC");
        return false;
    }

    /// @notice Books an appointment with a doctor
    /// @param doctorAddress The address of the doctor
    /// @param paymentMethod The payment method to use
    /// @param paymentType The type of payment (ETH, USDC, SONIC)
    function bookAppointment(
        address doctorAddress,
        string memory paymentMethod,
        TelemedicinePayments.PaymentType paymentType
    ) external payable onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
        if (!core.hasRole(core.DOCTOR_ROLE(), doctorAddress)) revert TelemedicinePayments.NotAuthorized();
        if (!isPaymentMethodSupported[paymentMethod]) revert TelemedicinePayments.InvalidStatus();
        if (block.timestamp < core.minBookingBuffer()) revert TelemedicinePayments.InvalidStatus();

        TelemedicineCore.Doctor memory doctor = core.doctors(doctorAddress);
        uint256 baseFee = doctor.consultationFee;
        uint256 discountedFee = _applyFeeDiscount(msg.sender, baseFee);
        if (discountedFee > type(uint96).max) revert TelemedicinePayments.InsufficientFunds();

        bool usedSubscription = _checkAndChargeConsult(msg.sender);

        if (!usedSubscription) {
            _processPayment(paymentType, discountedFee);
            emit ConsultCharged(msg.sender, discountedFee, paymentMethod);
        }

        unchecked { patientConsults[msg.sender] = patientConsults[msg.sender].add(1); }
        TelemedicineCore.GamificationData storage gamification = core.patients(msg.sender).gamification;
        unchecked {
            gamification.mediPoints = uint96(
                gamification.mediPoints.add(core.pointsForActions("appointment"))
            );
        }
        _levelUp(msg.sender);

        emit AppointmentBooked(msg.sender, doctorAddress, usedSubscription ? "Subscription" : paymentMethod);
    }

    /// @notice Gets the subscription status of a patient
    /// @param patient The address of the patient
    /// @return isActive Whether the subscription is active
    /// @return expiry The subscription expiry timestamp
    /// @return consultsUsed The number of consults used
    function getSubscriptionStatus(address patient) external view returns (bool isActive, uint256 expiry, uint256 consultsUsed) {
        Subscription memory sub = subscriptions[patient];
        bool active = sub.isActive && block.timestamp < sub.expiry;
        return (active, sub.expiry, sub.consultsUsed);
    }

    /// @notice Withdraws funds to a specified address
    /// @param to The address to withdraw to
    /// @param amount The amount to withdraw
    /// @param paymentType The type of payment (ETH, USDC, SONIC)
    function withdraw(address to, uint256 amount, TelemedicinePayments.PaymentType paymentType) 
        external 
        onlyRole(core.ADMIN_ROLE()) 
        nonReentrant 
    {
        if (to == address(0)) revert TelemedicinePayments.InvalidAddress();
        if (!_hasSufficientFunds(amount, paymentType)) revert TelemedicinePayments.InsufficientFunds();
        _releasePayment(to, amount, paymentType);
    }

    /// @notice Deposits ETH into the contract (restricted to payments)
    function deposit() external payable onlyRole(core.PATIENT_ROLE()) whenNotPaused {
        // No additional logic needed; ETH is received and tracked via balance
    }

    // Internal Functions
    function _applyFeeDiscount(address _patient, uint256 _baseFee) internal view returns (uint256) {
        uint8 level = core.patients(_patient).gamification.currentLevel;
        uint256 discountPercentage = core.discountLevels(level);
        if (discountPercentage == 0) return _baseFee;
        uint256 discount = _baseFee.mul(discountPercentage).div(100);
        return _baseFee.sub(discount);
    }

    function _levelUp(address _patient) internal {
        TelemedicineCore.GamificationData storage gamification = core.patients(_patient).gamification;
        uint256 pointsNeeded = uint256(gamification.currentLevel + 1).mul(core.pointsPerLevel());
        if (gamification.mediPoints >= pointsNeeded && gamification.currentLevel < core.maxLevel()) {
            unchecked { gamification.currentLevel = gamification.currentLevel + 1; }
        }
    }

    function _processPayment(TelemedicinePayments.PaymentType _type, uint256 _amount) internal {
        if (_type == TelemedicinePayments.PaymentType.ETH) {
            if (msg.value < _amount) revert TelemedicinePayments.InsufficientFunds();
            if (msg.value > _amount) {
                _safeTransferETH(msg.sender, msg.value.sub(_amount));
            }
        } else if (_type == TelemedicinePayments.PaymentType.USDC) {
            payments.usdcToken().safeTransferFrom(msg.sender, address(payments), _amount);
        } else if (_type == TelemedicinePayments.PaymentType.SONIC) {
            payments.sonicToken().safeTransferFrom(msg.sender, address(payments), _amount);
        } else {
            revert TelemedicinePayments.InvalidStatus();
        }
    }

    function _releasePayment(address _to, uint256 _amount, TelemedicinePayments.PaymentType _paymentType) internal {
        if (!_hasSufficientFunds(_amount, _paymentType)) {
            payments.queuePayment(_to, _amount, _paymentType, uint48(block.timestamp));
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

    function _safeTransferETH(address _to, uint256 _amount) internal {
        (bool success, ) = _to.call{value: _amount}("");
        if (!success) revert TelemedicinePayments.PaymentFailed();
    }

    // Fallback function restricted to deposit
    receive() external payable {
        if (!core.hasRole(core.PATIENT_ROLE(), msg.sender) || core.paused()) revert TelemedicinePayments.NotAuthorized();
    }

    // Modifiers
    modifier onlyRole(bytes32 role) {
        if (!core.hasRole(role, msg.sender)) revert TelemedicinePayments.NotAuthorized();
        _;
    }

    modifier whenNotPaused() {
        if (core.paused()) revert TelemedicinePayments.ContractPaused();
        _;
    }
}
