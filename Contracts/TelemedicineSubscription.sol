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
import {TelemedicineOperations} from "./TelemedicineOperations.sol";

/// @title TelemedicineSubscription
/// @notice Manages patient subscriptions, consultation fees, and appointment bookings
/// @dev UUPS upgradeable, integrates with TelemedicineCore, Payments, and Operations
contract TelemedicineSubscription is Initializable, UUPSUpgradeable, ReentrancyGuardUpgradeable, PausableUpgradeable {
    using SafeMathUpgradeable for uint256;
    using SafeERC20Upgradeable for IERC20Upgradeable;

    // Custom Errors
    error InvalidAddress();
    error NotAuthorized();
    error ContractPaused();
    error InvalidFee();
    error InvalidStatus();
    error InsufficientFunds();
    error InvalidPaymentType();
    error ExternalCallFailed();
    error InvalidVideoCallLink();

    // External Contracts
    TelemedicineCore public core;
    TelemedicinePayments public payments;
    TelemedicineOperations public operations;

    // Configurable Payment Parameters
    uint96 public monthlyFeeUSDC; // $20 in USDC (6 decimals)
    uint96 public annualFeeUSDC; // $200 in USDC (6 decimals)
    uint96 public perConsultFeeUSDC; // $10 in USDC (6 decimals)
    uint8 public subscriptionConsultsLimit; // Max consults per subscription period
    uint256 public monthDuration; // Duration of a month in seconds
    uint256 public versionNumber; // New: Track contract version

    // Constants
    uint256 public constant MONTH_DURATION = 30 days;
    uint256 public constant YEAR_DURATION = 365 days;
    uint96 public constant MIN_MONTHLY_FEE = 5 * 10**6; // New: $5 minimum
    uint96 public constant MIN_ANNUAL_FEE = 50 * 10**6; // New: $50 minimum
    uint96 public constant MIN_CONSULT_FEE = 2 * 10**6; // New: $2 minimum
    uint256 public constant MIN_MONTH_DURATION = 7 days; // New: Minimum 7 days

    // Supported Payment Methods (Bitmap)
    uint256 public supportedPaymentMethods; // New: Bitmap (bit 0: ETH, bit 1: USDC, bit 2: SONIC)

    // Structs
    struct Subscription {
        bool isActive;
        uint256 expiry;
        uint256 consultsUsed;
        uint256 lastReset;
    }

    // Mappings
    mapping(address => Subscription) public subscriptions;
    mapping(uint256 => PendingPayment) public pendingPayments; // Updated: Use local PendingPayment
    uint256 public pendingPaymentCounter;

    // Pending Payment Struct (Aligned with TelemedicineOperations)
    struct PendingPayment {
        address recipient;
        uint256 amount;
        TelemedicinePayments.PaymentType paymentType;
        bool processed;
    }

    // Events
    event Subscribed(address indexed patient, bool isAnnual, uint256 expiry);
    event AppointmentBooked(address indexed patient, address indexed doctor, TelemedicinePayments.PaymentType paymentType);
    event ConsultCharged(address indexed patient, uint256 amount, TelemedicinePayments.PaymentType paymentType);
    event ConfigurationUpdated(string indexed parameter, uint256 value);
    event PaymentMethodUpdated(TelemedicinePayments.PaymentType paymentType, bool enabled);
    event PaymentQueued(uint256 indexed paymentId, address recipient, uint256 amount, TelemedicinePayments.PaymentType paymentType);
    event PaymentReleasedFromQueue(uint256 indexed paymentId, address recipient, uint256 amount);
    event DepositReceived(address indexed sender, uint256 amount);
    event ReserveFundAllocated(uint256 indexed operationId, uint256 amount, TelemedicinePayments.PaymentType paymentType);
    event PlatformFeeAllocated(uint256 indexed operationId, uint256 amount, TelemedicinePayments.PaymentType paymentType);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the contract with core, payments, and operations addresses
    /// @param _core Address of the TelemedicineCore contract
    /// @param _payments Address of the TelemedicinePayments contract
    /// @param _operations Address of the TelemedicineOperations contract
    function initialize(address _core, address _payments, address _operations) external initializer {
        if (_core == address(0) || _payments == address(0) || _operations == address(0)) revert InvalidAddress();

        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        __Pausable_init();

        core = TelemedicineCore(_core);
        payments = TelemedicinePayments(_payments);
        operations = TelemedicineOperations(_operations);

        monthlyFeeUSDC = 20 * 10**6; // $20 in USDC
        annualFeeUSDC = 200 * 10**6; // $200 in USDC
        perConsultFeeUSDC = 10 * 10**6; // $10 in USDC
        subscriptionConsultsLimit = 3;
        monthDuration = MONTH_DURATION;

        // New: Initialize payment methods bitmap
        supportedPaymentMethods = (1 << uint256(TelemedicinePayments.PaymentType.ETH)) |
                                 (1 << uint256(TelemedicinePayments.PaymentType.USDC)) |
                                 (1 << uint256(TelemedicinePayments.PaymentType.SONIC));

        pendingPaymentCounter = 0;
        versionNumber = 1;
    }

    /// @notice Authorizes an upgrade to a new implementation
    /// @param newImplementation Address of the new contract implementation
    function _authorizeUpgrade(address newImplementation) internal override onlyRole(core.ADMIN_ROLE()) {
        versionNumber = versionNumber.add(1);
    }

    // Config Setters (onlyAdmin)

    /// @notice Sets the monthly subscription fee in USDC
    /// @param _fee New fee amount in USDC (6 decimals)
    function setMonthlyFeeUSDC(uint96 _fee) external onlyRole(core.ADMIN_ROLE()) {
        if (_fee < MIN_MONTHLY_FEE) revert InvalidFee();
        monthlyFeeUSDC = _fee;
        emit ConfigurationUpdated("monthlyFeeUSDC", _fee);
    }

    /// @notice Sets the annual subscription fee in USDC
    /// @param _fee New fee amount in USDC (6 decimals)
    function setAnnualFeeUSDC(uint96 _fee) external onlyRole(core.ADMIN_ROLE()) {
        if (_fee < MIN_ANNUAL_FEE) revert InvalidFee();
        annualFeeUSDC = _fee;
        emit ConfigurationUpdated("annualFeeUSDC", _fee);
    }

    /// @notice Sets the per-consultation fee in USDC
    /// @param _fee New fee amount in USDC (6 decimals)
    function setPerConsultFeeUSDC(uint96 _fee) external onlyRole(core.ADMIN_ROLE()) {
        if (_fee < MIN_CONSULT_FEE) revert InvalidFee();
        perConsultFeeUSDC = _fee;
        emit ConfigurationUpdated("perConsultFeeUSDC", _fee);
    }

    /// @notice Sets the maximum number of consultations per subscription period
    /// @param _limit New consultation limit
    function setSubscriptionConsultsLimit(uint8 _limit) external onlyRole(core.ADMIN_ROLE()) {
        subscriptionConsultsLimit = _limit;
        emit ConfigurationUpdated("subscriptionConsultsLimit", _limit);
    }

    /// @notice Sets the duration of a month in seconds
    /// @param _duration New month duration in seconds
    function setMonthDuration(uint256 _duration) external onlyRole(core.ADMIN_ROLE()) {
        if (_duration < MIN_MONTH_DURATION) revert InvalidFee();
        monthDuration = _duration;
        emit ConfigurationUpdated("monthDuration", _duration);
    }

    /// @notice Enables or disables a payment method
    /// @param _paymentType Payment type (ETH, USDC, SONIC)
    /// @param _enabled True to enable, false to disable
    function updatePaymentMethod(TelemedicinePayments.PaymentType _paymentType, bool _enabled) external onlyRole(core.ADMIN_ROLE()) {
        uint256 bit = 1 << uint256(_paymentType);
        bool isCurrentlyEnabled = (supportedPaymentMethods & bit) != 0;
        if (isCurrentlyEnabled == _enabled) revert InvalidStatus();

        if (_enabled) {
            supportedPaymentMethods |= bit;
        } else {
            supportedPaymentMethods &= ~bit;
        }
        emit PaymentMethodUpdated(_paymentType, _enabled);
    }

    /// @notice Subscribes a patient to a plan
    /// @param isAnnual True for annual plan, false for monthly
    /// @param paymentType Payment type (ETH, USDC, SONIC)
    function subscribe(bool isAnnual, TelemedicinePayments.PaymentType paymentType) 
        external payable onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused 
    {
        if (!core.patients(msg.sender).isRegistered) revert NotAuthorized();
        if (!_isPaymentMethodSupported(paymentType)) revert InvalidPaymentType();

        uint256 baseFee = isAnnual ? annualFeeUSDC : monthlyFeeUSDC;
        uint256 duration = isAnnual ? YEAR_DURATION : monthDuration;
        uint256 discountedFee = _applyFeeDiscount(msg.sender, baseFee);

        // Updated: Explicit payment type validation
        if (paymentType == TelemedicinePayments.PaymentType.ETH && msg.value == 0) revert InsufficientFunds();
        if (paymentType != TelemedicinePayments.PaymentType.ETH && msg.value > 0) revert InvalidPaymentType();

        uint256 reserveAmount = discountedFee.mul(core.reserveFundPercentage()).div(core.PERCENTAGE_DENOMINATOR());
        uint256 platformAmount = discountedFee.mul(core.platformFeePercentage()).div(core.PERCENTAGE_DENOMINATOR());

        // Updated: Try-catch for payment processing
        try this._processPayment(paymentType, discountedFee) {
            if (paymentType == TelemedicinePayments.PaymentType.ETH) {
                core.reserveFund = core.reserveFund.add(reserveAmount);
            } else if (paymentType == TelemedicinePayments.PaymentType.USDC) {
                payments.usdcToken().safeTransfer(address(this), reserveAmount);
                core.reserveFund = core.reserveFund.add(reserveAmount);
            } else if (paymentType == TelemedicinePayments.PaymentType.SONIC) {
                payments.sonicToken().safeTransfer(address(this), reserveAmount);
                core.reserveFund = core.reserveFund.add(reserveAmount);
            }

            emit ReserveFundAllocated(0, reserveAmount, paymentType);
            emit PlatformFeeAllocated(0, platformAmount, paymentType);
        } catch {
            revert ExternalCallFailed();
        }

        Subscription storage sub = subscriptions[msg.sender];
        if (sub.isActive && block.timestamp < sub.expiry) {
            sub.expiry = sub.expiry.add(duration);
        } else {
            sub.isActive = true;
            sub.expiry = block.timestamp.add(duration);
            sub.consultsUsed = 0;
            sub.lastReset = block.timestamp;
        }

        // Updated: Try-catch for gamification
        try core.pointsForActions(isAnnual ? "annualSubscription" : "monthlySubscription") returns (uint256 points) {
            TelemedicineCore.GamificationData storage gamification = core.patients(msg.sender).gamification;
            gamification.mediPoints = uint96(gamification.mediPoints.add(points));
            core._levelUp(msg.sender);
        } catch {
            // Log failure but proceed
        }

        emit Subscribed(msg.sender, isAnnual, sub.expiry);
    }

    /// @dev Checks subscription status and charges for a consultation if necessary
    /// @param patient Address of the patient
    /// @return bool True if subscription covers the consult, false if charged separately
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
            sub.consultsUsed = sub.consultsUsed.add(1);
            return true;
        }

        uint256 discountedFee = _applyFeeDiscount(patient, perConsultFeeUSDC);
        // Updated: Try-catch for payment
        try this._processPayment(TelemedicinePayments.PaymentType.USDC, discountedFee) {
            emit ConsultCharged(patient, discountedFee, TelemedicinePayments.PaymentType.USDC);
        } catch {
            revert ExternalCallFailed();
        }
        return false;
    }

    /// @notice Books an appointment with a doctor via TelemedicineOperations
    /// @param doctorAddress The address of the doctor
    /// @param paymentType The type of payment (ETH, USDC, SONIC)
    /// @param isVideoCall Whether it's a video call
    /// @param videoCallLinkHash Hash of the video call link
    function bookAppointment(
        address doctorAddress,
        TelemedicinePayments.PaymentType paymentType,
        bool isVideoCall,
        bytes32 videoCallLinkHash
    ) external payable onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
        if (!core.hasRole(core.DOCTOR_ROLE(), doctorAddress)) revert NotAuthorized();
        if (!core.patients(msg.sender).isRegistered) revert NotAuthorized();
        if (!_isPaymentMethodSupported(paymentType)) revert InvalidPaymentType();
        if (isVideoCall && videoCallLinkHash == bytes32(0)) revert InvalidVideoCallLink();
        if (paymentType == TelemedicinePayments.PaymentType.ETH && msg.value == 0) revert InsufficientFunds();
        if (paymentType != TelemedicinePayments.PaymentType.ETH && msg.value > 0) revert InvalidPaymentType();

        TelemedicineCore.Doctor memory doctor = core.doctors(doctorAddress);
        uint256 baseFee = doctor.consultationFee;
        uint256 discountedFee = _applyFeeDiscount(msg.sender, baseFee);
        if (discountedFee > type(uint96).max) revert InsufficientFunds();

        bool usedSubscription = _checkAndChargeConsult(msg.sender);
        uint256 reserveAmount = discountedFee.mul(core.reserveFundPercentage()).div(core.PERCENTAGE_DENOMINATOR());
        uint256 platformAmount = discountedFee.mul(core.platformFeePercentage()).div(core.PERCENTAGE_DENOMINATOR());

        if (!usedSubscription) {
            // Updated: Try-catch for payment
            try this._processPayment(paymentType, discountedFee) {
                if (paymentType == TelemedicinePayments.PaymentType.ETH) {
                    core.reserveFund = core.reserveFund.add(reserveAmount);
                } else if (paymentType == TelemedicinePayments.PaymentType.USDC) {
                    payments.usdcToken().safeTransfer(address(this), reserveAmount);
                    core.reserveFund = core.reserveFund.add(reserveAmount);
                } else if (paymentType == TelemedicinePayments.PaymentType.SONIC) {
                    payments.sonicToken().safeTransfer(address(this), reserveAmount);
                    core.reserveFund = core.reserveFund.add(reserveAmount);
                }

                emit ReserveFundAllocated(operations.appointmentCounter() + 1, reserveAmount, paymentType);
                emit PlatformFeeAllocated(operations.appointmentCounter() + 1, platformAmount, paymentType);
                emit ConsultCharged(msg.sender, discountedFee, paymentType);
            } catch {
                revert ExternalCallFailed();
            }
        }

        // Updated: Call operations.bookAppointment with videoCallLinkHash
        address[] memory doctors = new address[](1);
        doctors[0] = doctorAddress;
        try operations.bookAppointment{value: paymentType == TelemedicinePayments.PaymentType.ETH ? msg.value : 0}(
            doctors,
            uint48(block.timestamp + core.minBookingBuffer()),
            paymentType,
            isVideoCall,
            videoCallLinkHash
        ) {
            // Success
        } catch {
            revert ExternalCallFailed();
        }

        // Updated: Try-catch for gamification
        try core.pointsForActions("appointment") returns (uint256 points) {
            TelemedicineCore.GamificationData storage gamification = core.patients(msg.sender).gamification;
            gamification.mediPoints = uint96(gamification.mediPoints.add(points));
            core._levelUp(msg.sender);
        } catch {
            // Log failure but proceed
        }

        emit AppointmentBooked(msg.sender, doctorAddress, usedSubscription ? TelemedicinePayments.PaymentType.USDC : paymentType);
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
        external onlyRole(core.ADMIN_ROLE()) nonReentrant 
    {
        if (to == address(0)) revert InvalidAddress();
        if (!_hasSufficientFunds(amount, paymentType)) revert InsufficientFunds();
        _releasePayment(to, amount, paymentType);
    }

    /// @notice Deposits ETH into the contract
    /// @dev Restricted to patients when not paused
    function deposit() external payable onlyRole(core.PATIENT_ROLE()) whenNotPaused {
        emit DepositReceived(msg.sender, msg.value);
    }

    /// @notice Releases a queued payment
    /// @param paymentId The ID of the payment to release
    function releasePendingPayment(uint256 paymentId) external onlyRole(core.ADMIN_ROLE()) nonReentrant {
        PendingPayment storage payment = pendingPayments[paymentId];
        if (payment.recipient == address(0) || payment.processed) revert InvalidStatus();
        if (!_hasSufficientFunds(payment.amount, payment.paymentType)) revert InsufficientFunds();

        payment.processed = true;
        _releasePayment(payment.recipient, payment.amount, payment.paymentType);
        emit PaymentReleasedFromQueue(paymentId, payment.recipient, payment.amount);
    }

    /// @notice Processes pending payments in batch
    /// @param _paymentIds Array of payment IDs to process
    function processPendingPayments(uint256[] calldata _paymentIds) external onlyRole(core.ADMIN_ROLE()) nonReentrant whenNotPaused {
        for (uint256 i = 0; i < _paymentIds.length; i++) {
            PendingPayment storage payment = pendingPayments[_paymentIds[i]];
            if (payment.processed || payment.recipient == address(0)) continue;
            if (_hasSufficientFunds(payment.amount, payment.paymentType)) {
                payment.processed = true;
                if (payment.paymentType == TelemedicinePayments.PaymentType.ETH) {
                    _safeTransferETH(payment.recipient, payment.amount);
                } else if (payment.paymentType == TelemedicinePayments.PaymentType.USDC) {
                    payments.usdcToken().safeTransfer(payment.recipient, payment.amount);
                } else if (payment.paymentType == TelemedicinePayments.PaymentType.SONIC) {
                    payments.sonicToken().safeTransfer(payment.recipient, payment.amount);
                }
                emit PaymentReleasedFromQueue(_paymentIds[i], payment.recipient, payment.amount);
            }
        }
    }

    // Internal Functions

    /// @dev Applies a discount to a fee based on patient status
    /// @param _patient Address of the patient
    /// @param _baseFee Base fee before discount
    /// @return Discounted fee amount
    function _applyFeeDiscount(address _patient, uint256 _baseFee) internal view returns (uint256) {
        // Updated: Try-catch for external call
        try core._applyFeeDiscount(_patient, _baseFee) returns (uint256 discountedFee) {
            return discountedFee;
        } catch {
            return _baseFee; // Fallback to base fee
        }
    }

    /// @dev Processes a payment based on the payment type
    /// @param _type Type of payment (ETH, USDC, SONIC)
    /// @param _amount Amount to process
    function _processPayment(TelemedicinePayments.PaymentType _type, uint256 _amount) internal {
        if (_type == TelemedicinePayments.PaymentType.ETH) {
            if (msg.value < _amount) revert InsufficientFunds();
            if (msg.value > _amount) {
                _safeTransferETH(msg.sender, msg.value.sub(_amount));
            }
        } else if (_type == TelemedicinePayments.PaymentType.USDC) {
            payments.usdcToken().safeTransferFrom(msg.sender, address(payments), _amount);
        } else if (_type == TelemedicinePayments.PaymentType.SONIC) {
            payments.sonicToken().safeTransferFrom(msg.sender, address(payments), _amount);
        } else {
            revert InvalidPaymentType();
        }
    }

    /// @dev Releases a payment to a recipient
    /// @param _to Recipient address
    /// @param _amount Amount to release
    /// @param _paymentType Type of payment (ETH, USDC, SONIC)
    function _releasePayment(address _to, uint256 _amount, TelemedicinePayments.PaymentType _paymentType) internal {
        if (!_hasSufficientFunds(_amount, _paymentType)) {
            pendingPaymentCounter = pendingPaymentCounter.add(1);
            pendingPayments[pendingPaymentCounter] = PendingPayment(_to, _amount, _paymentType, false);
            emit PaymentQueued(pendingPaymentCounter, _to, _amount, _paymentType);
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

    /// @dev Checks if the contract has sufficient funds for a payment
    /// @param _amount Amount to check
    /// @param _paymentType Type of payment (ETH, USDC, SONIC)
    /// @return bool True if sufficient funds are available
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

    /// @dev Safely transfers ETH to an address with gas limit
    /// @param _to Recipient address
    /// @param _amount Amount of ETH to transfer
    function _safeTransferETH(address _to, uint256 _amount) internal {
        // Updated: Gas-limited call
        (bool success, ) = _to.call{value: _amount, gas: 30000}("");
        if (!success) revert InsufficientFunds();
    }

    /// @dev Checks if a payment method is supported
    /// @param _paymentType Payment type to check
    /// @return bool True if supported
    function _isPaymentMethodSupported(TelemedicinePayments.PaymentType _paymentType) internal view returns (bool) {
        return (supportedPaymentMethods & (1 << uint256(_paymentType))) != 0;
    }

    // Fallback function restricted to deposit
    /// @notice Receives ETH deposits from patients
    receive() external payable {
        if (!core.hasRole(core.PATIENT_ROLE(), msg.sender) || core.paused()) revert NotAuthorized();
        emit DepositReceived(msg.sender, msg.value);
    }

    // Modifiers

    /// @notice Restricts access to a specific role
    /// @param role The role required
    modifier onlyRole(bytes32 role) {
        if (!core.hasRole(role, msg.sender)) revert NotAuthorized();
        _;
    }

    /// @notice Ensures the contract is not paused
    modifier whenNotPaused() {
        if (core.paused()) revert ContractPaused();
        _;
    }

    // New: Storage gap for future upgrades
    uint256[50] private __gap;
}
