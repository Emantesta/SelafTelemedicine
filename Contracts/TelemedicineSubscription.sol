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

contract TelemedicineSubscription is Initializable, UUPSUpgradeable, ReentrancyGuardUpgradeable, PausableUpgradeable {
    using SafeMathUpgradeable for uint256;
    using SafeERC20Upgradeable for IERC20Upgradeable;

    TelemedicineCore public core;
    TelemedicinePayments public payments;
    TelemedicineOperations public operations;

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
    mapping(uint256 => TelemedicinePayments.PendingPayment) public pendingPayments;
    uint256 public pendingPaymentCounter;

    // Events
    event Subscribed(address indexed patient, bool isAnnual, uint256 expiry);
    event AppointmentBooked(address indexed patient, address indexed doctor, string paymentMethod);
    event ConsultCharged(address indexed patient, uint256 amount, string currency);
    event ConfigurationUpdated(string indexed parameter, uint256 value);
    event PaymentMethodAdded(string methodName);
    event PaymentMethodRemoved(string methodName);
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
        if (_core == address(0)) revert TelemedicinePayments.InvalidAddress();
        if (_payments == address(0)) revert TelemedicinePayments.InvalidAddress();
        if (_operations == address(0)) revert TelemedicinePayments.InvalidAddress();

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

        isPaymentMethodSupported["ETH"] = true;
        isPaymentMethodSupported["USDC"] = true;
        isPaymentMethodSupported["SONIC"] = true;

        pendingPaymentCounter = 0;
    }

    /// @notice Authorizes an upgrade to a new implementation
    /// @param newImplementation Address of the new contract implementation
    function _authorizeUpgrade(address newImplementation) internal override onlyRole(core.ADMIN_ROLE()) {}

    // Config setters (onlyAdmin)
    /// @notice Sets the monthly subscription fee in USDC
    /// @param _fee New fee amount in USDC (6 decimals)
    function setMonthlyFeeUSDC(uint96 _fee) external onlyRole(core.ADMIN_ROLE()) {
        if (_fee == 0) revert TelemedicinePayments.InvalidStatus();
        monthlyFeeUSDC = _fee;
        emit ConfigurationUpdated("monthlyFeeUSDC", _fee);
    }

    /// @notice Sets the annual subscription fee in USDC
    /// @param _fee New fee amount in USDC (6 decimals)
    function setAnnualFeeUSDC(uint96 _fee) external onlyRole(core.ADMIN_ROLE()) {
        if (_fee == 0) revert TelemedicinePayments.InvalidStatus();
        annualFeeUSDC = _fee;
        emit ConfigurationUpdated("annualFeeUSDC", _fee);
    }

    /// @notice Sets the per-consultation fee in USDC
    /// @param _fee New fee amount in USDC (6 decimals)
    function setPerConsultFeeUSDC(uint96 _fee) external onlyRole(core.ADMIN_ROLE()) {
        if (_fee == 0) revert TelemedicinePayments.InvalidStatus();
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
        if (_duration == 0) revert TelemedicinePayments.InvalidStatus();
        monthDuration = _duration;
        emit ConfigurationUpdated("monthDuration", _duration);
    }

    /// @notice Adds a new supported payment method
    /// @param _methodName Name of the payment method (e.g., "ETH", "USDC")
    function addPaymentMethod(string memory _methodName) external onlyRole(core.ADMIN_ROLE()) {
        if (isPaymentMethodSupported[_methodName]) revert TelemedicinePayments.InvalidStatus();
        isPaymentMethodSupported[_methodName] = true;
        emit PaymentMethodAdded(_methodName);
    }

    /// @notice Removes a supported payment method
    /// @param _methodName Name of the payment method to remove
    function removePaymentMethod(string memory _methodName) external onlyRole(core.ADMIN_ROLE()) {
        if (!isPaymentMethodSupported[_methodName]) revert TelemedicinePayments.InvalidStatus();
        isPaymentMethodSupported[_methodName] = false;
        emit PaymentMethodRemoved(_methodName);
    }

    /// @notice Subscribes a patient to a plan
    /// @param isAnnual True for annual plan, false for monthly
    function subscribe(bool isAnnual) external payable onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
        if (!core.patients(msg.sender).isRegistered) revert TelemedicinePayments.NotAuthorized();

        uint256 baseFee = isAnnual ? annualFeeUSDC : monthlyFeeUSDC;
        uint256 duration = isAnnual ? YEAR_DURATION : monthDuration;
        uint256 discountedFee = _applyFeeDiscount(msg.sender, baseFee);

        TelemedicinePayments.PaymentType paymentType = msg.value > 0 ? TelemedicinePayments.PaymentType.ETH : TelemedicinePayments.PaymentType.USDC;
        if (!isPaymentMethodSupported[paymentType == TelemedicinePayments.PaymentType.ETH ? "ETH" : paymentType == TelemedicinePayments.PaymentType.USDC ? "USDC" : "SONIC"]) 
            revert TelemedicinePayments.InvalidStatus();

        uint256 reserveAmount = discountedFee.mul(core.reserveFundPercentage()).div(core.PERCENTAGE_DENOMINATOR());
        uint256 platformAmount = discountedFee.mul(core.platformFeePercentage()).div(core.PERCENTAGE_DENOMINATOR());

        _processPayment(paymentType, discountedFee);

        if (paymentType == TelemedicinePayments.PaymentType.ETH) {
            core.reserveFund = core.reserveFund.add(reserveAmount);
        } else if (paymentType == TelemedicinePayments.PaymentType.USDC) {
            payments.usdcToken().safeTransfer(address(this), reserveAmount);
            core.reserveFund = core.reserveFund.add(reserveAmount);
        } else if (paymentType == TelemedicinePayments.PaymentType.SONIC) {
            payments.sonicToken().safeTransfer(address(this), reserveAmount);
            core.reserveFund = core.reserveFund.add(reserveAmount);
        }

        emit ReserveFundAllocated(0, reserveAmount, paymentType); // 0 as no specific operation ID
        emit PlatformFeeAllocated(0, platformAmount, paymentType);

        Subscription storage sub = subscriptions[msg.sender];
        if (sub.isActive && block.timestamp < sub.expiry) {
            sub.expiry = sub.expiry.add(duration);
        } else {
            sub.isActive = true;
            sub.expiry = block.timestamp.add(duration);
            sub.consultsUsed = 0;
            sub.lastReset = block.timestamp;
        }

        TelemedicineCore.GamificationData storage gamification = core.patients(msg.sender).gamification;
        unchecked {
            gamification.mediPoints = uint96(
                gamification.mediPoints.add(
                    core.pointsForActions(isAnnual ? "annualSubscription" : "monthlySubscription")
                )
            );
        }
        core._levelUp(msg.sender);

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
            unchecked { sub.consultsUsed = sub.consultsUsed.add(1); }
            return true;
        }

        uint256 discountedFee = _applyFeeDiscount(patient, perConsultFeeUSDC);
        _processPayment(TelemedicinePayments.PaymentType.USDC, discountedFee);
        emit ConsultCharged(patient, discountedFee, "USDC");
        return false;
    }

    /// @notice Books an appointment with a doctor via TelemedicineOperations
    /// @param doctorAddress The address of the doctor
    /// @param paymentMethod The payment method to use (e.g., "ETH", "USDC", "SONIC")
    /// @param paymentType The type of payment (ETH, USDC, SONIC)
    function bookAppointment(
        address doctorAddress,
        string memory paymentMethod,
        TelemedicinePayments.PaymentType paymentType
    ) external payable onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
        if (!core.hasRole(core.DOCTOR_ROLE(), doctorAddress)) revert TelemedicinePayments.NotAuthorized();
        if (!core.patients(msg.sender).isRegistered) revert TelemedicinePayments.NotAuthorized();
        if (!isPaymentMethodSupported[paymentMethod]) revert TelemedicinePayments.InvalidStatus();

        // Validate paymentMethod matches paymentType
        if (
            (paymentType == TelemedicinePayments.PaymentType.ETH && keccak256(abi.encodePacked(paymentMethod)) != keccak256(abi.encodePacked("ETH"))) ||
            (paymentType == TelemedicinePayments.PaymentType.USDC && keccak256(abi.encodePacked(paymentMethod)) != keccak256(abi.encodePacked("USDC"))) ||
            (paymentType == TelemedicinePayments.PaymentType.SONIC && keccak256(abi.encodePacked(paymentMethod)) != keccak256(abi.encodePacked("SONIC")))
        ) revert TelemedicinePayments.InvalidStatus();

        TelemedicineCore.Doctor memory doctor = core.doctors(doctorAddress);
        uint256 baseFee = doctor.consultationFee;
        uint256 discountedFee = _applyFeeDiscount(msg.sender, baseFee);
        if (discountedFee > type(uint96).max) revert TelemedicinePayments.InsufficientFunds();

        bool usedSubscription = _checkAndChargeConsult(msg.sender);
        uint256 reserveAmount = discountedFee.mul(core.reserveFundPercentage()).div(core.PERCENTAGE_DENOMINATOR());
        uint256 platformAmount = discountedFee.mul(core.platformFeePercentage()).div(core.PERCENTAGE_DENOMINATOR());

        if (!usedSubscription) {
            _processPayment(paymentType, discountedFee);

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
            emit ConsultCharged(msg.sender, discountedFee, paymentMethod);
        }

        address[] memory doctors = new address[](1);
        doctors[0] = doctorAddress;
        operations.bookAppointment{value: paymentType == TelemedicinePayments.PaymentType.ETH ? msg.value : 0}(
            doctors,
            uint48(block.timestamp + core.minBookingBuffer()),
            paymentType,
            false, // No video call by default
            ""     // No video call link
        );

        TelemedicineCore.GamificationData storage gamification = core.patients(msg.sender).gamification;
        unchecked {
            gamification.mediPoints = uint96(
                gamification.mediPoints.add(core.pointsForActions("appointment"))
            );
        }
        core._levelUp(msg.sender);

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

    /// @notice Deposits ETH into the contract
    /// @dev Restricted to patients when not paused
    function deposit() external payable onlyRole(core.PATIENT_ROLE()) whenNotPaused {
        emit DepositReceived(msg.sender, msg.value);
    }

    /// @notice Releases a queued payment
    /// @param paymentId The ID of the payment to release
    function releasePendingPayment(uint256 paymentId) external onlyRole(core.ADMIN_ROLE()) nonReentrant {
        TelemedicinePayments.PendingPayment storage payment = pendingPayments[paymentId];
        if (payment.recipient == address(0) || payment.processed) revert TelemedicinePayments.InvalidStatus();
        if (!_hasSufficientFunds(payment.amount, payment.paymentType)) revert TelemedicinePayments.InsufficientFunds();

        payment.processed = true;
        _releasePayment(payment.recipient, payment.amount, payment.paymentType);
        emit PaymentReleasedFromQueue(paymentId, payment.recipient, payment.amount);
    }

    // Internal Functions
    /// @dev Applies a discount to a fee based on patient status
    /// @param _patient Address of the patient
    /// @param _baseFee Base fee before discount
    /// @return Discounted fee amount
    function _applyFeeDiscount(address _patient, uint256 _baseFee) internal view returns (uint256) {
        return core._applyFeeDiscount(_patient, _baseFee);
    }

    /// @dev Processes a payment based on the payment type
    /// @param _type Type of payment (ETH, USDC, SONIC)
    /// @param _amount Amount to process
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

    /// @dev Releases a payment to a recipient
    /// @param _to Recipient address
    /// @param _amount Amount to release
    /// @param _paymentType Type of payment (ETH, USDC, SONIC)
    function _releasePayment(address _to, uint256 _amount, TelemedicinePayments.PaymentType _paymentType) internal {
        if (!_hasSufficientFunds(_amount, _paymentType)) {
            pendingPaymentCounter = pendingPaymentCounter.add(1);
            pendingPayments[pendingPaymentCounter] = TelemedicinePayments.PendingPayment(_to, _amount, _paymentType, false);
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

    /// @dev Safely transfers ETH to an address
    /// @param _to Recipient address
    /// @param _amount Amount of ETH to transfer
    function _safeTransferETH(address _to, uint256 _amount) internal {
        (bool success, ) = _to.call{value: _amount}("");
        if (!success) revert TelemedicinePayments.PaymentFailed();
    }

    // Fallback function restricted to deposit
    /// @notice Receives ETH deposits from patients
    receive() external payable {
        if (!core.hasRole(core.PATIENT_ROLE(), msg.sender) || core.paused()) revert TelemedicinePayments.NotAuthorized();
        emit DepositReceived(msg.sender, msg.value);
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
