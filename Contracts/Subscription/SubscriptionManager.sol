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

contract SubscriptionManager is Initializable, UUPSUpgradeable, ReentrancyGuardUpgradeable, PausableUpgradeable {
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
    bool private localPaused;

    enum SubscriptionTier { None, Basic, Premium }
    struct Subscription {
        bool isActive;
        uint256 expiry;
        uint256 consultsUsed;
        uint256 lastReset;
        SubscriptionTier tier;
        uint256 startTimestamp;
    }

    mapping(address => Subscription) public subscriptions;

    event Subscribed(address indexed patient, bool isAnnual, SubscriptionTier tier, uint256 expiry);
    event SubscriptionCancelled(address indexed patient, uint256 refundAmount, ITelemedicinePayments.PaymentType paymentType);
    event AppointmentBooked(address indexed patient, address indexed doctor, string paymentMethod);
    event ConsultCharged(address indexed patient, uint256 amount, string currency);
    event ConfigurationUpdated(string indexed parameter, uint256 value);
    event PauseStateSynced(bool paused);

    constructor() {
        _disableInitializers();
    }

    function initialize(
        address _core,
        address _operations,
        address _paymentProcessor,
        uint256 _requiredApprovals
    ) external initializer {
        if (_core == address(0) || _operations == address(0) || _paymentProcessor == address(0)) revert InvalidAddress();
        if (_requiredApprovals < 2 || _requiredApprovals > 10) revert InvalidApprovalCount();

        if (ITelemedicineCore(_core).version() < 1) revert InvalidCoreImplementation();
        if (ITelemedicineOperations(_operations).version() < 1) revert InvalidOperationsImplementation();

        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        __Pausable_init();

        core = ITelemedicineCore(_core);
        operations = ITelemedicineOperations(_operations);
        paymentProcessor = PaymentProcessor(_paymentProcessor);

        monthlyFeeUSDC = 20 * 10**6; // Assuming 6 decimals for USDC
        annualFeeUSDC = 200 * 10**6;
        perConsultFeeUSDC = 10 * 10**6;
        subscriptionConsultsLimitBasic = 3;
        subscriptionConsultsLimitPremium = 6;
        monthDuration = 30 days;
        minSubscriptionDuration = 7 days;
        localPaused = core.paused();

        emit PauseStateSynced(localPaused);
    }

    function subscribe(
        bool isAnnual,
        SubscriptionTier tier,
        ITelemedicinePayments.PaymentType paymentType
    ) external payable nonReentrant whenNotPaused onlyPatient {
        if (!isPaymentMethodSupported(paymentType)) revert PaymentMethodNotSupported();
        if (tier != SubscriptionTier.Basic && tier != SubscriptionTier.Premium) revert InvalidTier();

        uint256 baseFee = isAnnual ? annualFeeUSDC : monthlyFeeUSDC;
        if (baseFee > 1000 * 10**6) revert FeeTooHigh();
        uint256 duration = isAnnual ? 365 days : monthDuration;
        uint256 discountedFee = core._applyFeeDiscount(msg.sender, baseFee);
        if (discountedFee == 0 || discountedFee > baseFee) revert InvalidFee();

        paymentProcessor.processSubscriptionPayment{value: msg.value}(msg.sender, discountedFee, paymentType, duration);

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
        }

        uint96 points = uint96(core.pointsForActions(isAnnual ? "annualSubscription" : "monthlySubscription"));
        if (points == 0 || core.patients(msg.sender).gamification.mediPoints + points > paymentProcessor.maxMediPoints())
            revert InvalidPoints();
        core._awardPoints(msg.sender, points);

        emit Subscribed(msg.sender, isAnnual, tier, sub.expiry);
    }

    function cancelSubscription(ITelemedicinePayments.PaymentType paymentType) external nonReentrant whenNotPaused onlyPatient {
        Subscription storage sub = subscriptions[msg.sender];
        if (!sub.isActive || block.timestamp >= sub.expiry) revert SubscriptionNotActive();
        if (block.timestamp < sub.startTimestamp + minSubscriptionDuration) revert SubscriptionTooNew();

        uint256 remainingTime = sub.expiry - block.timestamp;
        uint256 baseFee = sub.tier == SubscriptionTier.Basic ? monthlyFeeUSDC : annualFeeUSDC;
        uint256 duration = sub.tier == SubscriptionTier.Basic ? monthDuration : 365 days;
        uint256 refundAmount = (baseFee * remainingTime) / duration;

        sub.isActive = false;
        sub.expiry = block.timestamp;
        sub.consultsUsed = 0;

        if (refundAmount > 0) {
            paymentProcessor.releasePayment(msg.sender, refundAmount, paymentType);
            emit SubscriptionCancelled(msg.sender, refundAmount, paymentType);
        }
    }

    function bookAppointment(
        address doctorAddress,
        ITelemedicinePayments.PaymentType paymentType
    ) external payable nonReentrant whenNotPaused onlyPatient {
        if (!core.hasRole(core.DOCTOR_ROLE(), doctorAddress)) revert NotDoctor();
        if (!isPaymentMethodSupported(paymentType)) revert PaymentMethodNotSupported();

        uint256 baseFee = core.doctors(doctorAddress).consultationFee;
        uint256 discountedFee = core._applyFeeDiscount(msg.sender, baseFee);
        if (discountedFee == 0 || discountedFee > baseFee) revert InvalidFee();

        bool usedSubscription = _checkAndChargeConsult(msg.sender);
        if (!usedSubscription) {
            paymentProcessor.processPayment{value: msg.value}(msg.sender, discountedFee, paymentType);
            emit ConsultCharged(msg.sender, discountedFee, paymentProcessor.getCurrency(paymentType));
        }

        operations.bookAppointment{value: paymentType == ITelemedicinePayments.PaymentType.ETH ? msg.value : 0}(
            doctorAddress,
            uint48(block.timestamp + core.minBookingBuffer()),
            paymentType,
            usedSubscription,
            ""
        );

        uint96 points = uint96(core.pointsForActions("appointment"));
        if (points == 0 || core.patients(msg.sender).gamification.mediPoints + points > paymentProcessor.maxMediPoints())
            revert InvalidPoints();
        core._awardPoints(msg.sender, points);

        emit AppointmentBooked(msg.sender, doctorAddress, usedSubscription ? "Subscription" : paymentProcessor.getCurrency(paymentType));
    }

    function setMonthlyFeeUSDC(uint256 _fee) external onlyConfigAdmin {
        if (_fee == 0 || _fee > 1000 * 10**6) revert InvalidFee();
        monthlyFeeUSDC = _fee;
        emit ConfigurationUpdated("monthlyFeeUSDC", _fee);
    }

    function setAnnualFeeUSDC(uint256 _fee) external onlyConfigAdmin {
        if (_fee == 0 || _fee > 10000 * 10**6) revert InvalidFee();
        annualFeeUSDC = _fee;
        emit ConfigurationUpdated("annualFeeUSDC", _fee);
    }

    function setPerConsultFeeUSDC(uint256 _fee) external onlyConfigAdmin {
        if (_fee == 0 || _fee > 500 * 10**6) revert InvalidFee();
        perConsultFeeUSDC = _fee;
        emit ConfigurationUpdated("perConsultFeeUSDC", _fee);
    }

    function setSubscriptionConsultsLimit(uint8 _limitBasic, uint8 _limitPremium) external onlyConfigAdmin {
        if (_limitBasic > 10 || _limitPremium > 20) revert InvalidLimit();
        subscriptionConsultsLimitBasic = _limitBasic;
        subscriptionConsultsLimitPremium = _limitPremium;
        emit ConfigurationUpdated("subscriptionConsultsLimitBasic", _limitBasic);
        emit ConfigurationUpdated("subscriptionConsultsLimitPremium", _limitPremium);
    }

    function syncPauseState() external onlyGovernance {
        bool newPaused = core.paused();
        if (newPaused != localPaused) {
            localPaused = newPaused;
            emit PauseStateSynced(newPaused);
        }
    }

    function isPaymentMethodSupported(ITelemedicinePayments.PaymentType paymentType) public view returns (bool) {
        return paymentProcessor.isPaymentMethodSupported(paymentType);
    }

    function getSubscriptionStatus(address patient) external view returns (bool isActive, uint256 expiry, uint256 consultsUsed, SubscriptionTier tier) {
        Subscription memory sub = subscriptions[patient];
        bool active = sub.isActive && block.timestamp < sub.expiry;
        return (active, sub.expiry, sub.consultsUsed, sub.tier);
    }

    function _checkAndChargeConsult(address patient) internal returns (bool) {
        Subscription storage sub = subscriptions[patient];
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

        uint256 discountedFee = core._applyFeeDiscount(patient, perConsultFeeUSDC);
        if (discountedFee == 0 || discountedFee > perConsultFeeUSDC) revert InvalidFee();
        paymentProcessor.processPayment(patient, discountedFee, ITelemedicinePayments.PaymentType.USDC);
        emit ConsultCharged(patient, discountedFee, "USDC");
        return false;
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyGovernance {}

    modifier onlyPatient() {
        if (!core.hasRole(core.PATIENT_ROLE(), msg.sender)) revert NotPatient();
        _;
    }

    modifier onlyConfigAdmin() {
        if (!paymentProcessor.isConfigAdmin(msg.sender)) revert NotAuthorized();
        _;
    }

    modifier onlyGovernance() {
        if (!paymentProcessor.isGovernanceApprover(msg.sender)) revert NotAuthorized();
        _;
    }

    modifier whenNotPaused() {
        if (localPaused) revert ContractPaused();
        _;
    }

    error InvalidAddress();
    error InvalidApprovalCount();
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
}
