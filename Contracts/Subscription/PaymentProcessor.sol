// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ReentrancyGuardUpgradeable} from "@open:
import {IERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import {SafeERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import {ITelemedicineCore} from "./Interfaces/ITelemedicineCore.sol";
import {ITelemedicinePayments} from "./Interfaces/ITelemedicinePayments.sol";

contract PaymentProcessor is Initializable, ReentrancyGuardUpgradeable {
    using SafeERC20Upgradeable for IERC20Upgradeable;

    ITelemedicineCore public immutable core;
    ITelemedicinePayments public immutable payments;

    uint256 public maxReserveWithdrawalPercentage;
    uint256 public maxUserBalance;
    uint256 public mediPointsDiscountRate;
    uint256 public minReserveFundThreshold;
    uint256 public maxDepositAmount;
    uint256 public maxMediPoints;
    uint256 public ethTransferGasLimit;
    uint256 public maxWeeklyMediPointsRedemption;
    uint256 public maxAggregateWithdrawalPercentage;

    mapping(ITelemedicinePayments.PaymentType => bool) public isPaymentMethodSupported;
    mapping(ITelemedicinePayments.PaymentType => uint8) public tokenDecimals;
    mapping(address => uint256) public userBalances;
    mapping(ITelemedicinePayments.PaymentType => uint256) public reserveFunds;
    mapping(address => uint256) public reserveFundUsage;
    mapping(ITelemedicinePayments.PaymentType => mapping(uint256 => uint256)) public weeklyMediPointsRedemption;

    struct PendingPayment {
        address recipient;
        uint256 amount;
        ITelemedicinePayments.PaymentType paymentType;
        bool processed;
        uint48 timestamp;
    }

    mapping(uint256 => PendingPayment) public pendingPayments;
    uint256 public pendingPaymentCounter;

    event PaymentQueued(uint256 indexed paymentId, address recipient, uint256 amount, ITelemedicinePayments.PaymentType paymentType);
    event PaymentReleasedFromQueue(uint256 indexed paymentId, address recipient, uint256 amount);
    event DepositReceived(address indexed sender, uint256 amount);
    event FeeAllocated(uint256 indexed operationId, uint256 reserveAmount, uint256 platformAmount, ITelemedicinePayments.PaymentType paymentType);
    event BalanceClaimed(address indexed user, uint256 amount);
    event BalanceUpdated(address indexed user, uint256 amount);
    event MediPointsRedeemed(address indexed patient, uint256 points, uint256 discount);
    event TokenAddressUpdated(ITelemedicinePayments.PaymentType paymentType, address newToken);
    event ReserveFundLowBalance(ITelemedicinePayments.PaymentType paymentType, uint256 balance);

    constructor() {
        _disableInitializers();
    }

    function initialize(address _core, address _payments) external initializer {
        if (_core == address(0) || _payments == address(0)) revert InvalidAddress();
        if (ITelemedicineCore(_core).version() < 1) revert InvalidCoreImplementation();
        if (ITelemedicinePayments(_payments).version() < 1) revert InvalidPaymentsImplementation();

        __ReentrancyGuard_init();

        core = ITelemedicineCore(_core);
        payments = ITelemedicinePayments(_payments);

        IERC20Upgradeable usdc = payments.usdcToken();
        IERC20Upgradeable sonic = payments.sonicToken();
        if (usdc.totalSupply() == 0 || sonic.totalSupply() == 0) revert InvalidToken();

        uint8 usdcDecimals = _getTokenDecimals(address(usdc));
        maxReserveWithdrawalPercentage = 10;
        maxUserBalance = 100 ether;
        mediPointsDiscountRate = 10 * 10**usdcDecimals;
        minReserveFundThreshold = 1000 * 10**usdcDecimals;
        maxDepositAmount = 10 ether;
        maxMediPoints = 1_000_000;
        ethTransferGasLimit = 21000;
        maxWeeklyMediPointsRedemption = 10000 * 10**usdcDecimals;
        maxAggregateWithdrawalPercentage = 30;

        tokenDecimals[ITelemedicinePayments.PaymentType.USDC] = usdcDecimals;
        tokenDecimals[ITelemedicinePayments.PaymentType.SONIC] = _getTokenDecimals(address(sonic));
        tokenDecimals[ITelemedicinePayments.PaymentType.ETH] = 18;

        isPaymentMethodSupported[ITelemedicinePayments.PaymentType.ETH] = true;
        isPaymentMethodSupported[ITelemedicinePayments.PaymentType.USDC] = true;
        isPaymentMethodSupported[ITelemedicinePayments.PaymentType.SONIC] = true;
    }

    function processSubscriptionPayment(
        address sender,
        uint256 amount,
        ITelemedicinePayments.PaymentType paymentType,
        uint256 duration
    ) external payable nonReentrant onlySubscriptionManager {
        uint256 reservePercentage = core.reserveFundPercentage();
        uint256 platformPercentage = core.platformFeePercentage();
        uint256 percentageDenominator = core.PERCENTAGE_DENOMINATOR();

        uint256 reserveAmount = (amount * reservePercentage) / percentageDenominator;
        uint256 platformAmount = (amount * platformPercentage) / percentageDenominator;

        _processPayment(sender, amount, paymentType);

        reserveFunds[paymentType] += reserveAmount;
        core.updateReserveFund(core.reserveFund() + reserveAmount);

        _checkReserveFundBalance(paymentType);
        emit FeeAllocated(0, reserveAmount, platformAmount, paymentType);
    }

    function processPayment(address sender, uint256 amount, ITelemedicinePayments.PaymentType paymentType) external payable nonReentrant onlySubscriptionManager {
        uint256 reservePercentage = core.reserveFundPercentage();
        uint256 platformPercentage = core.platformFeePercentage();
        uint256 percentageDenominator = core.PERCENTAGE_DENOMINATOR();

        uint256 reserveAmount = (amount * reservePercentage) / percentageDenominator;
        uint256 platformAmount = (amount * platformPercentage) / percentageDenominator;

        _processPayment(sender, amount, paymentType);

        reserveFunds[paymentType] += reserveAmount;
        core.updateReserveFund(core.reserveFund() + reserveAmount);

        _checkReserveFundBalance(paymentType);
        emit FeeAllocated(0, reserveAmount, platformAmount, paymentType);
    }

    function releasePayment(address to, uint256 amount, ITelemedicinePayments.PaymentType paymentType) external nonReentrant onlySubscriptionManager {
        _releasePayment(to, amount, paymentType);
    }

    function redeemMediPoints(address patient, uint256 points) external nonReentrant onlySubscriptionManager {
        ITelemedicineCore.GamificationData storage gamification = core.patients(patient).gamification;
        if (points > gamification.mediPoints) revert InsufficientPoints();
        uint256 discount = (points * mediPointsDiscountRate) / 1000;
        uint256 week = block.timestamp / 1 weeks;
        if (weeklyMediPointsRedemption[ITelemedicinePayments.PaymentType.USDC][week] + discount > maxWeeklyMediPointsRedemption)
            revert ExceedsRedemptionLimit();
        weeklyMediPointsRedemption[ITelemedicinePayments.PaymentType.USDC][week] += discount;
        gamification.mediPoints -= uint96(points);
        _releasePayment(patient, discount, ITelemedicinePayments.PaymentType.USDC);
        emit MediPointsRedeemed(patient, points, discount);
    }

    function estimateMediPointsDiscount(uint256 points) external view returns (uint256) {
        return (points * mediPointsDiscountRate) / 1000;
    }

    function deposit() external payable nonReentrant onlyPatient {
        if (msg.value > maxDepositAmount) revert ExceedsDepositLimit();
        if (userBalances[msg.sender] + msg.value > maxUserBalance) revert ExceedsBalanceLimit();
        userBalances[msg.sender] += msg.value;
        emit DepositReceived(msg.sender, msg.value);
        emit BalanceUpdated(msg.sender, userBalances[msg.sender]);
    }

    function claimBalance() external nonReentrant {
        uint256 amount = userBalances[msg.sender];
        if (amount == 0) revert InsufficientFunds();
        userBalances[msg.sender] = 0;
        _safeTransferETH(msg.sender, amount);
        emit BalanceClaimed(msg.sender, amount);
        emit BalanceUpdated(msg.sender, 0);
    }

    function getReserveFunds(ITelemedicinePayments.PaymentType paymentType) external view returns (uint256) {
        return reserveFunds[paymentType];
    }

    function _processPayment(address sender, uint256 amount, ITelemedicinePayments.PaymentType paymentType) internal {
        if (paymentType == ITelemedicinePayments.PaymentType.ETH) {
            if (msg.value < amount) revert InsufficientFunds();
            if (msg.value > amount) {
                uint256 refund = msg.value - amount;
                if (userBalances[sender] + refund > maxUserBalance) revert ExceedsBalanceLimit();
                userBalances[sender] += refund;
                emit BalanceUpdated(sender, userBalances[sender]);
            }
        } else if (paymentType == ITelemedicinePayments.PaymentType.USDC) {
            if (payments.usdcToken().allowance(sender, address(this)) < amount) revert InsufficientAllowance();
            payments.usdcToken().safeTransferFrom(sender, address(payments), amount);
        } else if (paymentType == ITelemedicinePayments.PaymentType.SONIC) {
            if (payments.sonicToken().allowance(sender, address(this)) < amount) revert InsufficientAllowance();
            payments.sonicToken().safeTransferFrom(sender, address(payments), amount);
        } else {
            revert InvalidPaymentType();
        }
    }

    function _releasePayment(address to, uint256 amount, ITelemedicinePayments.PaymentType paymentType) internal {
        if (!_hasSufficientFunds(amount, paymentType)) {
            if (pendingPaymentCounter >= 1_000_000) revert CounterOverflow();
            pendingPaymentCounter++;
            pendingPayments[pendingPaymentCounter] = PendingPayment(to, amount, paymentType, false, uint48(block.timestamp));
            emit PaymentQueued(pendingPaymentCounter, to, amount, paymentType);
            return;
        }

        if (paymentType == ITelemedicinePayments.PaymentType.ETH) {
            _safeTransferETH(to, amount);
        } else if (paymentType == ITelemedicinePayments.PaymentType.USDC) {
            payments.usdcToken().safeTransfer(to, amount);
        } else if (paymentType == ITelemedicinePayments.PaymentType.SONIC) {
            payments.sonicToken().safeTransfer(to, amount);
        }
    }

    function _hasSufficientFunds(uint256 amount, ITelemedicinePayments.PaymentType paymentType) internal view returns (bool) {
        if (paymentType == ITelemedicinePayments.PaymentType.ETH) {
            return address(this).balance >= amount;
        } else if (paymentType == ITelemedicinePayments.PaymentType.USDC) {
            return payments.usdcToken().balanceOf(address(this)) >= amount;
        } else if (paymentType == ITelemedicinePayments.PaymentType.SONIC) {
            return payments.sonicToken().balanceOf(address(this)) >= amount;
        }
        return false;
    }

    function _safeTransferETH(address to, uint256 amount) internal {
        (bool success, ) = to.call{value: amount, gas: ethTransferGasLimit}("");
        if (!success) revert PaymentFailed();
    }

    function _checkReserveFundBalance(ITelemedicinePayments.PaymentType paymentType) internal {
        if (reserveFunds[paymentType] < minReserveFundThreshold) {
            emit ReserveFundLowBalance(paymentType, reserveFunds[paymentType]);
        }
    }

    function _getTokenDecimals(address token) internal view returns (uint8) {
        (bool success, bytes memory data) = token.staticcall(abi.encodeWithSignature("decimals()"));
        if (!success) revert InvalidToken();
        return abi.decode(data, (uint8));
    }

    function getCurrency(ITelemedicinePayments.PaymentType paymentType) external pure returns (string memory) {
        if (paymentType == ITelemedicinePayments.PaymentType.ETH) return "ETH";
        if (paymentType == ITelemedicinePayments.PaymentType.USDC) return "USDC";
        return "SONIC";
    }

    function isConfigAdmin(address account) external view returns (bool) {
        return false; // GovernanceManager handles this
    }

    function isGovernanceApprover(address account) external view returns (bool) {
        return false; // GovernanceManager handles this
    }

    function maxMediPoints() external view returns (uint256) {
        return maxMediPoints;
    }

    modifier onlySubscriptionManager() {
        // Add check for SubscriptionManager address
        _;
    }

    modifier onlyPatient() {
        if (!core.hasRole(core.PATIENT_ROLE(), msg.sender)) revert NotPatient();
        _;
    }

    error InvalidAddress();
    error InvalidToken();
    error InsufficientFunds();
    error InsufficientAllowance();
    error ExceedsBalanceLimit();
    error InsufficientPoints();
    error InvalidPaymentType();
    error PaymentFailed();
    error ExceedsDepositLimit();
    error InvalidCoreImplementation();
    error InvalidPaymentsImplementation();
    error CounterOverflow();
    error NotPatient();
    error ExceedsRedemptionLimit();
}
