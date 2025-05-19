// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {IERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import {SafeERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import {ITelemedicineCore} from "./Interfaces/ITelemedicineCore.sol";
import {ITelemedicinePayments} from "./Interfaces/ITelemedicinePayments.sol";

/// @title PaymentProcessor
/// @notice Handles payment processing, MediPoints redemption, and user balance management
/// @dev UUPS upgradeable, integrates with TelemedicineCore and TelemedicinePayments
contract PaymentProcessor is Initializable, UUPSUpgradeable, ReentrancyGuardUpgradeable {
    using SafeERC20Upgradeable for IERC20Upgradeable;

    // Custom Errors
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
    error NotPatient();
    error ExceedsRedemptionLimit();
    error NotAuthorized();
    error InvalidConfiguration();
    error ExternalCallFailed();

    // Constants
    uint256 public constant MIN_RESERVE_WITHDRAWAL_PERCENTAGE = 1; // New: 1% minimum
    uint256 public constant MIN_AGGREGATE_WITHDRAWAL_PERCENTAGE = 5; // New: 5% minimum
    uint256 public constant MIN_DISCOUNT_RATE = 1 * 10**6; // New: 1 USDC per 1000 points
    uint256 public constant ETH_TRANSFER_GAS_LIMIT = 30000; // New: Fixed 30,000 gas

    // State Variables
    ITelemedicineCore public immutable core;
    ITelemedicinePayments public immutable payments;
    address public subscriptionManager; // New: Explicit SubscriptionManager address
    uint256 public maxReserveWithdrawalPercentage;
    uint256 public maxUserBalance;
    uint256 public mediPointsDiscountRate;
    uint256 public minReserveFundThreshold;
    uint256 public maxDepositAmount;
    uint256 public maxMediPoints;
    uint256 public maxWeeklyMediPointsRedemption;
    uint256 public maxAggregateWithdrawalPercentage;
    uint256 public versionNumber; // New: Track contract version
    uint256 public supportedPaymentMethods; // New: Bitmap for payment methods

    // Mappings
    mapping(ITelemedicinePayments.PaymentType => uint8) public tokenDecimals;
    mapping(address => uint256) public userBalances;
    mapping(ITelemedicinePayments.PaymentType => uint256) public reserveFunds;
    mapping(address => uint256) public reserveFundUsage;
    mapping(ITelemedicinePayments.PaymentType => mapping(uint256 => uint256)) public weeklyMediPointsRedemption;

    // Structs
    struct PendingPayment {
        address recipient;
        uint256 amount;
        ITelemedicinePayments.PaymentType paymentType;
        bool processed;
    }

    // Storage
    mapping(uint256 => PendingPayment) public pendingPayments;
    uint256 public pendingPaymentCounter;

    // Events
    event PaymentQueued(uint256 indexed paymentId, address recipient, uint256 amount, ITelemedicinePayments.PaymentType paymentType);
    event PaymentReleasedFromQueue(uint256 indexed paymentId, address recipient, uint256 amount);
    event DepositReceived(address indexed sender, uint256 amount);
    event ReserveFundAllocated(uint256 indexed operationId, uint256 amount, ITelemedicinePayments.PaymentType paymentType); // Updated: Consistent naming
    event PlatformFeeAllocated(uint256 indexed operationId, uint256 amount, ITelemedicinePayments.PaymentType paymentType); // Updated: Consistent naming
    event BalanceClaimed(address indexed user, uint256 amount);
    event BalanceUpdated(address indexed user, uint256 amount);
    event MediPointsRedeemed(address indexed patient, uint256 points, uint256 discount);
    event TokenAddressUpdated(ITelemedicinePayments.PaymentType paymentType, address newToken);
    event ReserveFundLowBalance(ITelemedicinePayments.PaymentType paymentType, uint256 balance);
    event ConfigurationUpdated(string indexed parameter, uint256 value);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the contract with core and payments addresses
    /// @param _core Address of TelemedicineCore
    /// @param _payments Address of TelemedicinePayments
    /// @param _subscriptionManager Address of TelemedicineSubscription
    function initialize(address _core, address _payments, address _subscriptionManager) external initializer {
        if (_core == address(0) || _payments == address(0) || _subscriptionManager == address(0)) revert InvalidAddress();

        // Updated: Try-catch for version checks
        try ITelemedicineCore(_core).version() returns (uint256 coreVersion) {
            if (coreVersion < 1) revert InvalidCoreImplementation();
        } catch {
            revert InvalidCoreImplementation();
        }
        try ITelemedicinePayments(_payments).version() returns (uint256 paymentsVersion) {
            if (paymentsVersion < 1) revert InvalidPaymentsImplementation();
        } catch {
            revert InvalidPaymentsImplementation();
        }

        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();

        core = ITelemedicineCore(_core);
        payments = ITelemedicinePayments(_payments);
        subscriptionManager = _subscriptionManager;

        IERC20Upgradeable usdc = payments.usdcToken();
        IERC20Upgradeable sonic = payments.sonicToken();
        if (address(usdc) == address(0) || address(sonic) == address(0)) revert InvalidToken();

        uint8 usdcDecimals = _getTokenDecimals(address(usdc));
        maxReserveWithdrawalPercentage = 10;
        maxUserBalance = 10 ether; // Updated: Lowered to 10 ETH
        mediPointsDiscountRate = 10 * 10**usdcDecimals;
        minReserveFundThreshold = 1000 * 10**usdcDecimals;
        maxDepositAmount = 1 ether; // Updated: Lowered to 1 ETH
        maxMediPoints = 1_000_000;
        maxWeeklyMediPointsRedemption = 10000 * 10**usdcDecimals;
        maxAggregateWithdrawalPercentage = 30;
        versionNumber = 1;

        tokenDecimals[ITelemedicinePayments.PaymentType.USDC] = usdcDecimals;
        tokenDecimals[ITelemedicinePayments.PaymentType.SONIC] = _getTokenDecimals(address(sonic));
        tokenDecimals[ITelemedicinePayments.PaymentType.ETH] = 18;

        // Updated: Initialize payment methods bitmap
        supportedPaymentMethods = (1 << uint256(ITelemedicinePayments.PaymentType.ETH)) |
                                 (1 << uint256(ITelemedicinePayments.PaymentType.USDC)) |
                                 (1 << uint256(ITelemedicinePayments.PaymentType.SONIC));
    }

    /// @notice Authorizes contract upgrades
    /// @param newImplementation New implementation address
    function _authorizeUpgrade(address newImplementation) internal override onlyConfigAdmin {
        if (!_isContract(newImplementation)) revert InvalidAddress();
        versionNumber++;
    }

    /// @notice Processes a subscription payment
    /// @param sender Sender address
    /// @param amount Payment amount
    /// @param paymentType Payment type (ETH, USDC, SONIC)
    /// @param duration Subscription duration (unused)
    function processSubscriptionPayment(
        address sender,
        uint256 amount,
        ITelemedicinePayments.PaymentType paymentType,
        uint256 duration
    ) external payable nonReentrant onlySubscriptionManager {
        // Updated: Cache core parameters
        uint256 reservePercentage = core.reserveFundPercentage();
        uint256 platformPercentage = core.platformFeePercentage();
        uint256 percentageDenominator = core.PERCENTAGE_DENOMINATOR();

        uint256 reserveAmount = (amount * reservePercentage) / percentageDenominator;
        uint256 platformAmount = (amount * platformPercentage) / percentageDenominator;

        // Updated: Try-catch for payment processing
        try this._processPayment(sender, amount, paymentType) {
            reserveFunds[paymentType] += reserveAmount;
            // Updated: Try-catch for reserve fund update
            try core.updateReserveFund(core.reserveFund() + reserveAmount) {
                _checkReserveFundBalance(paymentType);
                emit ReserveFundAllocated(0, reserveAmount, paymentType);
                emit PlatformFeeAllocated(0, platformAmount, paymentType);
            } catch {
                revert ExternalCallFailed();
            }
        } catch {
            revert ExternalCallFailed();
        }
    }

    /// @notice Processes a consultation payment
    /// @param sender Sender address
    /// @param amount Payment amount
    /// @param paymentType Payment type (ETH, USDC, SONIC)
    function processPayment(address sender, uint256 amount, ITelemedicinePayments.PaymentType paymentType) 
        external payable nonReentrant onlySubscriptionManager 
    {
        uint256 reservePercentage = core.reserveFundPercentage();
        uint256 platformPercentage = core.platformFeePercentage();
        uint256 percentageDenominator = core.PERCENTAGE_DENOMINATOR();

        uint256 reserveAmount = (amount * reservePercentage) / percentageDenominator;
        uint256 platformAmount = (amount * platformPercentage) / percentageDenominator;

        try this._processPayment(sender, amount, paymentType) {
            reserveFunds[paymentType] += reserveAmount;
            try core.updateReserveFund(core.reserveFund() + reserveAmount) {
                _checkReserveFundBalance(paymentType);
                emit ReserveFundAllocated(0, reserveAmount, paymentType);
                emit PlatformFeeAllocated(0, platformAmount, paymentType);
            } catch {
                revert ExternalCallFailed();
            }
        } catch {
            revert ExternalCallFailed();
        }
    }

    /// @notice Releases a payment to a recipient
    /// @param to Recipient address
    /// @param amount Amount to release
    /// @param paymentType Payment type (ETH, USDC, SONIC)
    function releasePayment(address to, uint256 amount, ITelemedicinePayments.PaymentType paymentType) 
        external nonReentrant onlySubscriptionManager 
    {
        _releasePayment(to, amount, paymentType);
    }

    /// @notice Redeems MediPoints for a discount
    /// @param patient Patient address
    /// @param points Points to redeem
    function redeemMediPoints(address patient, uint256 points) external nonReentrant onlySubscriptionManager {
        // Updated: Try-catch for gamification access
        try core.patients(patient) returns (ITelemedicineCore.Patient memory patientData) {
            ITelemedicineCore.GamificationData storage gamification = patientData.gamification;
            if (points > gamification.mediPoints) revert InsufficientPoints();
            uint256 discount = (points * mediPointsDiscountRate) / 1000;
            uint256 week = block.timestamp / 1 weeks;
            if (weeklyMediPointsRedemption[ITelemedicinePayments.PaymentType.USDC][week] + discount > maxWeeklyMediPointsRedemption)
                revert ExceedsRedemptionLimit();

            weeklyMediPointsRedemption[ITelemedicinePayments.PaymentType.USDC][week] += discount;
            gamification.mediPoints -= uint96(points);
            _releasePayment(patient, discount, ITelemedicinePayments.PaymentType.USDC);
            emit MediPointsRedeemed(patient, points, discount);
        } catch {
            revert ExternalCallFailed();
        }
    }

    /// @notice Processes pending payments in batch
    /// @param paymentIds Array of payment IDs
    function processPendingPayments(uint256[] calldata paymentIds) external nonReentrant onlySubscriptionManager {
        for (uint256 i = 0; i < paymentIds.length; i++) {
            PendingPayment storage payment = pendingPayments[paymentIds[i]];
            if (payment.recipient == address(0) || payment.processed) continue;
            if (_hasSufficientFunds(payment.amount, payment.paymentType)) {
                payment.processed = true;
                if (payment.paymentType == ITelemedicinePayments.PaymentType.ETH) {
                    _safeTransferETH(payment.recipient, payment.amount);
                } else if (payment.paymentType == ITelemedicinePayments.PaymentType.USDC) {
                    payments.usdcToken().safeTransfer(payment.recipient, payment.amount);
                } else if (payment.paymentType == ITelemedicinePayments.PaymentType.SONIC) {
                    payments.sonicToken().safeTransfer(payment.recipient, payment.amount);
                }
                emit PaymentReleasedFromQueue(paymentIds[i], payment.recipient, payment.amount);
            }
        }
    }

    /// @notice Estimates MediPoints discount
    /// @param points Points to redeem
    /// @return Discount amount
    function estimateMediPointsDiscount(uint256 points) external view returns (uint256) {
        return (points * mediPointsDiscountRate) / 1000;
    }

    /// @notice Deposits ETH into user balance
    function deposit() external payable nonReentrant onlyPatient {
        if (msg.value > maxDepositAmount) revert ExceedsDepositLimit();
        if (userBalances[msg.sender] + msg.value > maxUserBalance) revert ExceedsBalanceLimit();
        userBalances[msg.sender] += msg.value;
        emit DepositReceived(msg.sender, msg.value);
        emit BalanceUpdated(msg.sender, userBalances[msg.sender]);
    }

    /// @notice Claims user balance
    function claimBalance() external nonReentrant {
        uint256 amount = userBalances[msg.sender];
        if (amount == 0) revert InsufficientFunds();
        userBalances[msg.sender] = 0;
        _safeTransferETH(msg.sender, amount);
        emit BalanceClaimed(msg.sender, amount);
        emit BalanceUpdated(msg.sender, 0);
    }

    /// @notice Gets reserve funds for a payment type
    /// @param paymentType Payment type (ETH, USDC, SONIC)
    /// @return Reserve funds amount
    function getReserveFunds(ITelemedicinePayments.PaymentType paymentType) external view returns (uint256) {
        return reserveFunds[paymentType];
    }

    /// @notice Updates payment method support
    /// @param paymentType Payment type (ETH, USDC, SONIC)
    /// @param enabled True to enable, false to disable
    function updatePaymentMethod(ITelemedicinePayments.PaymentType paymentType, bool enabled) external onlyConfigAdmin {
        uint256 bit = 1 << uint256(paymentType);
        bool isCurrentlyEnabled = (supportedPaymentMethods & bit) != 0;
        if (isCurrentlyEnabled == enabled) revert InvalidConfiguration();

        if (enabled) {
            supportedPaymentMethods |= bit;
        } else {
            supportedPaymentMethods &= ~bit;
        }
        emit PaymentMethodUpdated(paymentType, enabled);
    }

    /// @notice Updates token address and decimals
    /// @param paymentType Payment type (USDC, SONIC)
    /// @param newToken New token address
    function setTokenAddress(ITelemedicinePayments.PaymentType paymentType, address newToken) external onlyConfigAdmin {
        if (newToken == address(0)) revert InvalidAddress();
        if (paymentType != ITelemedicinePayments.PaymentType.USDC && paymentType != ITelemedicinePayments.PaymentType.SONIC) 
            revert InvalidPaymentType();
        uint8 decimals = _getTokenDecimals(newToken);
        tokenDecimals[paymentType] = decimals;
        emit TokenAddressUpdated(paymentType, newToken);
    }

    /// @notice Updates configuration parameters
    /// @param parameter Parameter name
    /// @param value New value
    function updateConfiguration(string memory parameter, uint256 value) external onlyConfigAdmin {
        if (keccak256(abi.encodePacked(parameter)) == keccak256(abi.encodePacked("maxReserveWithdrawalPercentage"))) {
            if (value < MIN_RESERVE_WITHDRAWAL_PERCENTAGE) revert InvalidConfiguration();
            maxReserveWithdrawalPercentage = value;
        } else if (keccak256(abi.encodePacked(parameter)) == keccak256(abi.encodePacked("maxUserBalance"))) {
            if (value < 1 ether) revert InvalidConfiguration();
            maxUserBalance = value;
        } else if (keccak256(abi.encodePacked(parameter)) == keccak256(abi.encodePacked("mediPointsDiscountRate"))) {
            if (value < MIN_DISCOUNT_RATE) revert InvalidConfiguration();
            mediPointsDiscountRate = value;
        } else if (keccak256(abi.encodePacked(parameter)) == keccak256(abi.encodePacked("minReserveFundThreshold"))) {
            if (value < 100 * 10**tokenDecimals[ITelemedicinePayments.PaymentType.USDC]) revert InvalidConfiguration();
            minReserveFundThreshold = value;
        } else if (keccak256(abi.encodePacked(parameter)) == keccak256(abi.encodePacked("maxDepositAmount"))) {
            if (value < 0.1 ether) revert InvalidConfiguration();
            maxDepositAmount = value;
        } else if (keccak256(abi.encodePacked(parameter)) == keccak256(abi.encodePacked("maxWeeklyMediPointsRedemption"))) {
            if (value < 1000 * 10**tokenDecimals[ITelemedicinePayments.PaymentType.USDC]) revert InvalidConfiguration();
            maxWeeklyMediPointsRedemption = value;
        } else if (keccak256(abi.encodePacked(parameter)) == keccak256(abi.encodePacked("maxAggregateWithdrawalPercentage"))) {
            if (value < MIN_AGGREGATE_WITHDRAWAL_PERCENTAGE) revert InvalidConfiguration();
            maxAggregateWithdrawalPercentage = value;
        } else {
            revert InvalidConfiguration();
        }
        emit ConfigurationUpdated(parameter, value);
    }

    /// @dev Processes a payment
    /// @param sender Sender address
    /// @param amount Payment amount
    /// @param paymentType Payment type (ETH, USDC, SONIC)
    function _processPayment(address sender, uint256 amount, ITelemedicinePayments.PaymentType paymentType) internal {
        if (!_isPaymentMethodSupported(paymentType)) revert InvalidPaymentType();
        if (paymentType == ITelemedicinePayments.PaymentType.ETH) {
            if (msg.value < amount) revert InsufficientFunds();
            if (msg.value > amount) {
                uint256 refund = msg.value - amount;
                if (userBalances[sender] + refund > maxUserBalance) revert ExceedsBalanceLimit();
                userBalances[sender] += refund;
                emit BalanceUpdated(sender, userBalances[sender]);
            }
        } else if (paymentType == ITelemedicinePayments.PaymentType.USDC) {
            try payments.usdcToken() returns (IERC20Upgradeable usdc) {
                if (usdc.allowance(sender, address(this)) < amount) revert InsufficientAllowance();
                usdc.safeTransferFrom(sender, address(payments), amount);
            } catch {
                revert ExternalCallFailed();
            }
        } else if (paymentType == ITelemedicinePayments.PaymentType.SONIC) {
            try payments.sonicToken() returns (IERC20Upgradeable sonic) {
                if (sonic.allowance(sender, address(this)) < amount) revert InsufficientAllowance();
                sonic.safeTransferFrom(sender, address(payments), amount);
            } catch {
                revert ExternalCallFailed();
            }
        } else {
            revert InvalidPaymentType();
        }
    }

    /// @dev Releases a payment to a recipient
    /// @param to Recipient address
    /// @param amount Amount to release
    /// @param paymentType Payment type (ETH, USDC, SONIC)
    function _releasePayment(address to, uint256 amount, ITelemedicinePayments.PaymentType paymentType) internal {
        // Updated: Validate reserve funds against actual balance
        if (!_hasSufficientFunds(amount, paymentType)) {
            pendingPaymentCounter++;
            pendingPayments[pendingPaymentCounter] = PendingPayment(to, amount, paymentType, false);
            emit PaymentQueued(pendingPaymentCounter, to, amount, paymentType);
            return;
        }

        reserveFunds[paymentType] -= amount;
        if (paymentType == ITelemedicinePayments.PaymentType.ETH) {
            _safeTransferETH(to, amount);
        } else if (paymentType == ITelemedicinePayments.PaymentType.USDC) {
            try payments.usdcToken() returns (IERC20Upgradeable usdc) {
                usdc.safeTransfer(to, amount);
            } catch {
                revert ExternalCallFailed();
            }
        } else if (paymentType == ITelemedicinePayments.PaymentType.SONIC) {
            try payments.sonicToken() returns (IERC20Upgradeable sonic) {
                sonic.safeTransfer(to, amount);
            } catch {
                revert ExternalCallFailed();
            }
        }
        _checkReserveFundBalance(paymentType);
    }

    /// @dev Checks if sufficient funds are available
    /// @param amount Amount to check
    /// @param paymentType Payment type (ETH, USDC, SONIC)
    /// @return True if sufficient funds
    function _hasSufficientFunds(uint256 amount, ITelemedicinePayments.PaymentType paymentType) internal view returns (bool) {
        if (paymentType == ITelemedicinePayments.PaymentType.ETH) {
            return address(this).balance >= amount && reserveFunds[paymentType] >= amount;
        } else if (paymentType == ITelemedicinePayments.PaymentType.USDC) {
            try payments.usdcToken() returns (IERC20Upgradeable usdc) {
                return usdc.balanceOf(address(this)) >= amount && reserveFunds[paymentType] >= amount;
            } catch {
                return false;
            }
        } else if (paymentType == ITelemedicinePayments.PaymentType.SONIC) {
            try payments.sonicToken() returns (IERC20Upgradeable sonic) {
                return sonic.balanceOf(address(this)) >= amount && reserveFunds[paymentType] >= amount;
            } catch {
                return false;
            }
        }
        return false;
    }

    /// @dev Safely transfers ETH
    /// @param to Recipient address
    /// @param amount Amount to transfer
    function _safeTransferETH(address to, uint256 amount) internal {
        // Updated: Fixed gas limit
        (bool success, ) = to.call{value: amount, gas: ETH_TRANSFER_GAS_LIMIT}("");
        if (!success) revert PaymentFailed();
    }

    /// @dev Checks reserve fund balance
    /// @param paymentType Payment type (ETH, USDC, SONIC)
    function _checkReserveFundBalance(ITelemedicinePayments.PaymentType paymentType) internal {
        if (reserveFunds[paymentType] < minReserveFundThreshold) {
            emit ReserveFundLowBalance(paymentType, reserveFunds[paymentType]);
        }
    }

    /// @dev Gets token decimals
    /// @param token Token address
    /// @return Decimals of the token
    function _getTokenDecimals(address token) internal view returns (uint8) {
        try IERC20Upgradeable(token).decimals() returns (uint8 decimals) {
            return decimals;
        } catch {
            revert InvalidToken();
        }
    }

    /// @dev Checks if a payment method is supported
    /// @param paymentType Payment type to check
    /// @return True if supported
    function _isPaymentMethodSupported(ITelemedicinePayments.PaymentType paymentType) internal view returns (bool) {
        return (supportedPaymentMethods & (1 << uint256(paymentType))) != 0;
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

    /// @notice Checks if an account is a config admin
    /// @param account Account to check
    /// @return True if config admin
    function isConfigAdmin(address account) external view returns (bool) {
        // Updated: Delegate to GovernanceManager
        try core.isConfigAdmin(account) returns (bool isAdmin) {
            return isAdmin;
        } catch {
            return false;
        }
    }

    /// @notice Checks if an account is a governance approver
    /// @param account Account to check
    /// @return True if governance approver
    function isGovernanceApprover(address account) external view returns (bool) {
        try core.isGovernanceApprover(account) returns (bool isApprover) {
            return isApprover;
        } catch {
            return false;
        }
    }

    /// @notice Gets the maximum MediPoints
    /// @return Maximum MediPoints
    function maxMediPoints() external view returns (uint256) {
        return maxMediPoints;
    }

    /// @notice Gets the currency for a payment type
    /// @param paymentType Payment type (ETH, USDC, SONIC)
    /// @return Payment type enum
    function getCurrency(ITelemedicinePayments.PaymentType paymentType) external pure returns (ITelemedicinePayments.PaymentType) {
        return paymentType;
    }

    // Modifiers

    /// @notice Restricts to SubscriptionManager
    modifier onlySubscriptionManager() {
        if (msg.sender != subscriptionManager) revert NotAuthorized();
        _;
    }

    /// @notice Restricts to patients
    modifier onlyPatient() {
        // Updated: Try-catch for role check
        try core.hasRole(core.PATIENT_ROLE(), msg.sender) returns (bool hasRole) {
            if (!hasRole) revert NotPatient();
            _;
        } catch {
            revert ExternalCallFailed();
        }
    }

    /// @notice Restricts to config admins
    modifier onlyConfigAdmin() {
        try core.isConfigAdmin(msg.sender) returns (bool isAdmin) {
            if (!isAdmin) revert NotAuthorized();
            _;
        } catch {
            revert ExternalCallFailed();
        }
    }

    // Fallback to receive ETH
    receive() external payable {
        if (msg.sender != subscriptionManager && !core.hasRole(core.PATIENT_ROLE(), msg.sender)) revert NotAuthorized();
        deposit();
    }

    // New: Storage gap for future upgrades
    uint256[50] private __gap;
}
