// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {TelemedicineCore} from "./TelemedicineCore.sol";
import {TelemedicinePayments} from "./TelemedicinePayments.sol";
import {TelemedicineSubscription} from "./TelemedicineSubscription.sol";

/// @title SimplePaymaster
/// @notice A paymaster contract for sponsoring gas costs in ERC-4337 UserOps on Sonic Blockchain
/// @dev Supports ETH, USDC, and SONIC tokens; ensure TelemedicineCore, Payments, and Subscription are deployed on Sonic
contract SimplePaymaster is Initializable, ReentrancyGuardUpgradeable {
    /// @notice Reference to the TelemedicineCore contract for role and gamification checks
    TelemedicineCore public core;
    /// @notice Reference to the TelemedicinePayments contract for token management
    TelemedicinePayments public payments;
    /// @notice Reference to the TelemedicineSubscription contract for subscription status
    TelemedicineSubscription public subscription;

    /// @notice Supported sponsor types for gas cost
    enum SponsorType { ETH, USDC, SONIC }
    /// @notice Tracks total gas sponsored per user
    mapping(address => uint256) public sponsoredGasCosts;

    /// @notice Emitted when the paymaster is funded
    event PaymasterFunded(address indexed funder, uint256 amount, SponsorType sponsorType);
    /// @notice Emitted when gas is sponsored for a UserOp
    event GasSponsored(address indexed sender, uint256 amount, SponsorType sponsorType);
    /// @notice Emitted when funds are withdrawn
    event FundsWithdrawn(address indexed to, uint256 amount, SponsorType sponsorType);

    /// @notice Structure for ERC-4337 UserOperation
    struct UserOperation {
        address sender;
        uint256 nonce;
        bytes initCode;
        bytes callData;
        uint256 callGasLimit;
        uint256 verificationGasLimit;
        uint256 preVerificationGas;
        uint256 maxFeePerGas;
        uint256 maxPriorityFeePerGas;
        bytes paymasterAndData;
        bytes signature;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the paymaster with core, payments, and subscription contracts
    /// @param _core Address of the TelemedicineCore contract
    /// @param _payments Address of the TelemedicinePayments contract
    /// @param _subscription Address of the TelemedicineSubscription contract
    function initialize(address _core, address _payments, address _subscription) external initializer {
        if (_core == address(0)) revert SimplePaymaster__InvalidCoreAddress();
        if (_payments == address(0)) revert SimplePaymaster__InvalidPaymentsAddress();
        if (_subscription == address(0)) revert SimplePaymaster__InvalidSubscriptionAddress();

        __ReentrancyGuard_init();
        core = TelemedicineCore(_core);
        payments = TelemedicinePayments(_payments);
        subscription = TelemedicineSubscription(_subscription);
    }

    /// @notice Funds the paymaster with ETH, USDC, or SONIC
    /// @param _sponsorType Type of funds (ETH, USDC, SONIC)
    /// @param _amount Amount to deposit
    function deposit(SponsorType _sponsorType, uint256 _amount) external payable {
        if (_amount == 0) revert SimplePaymaster__InvalidDepositAmount();
        _validateSponsorType(_sponsorType);

        if (_sponsorType == SponsorType.ETH) {
            if (msg.value != _amount) revert SimplePaymaster__ETHAmountMismatch();
        } else if (_sponsorType == SponsorType.USDC) {
            if (msg.value != 0) revert SimplePaymaster__NoETHForUSDCDdeposit();
            if (!payments.usdcToken().transferFrom(msg.sender, address(this), _amount))
                revert SimplePaymaster__USDCTransferFailed();
        } else {
            if (msg.value != 0) revert SimplePaymaster__NoETHForSONICDeposit();
            if (!payments.sonicToken().transferFrom(msg.sender, address(this), _amount))
                revert SimplePaymaster__SONICTransferFailed();
        }

        emit PaymasterFunded(msg.sender, _amount, _sponsorType);
    }

    /// @notice Withdraws funds (admin only)
    /// @param to Recipient address
    /// @param amount Amount to withdraw
    /// @param _sponsorType Type of funds (ETH, USDC, SONIC)
    function withdraw(address payable to, uint256 amount, SponsorType _sponsorType) external onlyRole(core.ADMIN_ROLE()) nonReentrant {
        if (to == address(0)) revert SimplePaymaster__InvalidRecipientAddress();
        _validateSponsorType(_sponsorType);

        if (_sponsorType == SponsorType.ETH) {
            if (address(this).balance < amount) revert SimplePaymaster__InsufficientETHBalance();
            (bool success, ) = to.call{value: amount}("");
            if (!success) revert SimplePaymaster__ETHWithdrawalFailed();
        } else if (_sponsorType == SponsorType.USDC) {
            if (payments.usdcToken().balanceOf(address(this)) < amount) revert SimplePaymaster__InsufficientUSDCBalance();
            if (!payments.usdcToken().transfer(to, amount)) revert SimplePaymaster__USDCWithdrawalFailed();
        } else {
            if (payments.sonicToken().balanceOf(address(this)) < amount) revert SimplePaymaster__InsufficientSONICBalance();
            if (!payments.sonicToken().transfer(to, amount)) revert SimplePaymaster__SONICWithdrawalFailed();
        }

        emit FundsWithdrawn(to, amount, _sponsorType);
    }

    /// @notice Validates a UserOp for gas sponsorship
    /// @param userOp The UserOperation to validate
    /// @param maxCost Maximum gas cost to sponsor
    /// @return validationData Validation result (0 for valid)
    /// @return context Data to pass to postOp (sender, sponsorType)
    function validatePaymasterUserOp(
        UserOperation calldata userOp,
        bytes32 /* userOpHash */,
        uint256 maxCost
    ) external view returns (uint256 validationData, bytes memory context) {
        if (msg.sender != address(core)) revert SimplePaymaster__OnlyCoreAllowed();
        if (!core.hasRole(core.PATIENT_ROLE(), userOp.sender)) revert SimplePaymaster__SenderNotPatient();

        // Check gamification level
        (bool success, bytes memory result) = address(core).staticcall(
            abi.encodeWithSignature("getPatientLevel(address)", userOp.sender)
        );
        if (!success || abi.decode(result, (uint8)) == 0) revert SimplePaymaster__PatientLevelTooLow();

        // Check subscription status
        (bool isActive, , ) = subscription.getSubscriptionStatus(userOp.sender);
        if (!isActive) revert SimplePaymaster__SubscriptionNotActive();

        // Decode sponsor type
        if (userOp.paymasterAndData.length < 21) revert SimplePaymaster__InvalidPaymasterData();
        SponsorType sponsorType = SponsorType(uint8(userOp.paymasterAndData[20]));
        _validateSponsorType(sponsorType);

        // Validate funds
        if (sponsorType == SponsorType.ETH) {
            if (address(this).balance < maxCost) revert SimplePaymaster__InsufficientETHFunds();
        } else if (sponsorType == SponsorType.USDC) {
            if (payments.usdcToken().balanceOf(address(this)) < maxCost) revert SimplePaymaster__InsufficientUSDCFunds();
        } else {
            if (payments.sonicToken().balanceOf(address(this)) < maxCost) revert SimplePaymaster__InsufficientSONICFunds();
        }

        return (0, abi.encode(userOp.sender, sponsorType));
    }

    /// @notice Handles post-operation gas cost accounting
    /// @param mode PostOp mode (0 for success)
    /// @param context Data from validatePaymasterUserOp (sender, sponsorType)
    /// @param actualGasCost Actual gas cost incurred
    function postOp(
        uint8 mode,
        bytes calldata context,
        uint256 actualGasCost
    ) external nonReentrant {
        if (msg.sender != address(core)) revert SimplePaymaster__OnlyCoreAllowed();
        if (mode != 0) return;

        (address sender, SponsorType sponsorType) = abi.decode(context, (address, SponsorType));
        _validateSponsorType(sponsorType);

        if (sponsorType == SponsorType.ETH) {
            if (address(this).balance < actualGasCost) revert SimplePaymaster__InsufficientETHPostOp();
        } else if (sponsorType == SponsorType.USDC) {
            if (payments.usdcToken().balanceOf(address(this)) < actualGasCost) revert SimplePaymaster__InsufficientUSDCPostOp();
            if (!payments.usdcToken().transfer(address(payments), actualGasCost)) revert SimplePaymaster__USDCTransferFailed();
        } else {
            if (payments.sonicToken().balanceOf(address(this)) < actualGasCost) revert SimplePaymaster__InsufficientSONICPostOp();
            if (!payments.sonicToken().transfer(address(payments), actualGasCost)) revert SimplePaymaster__SONICTransferFailed();
        }

        sponsoredGasCosts[sender] += actualGasCost;
        emit GasSponsored(sender, actualGasCost, sponsorType);
    }

    /// @notice Returns the balance for a sponsor type
    /// @param _sponsorType Type of funds (ETH, USDC, SONIC)
    /// @return Balance amount
    function getBalance(SponsorType _sponsorType) external view returns (uint256) {
        _validateSponsorType(_sponsorType);
        if (_sponsorType == SponsorType.ETH) return address(this).balance;
        if (_sponsorType == SponsorType.USDC) return payments.usdcToken().balanceOf(address(this));
        return payments.sonicToken().balanceOf(address(this));
    }

    /// @notice Receives ETH deposits and emits an event
    receive() external payable {
        emit PaymasterFunded(msg.sender, msg.value, SponsorType.ETH);
    }

    /// @notice Restricts access to a specific role
    modifier onlyRole(bytes32 role) {
        if (!core.hasRole(role, msg.sender)) revert SimplePaymaster__Unauthorized();
        _;
    }

    /// @notice Validates the sponsor type
    /// @param _sponsorType Type to validate
    function _validateSponsorType(SponsorType _sponsorType) private pure {
        if (uint8(_sponsorType) > uint8(SponsorType.SONIC)) revert SimplePaymaster__InvalidSponsorType();
    }
}

/// @notice Custom errors for SimplePaymaster
error SimplePaymaster__InvalidCoreAddress();
error SimplePaymaster__InvalidPaymentsAddress();
error SimplePaymaster__InvalidSubscriptionAddress();
error SimplePaymaster__InvalidDepositAmount();
error SimplePaymaster__ETHAmountMismatch();
error SimplePaymaster__NoETHForUSDCDdeposit();
error SimplePaymaster__NoETHForSONICDeposit();
error SimplePaymaster__USDCTransferFailed();
error SimplePaymaster__SONICTransferFailed();
error SimplePaymaster__InvalidRecipientAddress();
error SimplePaymaster__InsufficientETHBalance();
error SimplePaymaster__InsufficientUSDCBalance();
error SimplePaymaster__InsufficientSONICBalance();
error SimplePaymaster__ETHWithdrawalFailed();
error SimplePaymaster__USDCWithdrawalFailed();
error SimplePaymaster__SONICWithdrawalFailed();
error SimplePaymaster__OnlyCoreAllowed();
error SimplePaymaster__SenderNotPatient();
error SimplePaymaster__PatientLevelTooLow();
error SimplePaymaster__SubscriptionNotActive();
error SimplePaymaster__InvalidPaymasterData();
error SimplePaymaster__InsufficientETHFunds();
error SimplePaymaster__InsufficientUSDCFunds();
error SimplePaymaster__InsufficientSONICFunds();
error SimplePaymaster__InsufficientETHPostOp();
error SimplePaymaster__InsufficientUSDCPostOp();
error SimplePaymaster__InsufficientSONICPostOp();
error SimplePaymaster__Unauthorized();
error SimplePaymaster__InvalidSponsorType();
