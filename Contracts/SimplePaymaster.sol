// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
import {Initializable} from "@openzeppelin
/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin
/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {SafeMathUpgradeable} from "@openzeppelin
/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";
import {IERC20} from "@openzeppelin
/contracts/token/ERC20/IERC20.sol";
import {TelemedicineCore} from "./TelemedicineCore.sol";
import {TelemedicinePayments} from "./TelemedicinePayments.sol";
import {TelemedicineSubscription} from "./TelemedicineSubscription.sol";
contract SimplePaymaster is Initializable, ReentrancyGuardUpgradeable {
    using SafeMathUpgradeable for uint256;

TelemedicineCore public core;
TelemedicinePayments public payments;
TelemedicineSubscription public subscription;
uint256 public constant VERSION = 1;

// Supported sponsor types for gas cost
enum SponsorType { ETH, USDC, SONIC }
mapping(address => uint256) public sponsoredGasCosts; // Tracks total gas sponsored per user

event PaymasterFunded(address indexed funder, uint256 amount, SponsorType sponsorType);
event GasSponsored(address indexed sender, uint256 amount, SponsorType sponsorType);
event FundsWithdrawn(address indexed to, uint256 amount, SponsorType sponsorType);

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

function initialize(address _core, address _payments, address _subscription) external initializer {
    __ReentrancyGuard_init();
    core = TelemedicineCore(_core);
    payments = TelemedicinePayments(_payments);
    subscription = TelemedicineSubscription(_subscription);
}

// Fund the paymaster with ETH, USDC, or SONIC
function deposit(SponsorType _sponsorType, uint256 _amount) external payable nonReentrant {
    require(_amount > 0, "Deposit amount must be greater than zero");

    if (_sponsorType == SponsorType.ETH) {
        require(msg.value == _amount, "ETH amount mismatch");
        emit PaymasterFunded(msg.sender, _amount, _sponsorType);
    } else if (_sponsorType == SponsorType.USDC) {
        require(msg.value == 0, "No ETH allowed for USDC deposit");
        require(payments.usdcToken().transferFrom(msg.sender, address(this), _amount), "USDC transfer failed");
        emit PaymasterFunded(msg.sender, _amount, _sponsorType);
    } else if (_sponsorType == SponsorType.SONIC) {
        require(msg.value == 0, "No ETH allowed for SONIC deposit");
        require(payments.sonicToken().transferFrom(msg.sender, address(this), _amount), "SONIC transfer failed");
        emit PaymasterFunded(msg.sender, _amount, _sponsorType);
    } else {
        revert("Unsupported sponsor type");
    }
}

// Withdraw funds (admin only)
function withdraw(address payable to, uint256 amount, SponsorType _sponsorType) external onlyRole(core.ADMIN_ROLE()) nonReentrant {
    require(to != address(0), "Invalid recipient address");
    if (_sponsorType == SponsorType.ETH) {
        require(address(this).balance >= amount, "Insufficient ETH balance");
        (bool success, ) = to.call{value: amount}("");
        require(success, "ETH withdrawal failed");
        emit FundsWithdrawn(to, amount, _sponsorType);
    } else if (_sponsorType == SponsorType.USDC) {
        require(payments.usdcToken().balanceOf(address(this)) >= amount, "Insufficient USDC balance");
        require(payments.usdcToken().transfer(to, amount), "USDC withdrawal failed");
        emit FundsWithdrawn(to, amount, _sponsorType);
    } else if (_sponsorType == SponsorType.SONIC) {
        require(payments.sonicToken().balanceOf(address(this)) >= amount, "Insufficient SONIC balance");
        require(payments.sonicToken().transfer(to, amount), "SONIC transfer failed");
        emit FundsWithdrawn(to, amount, _sponsorType);
    } else {
        revert("Unsupported sponsor type");
    }
}

// ERC-4337 paymaster validation
function validatePaymasterUserOp(
    UserOperation calldata userOp,
    bytes32 /* userOpHash */,
    uint256 maxCost
) external view returns (uint256, bytes memory) {
    require(msg.sender == address(core), "Only TelemedicineCore can call");
    require(core.hasRole(core.PATIENT_ROLE(), userOp.sender), "Sender is not a patient");

    // Check gamification level (getPatientLevel is part of TelemedicineCore's gamification system)
    (bool success, bytes memory result) = address(core).staticcall(
        abi.encodeWithSignature("getPatientLevel(address)", userOp.sender)
    );
    require(success && abi.decode(result, (uint8)) > 0, "Patient level too low for sponsorship");

    // Check subscription status
    (bool isActive, , ) = subscription.getSubscriptionStatus(userOp.sender);
    require(isActive, "Patient subscription not active");

    // Decode sponsor type from paymasterAndData (first byte after paymaster address)
    require(userOp.paymasterAndData.length >= 20 + 1, "Invalid paymasterAndData length");
    bytes memory data = userOp.paymasterAndData;
    SponsorType sponsorType = SponsorType(uint8(data[20])); // First byte after 20-byte address

    // Validate funds based on sponsor type
    if (sponsorType == SponsorType.ETH) {
        require(address(this).balance >= maxCost, "Insufficient ETH funds");
    } else if (sponsorType == SponsorType.USDC) {
        require(payments.usdcToken().balanceOf(address(this)) >= maxCost, "Insufficient USDC funds");
    } else if (sponsorType == SponsorType.SONIC) {
        require(payments.sonicToken().balanceOf(address(this)) >= maxCost, "Insufficient SONIC funds");
    } else {
        revert("Unsupported sponsor type");
    }

    return (0, abi.encode(sponsorType)); // 0 = valid, context = sponsorType
}

// Post-operation hook
function postOp(
    uint8 mode,
    bytes calldata context,
    uint256 actualGasCost
) external nonReentrant {
    require(msg.sender == address(core), "Only TelemedicineCore can call");
    if (mode != 0) return; // Only handle success (mode 0)

    SponsorType sponsorType = abi.decode(context, (SponsorType));
    address sender = tx.origin; // Simplified; in practice, extract from UserOperation via core

    if (sponsorType == SponsorType.ETH) {
        require(address(this).balance >= actualGasCost, "Insufficient ETH post-op");
        // Gas cost is implicitly covered by ETH balance reduction
    } else if (sponsorType == SponsorType.USDC) {
        require(payments.usdcToken().balanceOf(address(this)) >= actualGasCost, "Insufficient USDC post-op");
        require(payments.usdcToken().transfer(address(payments), actualGasCost), "USDC transfer failed");
    } else if (sponsorType == SponsorType.SONIC) {
        require(payments.sonicToken().balanceOf(address(this)) >= actualGasCost, "Insufficient SONIC post-op");
        require(payments.sonicToken().transfer(address(payments), actualGasCost), "SONIC transfer failed");
    } else {
        revert("Unsupported sponsor type");
    }

    sponsoredGasCosts[sender] = sponsoredGasCosts[sender].add(actualGasCost);
    emit GasSponsored(sender, actualGasCost, sponsorType);
}

// View balance for a specific sponsor type
function getBalance(SponsorType _sponsorType) external view returns (uint256) {
    if (_sponsorType == SponsorType.ETH) {
        return address(this).balance;
    } else if (_sponsorType == SponsorType.USDC) {
        return payments.usdcToken().balanceOf(address(this));
    } else if (_sponsorType == SponsorType.SONIC) {
        return payments.sonicToken().balanceOf(address(this));
    } else {
        revert("Unsupported sponsor type");
    }
}

// Fallback function to receive ETH
receive() external payable {}

// Role-based access modifier
modifier onlyRole(bytes32 role) {
    require(core.hasRole(role, msg.sender), "Unauthorized");
    _;
}

}
