// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {SafeMathUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {TelemedicineCore} from "./TelemedicineCore.sol";
import {TelemedicinePayments} from "./TelemedicinePayments.sol";
contract TelemedicineSubscription is Initializable, ReentrancyGuardUpgradeable {
    using SafeMathUpgradeable for uint256;

TelemedicineCore public core;
TelemedicinePayments public payments;

// Configurable Payment Parameters
uint256 public monthlyFeeUSDC; // $20 in USDC (6 decimals)
uint256 public annualFeeUSDC; // $200 in USDC (6 decimals)
uint256 public perConsultFeeUSDC; // $10 in USDC (6 decimals)
uint8 public subscriptionConsultsLimit; // Max consults per subscription period
uint256 public monthDuration; // Duration of a month in seconds

// Token addresses and supported payment methods
mapping(string => address) public paymentTokens; // e.g., "USDC" => USDC address
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
event Subscribed(address indexed patient, bool isAnnual, uint256 expiry);
event AppointmentBooked(address indexed patient, address indexed doctor, string paymentMethod);
event ConsultCharged(address indexed patient, uint256 amount, string currency);
event PaymentConfigUpdated(string parameter, uint256 value);
event PaymentTokenAdded(string tokenName, address tokenAddress);
event PaymentTokenRemoved(string tokenName);

/// @custom:oz-upgrades-unsafe-allow constructor
constructor() {
    _disableInitializers();
}

function initialize(
    address _core,
    address _payments,
    address _usdcToken,
    address _sonicToken
) external initializer {
    __ReentrancyGuard_init();
    core = TelemedicineCore(_core);
    payments = TelemedicinePayments(_payments);
    monthlyFeeUSDC = 20 * 10**6; // $20 in USDC
    annualFeeUSDC = 200 * 10**6; // $200 in USDC
    perConsultFeeUSDC = 10 * 10**6; // $10 in USDC
    subscriptionConsultsLimit = 3;
    monthDuration = 30 days;

    paymentTokens["USDC"] = _usdcToken;
    paymentTokens["SONIC"] = _sonicToken;
    isPaymentMethodSupported["ETH"] = true;
    isPaymentMethodSupported["USDC"] = true;
    isPaymentMethodSupported["SONIC"] = true;
}

// Config setters (onlyAdmin)
function setMonthlyFeeUSDC(uint256 _fee) external onlyRole(core.ADMIN_ROLE()) {
    monthlyFeeUSDC = _fee;
    emit PaymentConfigUpdated("monthlyFeeUSDC", _fee);
}

function setAnnualFeeUSDC(uint256 _fee) external onlyRole(core.ADMIN_ROLE()) {
    annualFeeUSDC = _fee;
    emit PaymentConfigUpdated("annualFeeUSDC", _fee);
}

function setPerConsultFeeUSDC(uint256 _fee) external onlyRole(core.ADMIN_ROLE()) {
    perConsultFeeUSDC = _fee;
    emit PaymentConfigUpdated("perConsultFeeUSDC", _fee);
}

function setSubscriptionConsultsLimit(uint8 _limit) external onlyRole(core.ADMIN_ROLE()) {
    subscriptionConsultsLimit = _limit;
    emit PaymentConfigUpdated("subscriptionConsultsLimit", _limit);
}

function setMonthDuration(uint256 _duration) external onlyRole(core.ADMIN_ROLE()) {
    require(_duration > 0, "Duration must be positive");
    monthDuration = _duration;
    emit PaymentConfigUpdated("monthDuration", _duration);
}

function addPaymentToken(string memory _tokenName, address _tokenAddress) external onlyRole(core.ADMIN_ROLE()) {
    require(_tokenAddress != address(0), "Invalid token address");
    paymentTokens[_tokenName] = _tokenAddress;
    isPaymentMethodSupported[_tokenName] = true;
    emit PaymentTokenAdded(_tokenName, _tokenAddress);
}

function removePaymentToken(string memory _tokenName) external onlyRole(core.ADMIN_ROLE()) {
    require(isPaymentMethodSupported[_tokenName], "Token not supported");
    isPaymentMethodSupported[_tokenName] = false;
    emit PaymentTokenRemoved(_tokenName);
}

// Subscribe to a plan
function subscribe(bool isAnnual) external onlyRole(core.PATIENT_ROLE()) nonReentrant {
    uint256 fee = isAnnual ? annualFeeUSDC : monthlyFeeUSDC;
    uint256 duration = isAnnual ? 365 days : monthDuration;

    IERC20 usdcToken = IERC20(paymentTokens["USDC"]);
    require(usdcToken.transferFrom(msg.sender, address(payments), fee), "USDC transfer failed");

    Subscription storage sub = subscriptions[msg.sender];
    if (sub.isActive && block.timestamp < sub.expiry) {
        sub.expiry = sub.expiry.add(duration);
    } else {
        sub.isActive = true;
        sub.expiry = block.timestamp.add(duration);
        sub.consultsUsed = 0;
        sub.lastReset = block.timestamp;
    }

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
        sub.consultsUsed = sub.consultsUsed.add(1);
        return true;
    }

    IERC20 usdcToken = IERC20(paymentTokens["USDC"]);
    require(usdcToken.transferFrom(patient, address(payments), perConsultFeeUSDC), "USDC transfer failed");
    emit ConsultCharged(patient, perConsultFeeUSDC, "USDC");
    return false;
}

// Book appointment
function bookAppointment(address doctorAddress, string memory paymentMethod) external payable onlyRole(core.PATIENT_ROLE()) nonReentrant {
    require(core.hasRole(core.DOCTOR_ROLE(), doctorAddress), "Invalid doctor");
    require(isPaymentMethodSupported[paymentMethod], "Payment method not supported");

    TelemedicineCore.Doctor memory doctor = core.doctors(doctorAddress);
    uint256 feeETH = doctor.consultationFee; // Assumes fee in wei for ETH; adjust if ecosystem uses different units
    uint256 feeUSDC = doctor.consultationFee; // Assumes same fee for simplicity; adjust as needed
    uint256 feeSONIC = doctor.consultationFee; // Assumes same fee for simplicity; adjust as needed

    bool usedSubscription = _checkAndChargeConsult(msg.sender);

    if (!usedSubscription) {
        if (keccak256(bytes(paymentMethod)) == keccak256(bytes("ETH"))) {
            require(msg.value >= feeETH, "Insufficient ETH");
            (bool success, ) = doctorAddress.call{value: feeETH}("");
            require(success, "ETH transfer failed");
            if (msg.value > feeETH) {
                (bool refundSuccess, ) = payable(msg.sender).call{value: msg.value.sub(feeETH)}("");
                require(refundSuccess, "Refund failed");
            }
            emit ConsultCharged(msg.sender, feeETH, "ETH");
        } else if (keccak256(bytes(paymentMethod)) == keccak256(bytes("USDC"))) {
            IERC20 usdcToken = IERC20(paymentTokens["USDC"]);
            require(usdcToken.transferFrom(msg.sender, doctorAddress, feeUSDC), "USDC transfer failed");
            emit ConsultCharged(msg.sender, feeUSDC, "USDC");
        } else if (keccak256(bytes(paymentMethod)) == keccak256(bytes("SONIC"))) {
            IERC20 sonicToken = IERC20(paymentTokens["SONIC"]);
            require(sonicToken.transferFrom(msg.sender, doctorAddress, feeSONIC), "SONIC transfer failed");
            emit ConsultCharged(msg.sender, feeSONIC, "SONIC");
        } else {
            revert("Unsupported payment method");
        }
    }

    patientConsults[msg.sender] = patientConsults[msg.sender].add(1);
    emit AppointmentBooked(msg.sender, doctorAddress, usedSubscription ? "Subscription" : paymentMethod);
}

// Get subscription status
function getSubscriptionStatus(address patient) external view returns (bool isActive, uint256 expiry, uint256 consultsUsed) {
    Subscription memory sub = subscriptions[patient];
    bool active = sub.isActive && block.timestamp < sub.expiry;
    return (active, sub.expiry, sub.consultsUsed);
}

// Withdraw funds (to TelemedicinePayments)
function withdraw(address to, uint256 amount, string memory currency) external onlyRole(core.ADMIN_ROLE()) nonReentrant {
    require(to != address(0), "Invalid recipient");
    if (keccak256(bytes(currency)) == keccak256(bytes("ETH"))) {
        require(amount <= address(this).balance, "Insufficient ETH balance");
        (bool success, ) = payable(address(payments)).call{value: amount}("");
        require(success, "ETH withdrawal failed");
    } else if (isPaymentMethodSupported[currency]) {
        IERC20 token = IERC20(paymentTokens[currency]);
        require(token.balanceOf(address(this)) >= amount, "Insufficient token balance");
        require(token.transfer(address(payments), amount), "Token withdrawal failed");
    } else {
        revert("Currency not supported");
    }
}

// Fallback function to receive ETH
receive() external payable {}

// Modifier for role-based access
modifier onlyRole(bytes32 role) {
    require(core.hasRole(role, msg.sender), "Unauthorized");
    _;
}

}

