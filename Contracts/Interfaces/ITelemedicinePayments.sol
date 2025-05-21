// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {IERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";

/// @title ITelemedicinePayments
/// @notice Interface for TelemedicinePayments contract handling payments, refunds, Sonic ($S) rewards, pending payment cancellation, and on-ramp/off-ramp requests
interface ITelemedicinePayments {
    // Errors
    error NotAuthorized();
    error ContractPaused();
    error InvalidAddress();
    error InsufficientFunds();
    error PaymentFailed();
    error InvalidRequestStatus();
    error InvalidRewardAmount();
    error InvalidRewardBounds();
    error InvalidPaymentId();

    // Enum
    enum PaymentType { ETH, USDC, SONIC }

    // Functions

    /// @notice Returns the USDC token contract
    /// @return IERC20Upgradeable The USDC token contract
    function usdcToken() external view returns (IERC20Upgradeable);

    /// @notice Returns the Sonic token contract (deprecated, use sonicNativeToken)
    /// @return IERC20Upgradeable The Sonic token contract
    function sonicToken() external view returns (IERC20Upgradeable);

    /// @notice Returns the Sonic native token contract
    /// @return IERC20Upgradeable The Sonic native token contract
    function sonicNativeToken() external view returns (IERC20Upgradeable);

    /// @notice Processes a user payment for services (e.g., appointments, AI analysis)
    /// @param paymentType The payment type (ETH, USDC, SONIC)
    /// @param amount The payment amount
    function _processPayment(PaymentType paymentType, uint256 amount) external payable;

    /// @notice Refunds a patient for a canceled service
    /// @param patient The patient address
    /// @param amount The refund amount
    /// @param paymentType The payment type (ETH, USDC, SONIC)
    function _refundPatient(address patient, uint256 amount, PaymentType paymentType) external;

    /// @notice Queues a payment for later processing, validates $S rewards
    /// @param recipient The recipient address
    /// @param amount The payment amount
    /// @param paymentType The payment type (ETH, USDC, SONIC)
    function queuePayment(address recipient, uint256 amount, PaymentType paymentType) external;

    /// @notice Cancels a pending payment
    /// @param recipient The recipient address
    /// @param paymentId The unique ID of the pending payment
    /// @return bool True if cancellation succeeds, false otherwise
    function cancelPendingPayment(address recipient, uint256 paymentId) external returns (bool);

    /// @notice Updates the minimum and maximum $S reward bounds (admin only)
    /// @param newMinReward The new minimum reward
    /// @param newMaxReward The new maximum reward
    function updateRewardBounds(uint256 newMinReward, uint256 newMaxReward) external;

    /// @notice Returns the current $S reward bounds
    /// @return minReward The minimum reward amount
    /// @return maxReward The maximum reward amount
    function getRewardBounds() external view returns (uint256 minReward, uint256 maxReward);

    /// @notice Retrieves a pending payment
    /// @param paymentId The payment ID
    /// @return recipient The recipient address
    /// @return amount The payment amount
    /// @return paymentType The payment type (ETH, USDC, SONIC)
    /// @return processed Whether the payment is processed
    /// @return requestTimestamp The request timestamp
    function getPendingPayment(uint256 paymentId) external view returns (
        address recipient,
        uint256 amount,
        PaymentType paymentType,
        bool processed,
        uint48 requestTimestamp
    );

    /// @notice Retrieves an on-ramp request (fiat to crypto)
    /// @param requestId The request ID
    /// @return id The request ID
    /// @return user The user address
    /// @return fiatAmount The fiat amount
    /// @return targetToken The target token (ETH, USDC, SONIC)
    /// @return status The request status
    /// @return cryptoAmount The crypto amount
    /// @return requestTimestamp The request timestamp
    /// @return providerReference The provider reference
    /// @return feePaid The fee paid
    function getOnRampRequest(uint256 requestId) external view returns (
        uint256 id,
        address user,
        uint256 fiatAmount,
        PaymentType targetToken,
        uint8 status,
        uint256 cryptoAmount,
        uint48 requestTimestamp,
        bytes32 providerReference,
        uint256 feePaid
    );

    /// @notice Retrieves an off-ramp request (crypto to fiat)
    /// @param requestId The request ID
    /// @return id The request ID
    /// @return user The user address
    /// @return sourceToken The source token (ETH, USDC, SONIC)
    /// @return cryptoAmount The crypto amount
    /// @return fiatAmount The fiat amount
    /// @return status The request status
    /// @return requestTimestamp The request timestamp
    /// @return bankDetails The bank details
    function getOffRampRequest(uint256 requestId) external view returns (
        uint256 id,
        address user,
        PaymentType sourceToken,
        uint256 cryptoAmount,
        uint256 fiatAmount,
        uint8 status,
        uint48 requestTimestamp,
        bytes32 bankDetails
    );

    /// @notice Returns the contract version
    /// @return The version number
    function version() external view returns (uint256);
}
