// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {ECDSAUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/ECDSAUpgradeable.sol";
import {ITelemedicineCore} from "./Interfaces/ITelemedicineCore.sol";
import {ITelemedicinePayments} from "./Interfaces/ITelemedicinePayments.sol";

/// @title GovernanceManager
/// @notice Manages governance proposals, role assignments, reserve withdrawals, and contract upgrades
/// @dev UUPS upgradeable, uses EIP-712 for multi-signature approvals
contract GovernanceManager is Initializable, UUPSUpgradeable, EIP712Upgradeable {
    using ECDSAUpgradeable for bytes32;

    // Custom Errors
    error InvalidAddress();
    error InvalidApprovalCount();
    error InvalidToken();
    error InvalidProposal();
    error AlreadyApproved();
    error AlreadyApprover();
    error NotApprover();
    error InsufficientFunds();
    error ExceedsWithdrawalLimit();
    error TooManyWithdrawals();
    error InvalidWithdrawalRequest();
    error TimelockNotExpired();
    error TimelockExpired();
    error NotAuthorized();
    error InsufficientApprovals();
    error InvalidSignature();
    error InvalidCoreImplementation();
    error InvalidPaymentsImplementation();
    error InvalidActionSelector();
    error InvalidDependencyVersion();
    error TooManyApprovers();
    error InvalidRole();
    error ReserveWithdrawalPaused();
    error BelowReserveThreshold();
    error InvalidPaymentType();
    error PaymentMethodExists();
    error PaymentMethodNotExists();
    error NotGovernance();
    error ProposalExecutionFailed();
    error SignatureReplay();
    error InvalidImplementation();

    // Constants
    uint256 public constant MAX_TIMELOCK = 30 days; // New: Maximum timelock period
    uint256 public constant MIN_RESERVE_THRESHOLD = 1 ether; // New: Minimum reserve threshold
    uint256 public constant MAX_WITHDRAWAL_PERCENTAGE = 10; // New: Max 10% of reserve per withdrawal

    // State Variables
    ITelemedicineCore public immutable core;
    ITelemedicinePayments public immutable payments;
    address public emergencyAdmin;
    uint256 public requiredApprovals;
    mapping(address => bool) public governanceApprovers;
    mapping(address => bool) public financialAdmins;
    mapping(address => bool) public configAdmins;
    uint256 public governanceApproverCount;
    mapping(bytes4 => bool) public allowedGovernanceSelectors;
    mapping(address => mapping(bytes32 => uint256)) public nonces; // Updated: Per-action nonces
    bool public reserveWithdrawalPaused;
    uint256 public versionNumber; // New: Track contract version

    // Structs
    struct Proposal {
        bytes32 actionHash; // Updated: Hash of actionData
        uint256 proposalTimestamp;
        uint256 approvalCount;
        mapping(address => bool) approvals; // Updated: Replace approvalsBitmap
        bool executed;
        bytes actionData;
        address newImplementation;
        bytes32 actionId;
    }

    struct ReserveWithdrawalRequest {
        address to;
        uint256 amount;
        ITelemedicinePayments.PaymentType paymentType;
        uint256 requestTimestamp;
        bool executed;
    }

    // Storage
    mapping(uint256 => Proposal) public proposals;
    mapping(uint256 => ReserveWithdrawalRequest) public reserveWithdrawalRequests;
    mapping(address => uint256) public activeWithdrawalRequests;
    uint256 public proposalCounter;
    uint256 public reserveWithdrawalCounter;

    // Events
    event ProposalCreated(uint256 indexed proposalId, bytes32 actionHash, address newImplementation, uint256 timestamp, bytes32 actionId);
    event ProposalApproved(uint256 indexed proposalId, address indexed approver);
    event ProposalExecuted(uint256 indexed proposalId, bytes32 actionHash, address newImplementation);
    event ReserveWithdrawalRequested(uint256 indexed requestId, address to, uint256 amount, ITelemedicinePayments.PaymentType paymentType);
    event ReserveWithdrawalExecuted(uint256 indexed requestId, address to, uint256 amount, ITelemedicinePayments.PaymentType paymentType);
    event RoleAssigned(bytes32 indexed role, address indexed account);
    event RoleRevoked(bytes32 indexed role, address indexed account);
    event EmergencyAdminUpdated(address indexed newAdmin);
    event ReserveWithdrawalPaused(bool paused);
    event PaymentMethodUpdated(ITelemedicinePayments.PaymentType paymentType, bool enabled); // Updated: Consistent naming
    event TokenAddressUpdated(ITelemedicinePayments.PaymentType paymentType, address newToken);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the contract with core, payments, and governance settings
    /// @param _core Address of TelemedicineCore
    /// @param _payments Address of TelemedicinePayments
    /// @param _initialApprover Initial governance approver
    /// @param _emergencyAdmin Emergency admin address
    /// @param _requiredApprovals Number of required approvals
    function initialize(
        address _core,
        address _payments,
        address _initialApprover,
        address _emergencyAdmin,
        uint256 _requiredApprovals
    ) external initializer {
        if (_core == address(0) || _payments == address(0) || _initialApprover == address(0) || _emergencyAdmin == address(0)) revert InvalidAddress();
        if (_requiredApprovals < 2 || _requiredApprovals > 10) revert InvalidApprovalCount();

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
        __EIP712_init("GovernanceManager", "1");

        core = ITelemedicineCore(_core);
        payments = ITelemedicinePayments(_payments);

        requiredApprovals = _requiredApprovals;
        governanceApprovers[_initialApprover] = true;
        configAdmins[_initialApprover] = true;
        governanceApproverCount = 1;
        emergencyAdmin = _emergencyAdmin;
        versionNumber = 1;

        allowedGovernanceSelectors[this.assignRole.selector] = true;
        allowedGovernanceSelectors[this.revokeRole.selector] = true;
        allowedGovernanceSelectors[this.addPaymentMethod.selector] = true;
        allowedGovernanceSelectors[this.removePaymentMethod.selector] = true;
        allowedGovernanceSelectors[this.setTokenAddress.selector] = true;
        allowedGovernanceSelectors[this.updateAllowedSelector.selector] = true; // New: Allow selector updates

        emit RoleAssigned(keccak256("GOVERNANCE_APPROVER"), _initialApprover);
        emit RoleAssigned(keccak256("CONFIG_ADMIN"), _initialApprover);
        emit EmergencyAdminUpdated(_emergencyAdmin);
    }

    /// @notice Updates allowed governance selectors
    /// @param selector Function selector
    /// @param allowed Whether to allow the selector
    function updateAllowedSelector(bytes4 selector, bool allowed, bytes[] calldata signatures) external governanceApproved(signatures) {
        allowedGovernanceSelectors[selector] = allowed;
        emit ConfigurationUpdated(selector, allowed ? 1 : 0);
    }

    /// @notice Proposes a governance action or contract upgrade
    /// @param actionData Encoded function call data
    /// @param newImplementation New contract implementation (if upgrade)
    /// @param actionId Unique action identifier
    function proposeAction(bytes memory actionData, address newImplementation, bytes32 actionId) external onlyGovernanceApprover {
        if (newImplementation != address(0) && actionData.length > 0) revert InvalidProposal();
        if (newImplementation != address(0)) {
            // New: Validate implementation
            if (!_isContract(newImplementation)) revert InvalidImplementation();
        }
        if (actionData.length > 0) {
            bytes4 selector = bytes4(actionData);
            if (!allowedGovernanceSelectors[selector]) revert InvalidActionSelector();
        }

        proposalCounter++;
        Proposal storage proposal = proposals[proposalCounter];
        bytes32 actionHash = actionData.length > 0 ? keccak256(actionData) : bytes32(0);
        proposal.actionHash = actionHash;
        proposal.proposalTimestamp = block.timestamp;
        proposal.approvals[msg.sender] = true;
        proposal.approvalCount = 1;
        proposal.actionData = actionData;
        proposal.newImplementation = newImplementation;
        proposal.actionId = actionId;

        emit ProposalCreated(proposalCounter, actionHash, newImplementation, block.timestamp, actionId);
    }

    /// @notice Approves a governance proposal
    /// @param proposalId Proposal ID
    function approveAction(uint256 proposalId) external onlyGovernanceApprover {
        Proposal storage proposal = proposals[proposalId];
        if ((proposal.actionHash == bytes32(0) && proposal.newImplementation == address(0)) || proposal.executed) revert InvalidProposal();
        if (proposal.approvals[msg.sender]) revert AlreadyApproved();
        // New: Check timelock expiry
        if (block.timestamp > proposal.proposalTimestamp + MAX_TIMELOCK) revert TimelockExpired();

        proposal.approvals[msg.sender] = true;
        proposal.approvalCount++;
        emit ProposalApproved(proposalId, msg.sender);

        if (proposal.approvalCount >= requiredApprovals && block.timestamp >= proposal.proposalTimestamp + 7 days) {
            if (!_validateDependencies()) revert InvalidDependencyVersion();
            if (proposal.newImplementation != address(0)) {
                _upgradeTo(proposal.newImplementation);
            } else {
                // Updated: Try-catch for action execution
                (bool success, bytes memory returnData) = address(this).call(proposal.actionData);
                if (!success) revert ProposalExecutionFailed();
            }
            proposal.executed = true;
            emit ProposalExecuted(proposalId, proposal.actionHash, proposal.newImplementation);
        }
    }

    /// @notice Batch approves multiple proposals
    /// @param proposalIds Array of proposal IDs
    function batchApproveActions(uint256[] calldata proposalIds) external onlyGovernanceApprover {
        for (uint256 i = 0; i < proposalIds.length; i++) {
            Proposal storage proposal = proposals[proposalIds[i]];
            if ((proposal.actionHash == bytes32(0) && proposal.newImplementation == address(0)) || proposal.executed) continue;
            if (proposal.approvals[msg.sender]) continue;
            if (block.timestamp > proposal.proposalTimestamp + MAX_TIMELOCK) continue;

            proposal.approvals[msg.sender] = true;
            proposal.approvalCount++;
            emit ProposalApproved(proposalIds[i], msg.sender);

            if (proposal.approvalCount >= requiredApprovals && block.timestamp >= proposal.proposalTimestamp + 7 days) {
                if (!_validateDependencies()) continue;
                if (proposal.newImplementation != address(0)) {
                    _upgradeTo(proposal.newImplementation);
                } else {
                    (bool success, ) = address(this).call(proposal.actionData);
                    if (!success) continue;
                }
                proposal.executed = true;
                emit ProposalExecuted(proposalIds[i], proposal.actionHash, proposal.newImplementation);
            }
        }
    }

    /// @notice Assigns a governance role
    /// @param role Role identifier
    /// @param account Account to assign the role to
    function assignRole(bytes32 role, address account) external onlyGovernance {
        if (account == address(0)) revert InvalidAddress();
        if (role == keccak256("GOVERNANCE_APPROVER")) {
            if (governanceApprovers[account]) revert AlreadyApprover();
            if (governanceApproverCount >= 10) revert TooManyApprovers();
            // New: Validate requiredApprovals
            if (requiredApprovals > governanceApproverCount + 1) revert InvalidApprovalCount();
            governanceApprovers[account] = true;
            governanceApproverCount++;
        } else if (role == keccak256("FINANCIAL_ADMIN")) {
            if (financialAdmins[account]) revert AlreadyApprover();
            financialAdmins[account] = true;
        } else if (role == keccak256("CONFIG_ADMIN")) {
            if (configAdmins[account]) revert AlreadyApprover();
            configAdmins[account] = true;
        } else {
            revert InvalidRole();
        }
        emit RoleAssigned(role, account);
    }

    /// @notice Revokes a governance role
    /// @param role Role identifier
    /// @param account Account to revoke the role from
    function revokeRole(bytes32 role, address account) external onlyGovernance {
        if (role == keccak256("GOVERNANCE_APPROVER")) {
            if (!governanceApprovers[account]) revert NotApprover();
            // New: Ensure at least one approver remains
            if (governanceApproverCount <= 1) revert InvalidApprovalCount();
            governanceApprovers[account] = false;
            governanceApproverCount--;
        } else if (role == keccak256("FINANCIAL_ADMIN")) {
            if (!financialAdmins[account]) revert NotApprover();
            financialAdmins[account] = false;
        } else if (role == keccak256("CONFIG_ADMIN")) {
            if (!configAdmins[account]) revert NotApprover();
            configAdmins[account] = false;
        } else {
            revert InvalidRole();
        }
        emit RoleRevoked(role, account);
    }

    /// @notice Adds a supported payment method
    /// @param method Payment type (ETH, USDC, SONIC)
    /// @param signatures Governance signatures
    function addPaymentMethod(ITelemedicinePayments.PaymentType method, bytes[] calldata signatures) 
        external governanceApproved(signatures) 
    {
        if (method > ITelemedicinePayments.PaymentType.SONIC) revert InvalidPaymentType();
        // Updated: Try-catch for payment method check
        try payments.isPaymentMethodSupported(method) returns (bool isSupported) {
            if (isSupported) revert PaymentMethodExists();
        } catch {
            revert ExternalCallFailed();
        }
        // Updated: Delegate to payments
        try payments.updatePaymentMethod(method, true) {
            emit PaymentMethodUpdated(method, true);
        } catch {
            revert ExternalCallFailed();
        }
    }

    /// @notice Removes a supported payment method
    /// @param method Payment type (ETH, USDC, SONIC)
    /// @param signatures Governance signatures
    function removePaymentMethod(ITelemedicinePayments.PaymentType method, bytes[] calldata signatures) 
        external governanceApproved(signatures) 
    {
        if (method > ITelemedicinePayments.PaymentType.SONIC) revert InvalidPaymentType();
        try payments.isPaymentMethodSupported(method) returns (bool isSupported) {
            if (!isSupported) revert PaymentMethodNotExists();
        } catch {
            revert ExternalCallFailed();
        }
        try payments.updatePaymentMethod(method, false) {
            emit PaymentMethodUpdated(method, false);
        } catch {
            revert ExternalCallFailed();
        }
    }

    /// @notice Updates a token address
    /// @param paymentType Payment type (USDC, SONIC)
    /// @param newToken New token address
    /// @param signatures Governance signatures
    function setTokenAddress(ITelemedicinePayments.PaymentType paymentType, address newToken, bytes[] calldata signatures) 
        external governanceApproved(signatures) 
    {
        if (newToken == address(0)) revert InvalidAddress();
        if (paymentType != ITelemedicinePayments.PaymentType.USDC && paymentType != ITelemedicinePayments.PaymentType.SONIC) 
            revert InvalidPaymentType();
        // Updated: Validate token decimals
        uint8 decimals = _getTokenDecimals(newToken);
        if (decimals == 0) revert InvalidToken();
        // Updated: Try-catch for token update
        try paymentType == ITelemedicinePayments.PaymentType.USDC ? 
            payments.setUsdcToken(newToken) : 
            payments.setSonicToken(newToken) 
        {
            emit TokenAddressUpdated(paymentType, newToken);
        } catch {
            revert ExternalCallFailed();
        }
    }

    /// @notice Requests a reserve fund withdrawal
    /// @param to Recipient address
    /// @param amount Amount to withdraw
    /// @param paymentType Payment type (ETH, USDC, SONIC)
    /// @param signatures Governance signatures
    function requestReserveWithdrawal(
        address to,
        uint256 amount,
        ITelemedicinePayments.PaymentType paymentType,
        bytes[] calldata signatures
    ) external onlyFinancialAdmin governanceApproved(signatures) {
        if (reserveWithdrawalPaused) revert ReserveWithdrawalPaused();
        if (to == address(0)) revert InvalidAddress();
        if (amount == 0) revert InsufficientFunds();
        if (activeWithdrawalRequests[msg.sender] >= 5) revert TooManyWithdrawals();
        // Updated: Validate reserve funds
        uint256 availableFunds = reserveFunds(paymentType);
        if (amount > availableFunds) revert InsufficientFunds();
        if (amount > availableFunds * MAX_WITHDRAWAL_PERCENTAGE / 100) revert ExceedsWithdrawalLimit();
        if (availableFunds - amount < MIN_RESERVE_THRESHOLD) revert BelowReserveThreshold();

        reserveWithdrawalCounter++;
        reserveWithdrawalRequests[reserveWithdrawalCounter] = ReserveWithdrawalRequest(
            to,
            amount,
            paymentType,
            block.timestamp,
            false
        );
        activeWithdrawalRequests[msg.sender]++;

        emit ReserveWithdrawalRequested(reserveWithdrawalCounter, to, amount, paymentType);
    }

    /// @notice Executes a reserve fund withdrawal
    /// @param requestId Withdrawal request ID
    function executeReserveWithdrawal(uint256 requestId) external onlyFinancialAdmin {
        if (reserveWithdrawalPaused) revert ReserveWithdrawalPaused();
        ReserveWithdrawalRequest storage request = reserveWithdrawalRequests[requestId];
        if (request.to == address(0) || request.executed) revert InvalidWithdrawalRequest();
        if (block.timestamp < request.requestTimestamp + 7 days) revert TimelockNotExpired();
        if (block.timestamp > request.requestTimestamp + MAX_TIMELOCK) revert TimelockExpired();

        uint256 availableFunds = reserveFunds(request.paymentType);
        if (request.amount > availableFunds) revert InsufficientFunds();
        if (availableFunds - request.amount < MIN_RESERVE_THRESHOLD) revert BelowReserveThreshold();

        request.executed = true;
        activeWithdrawalRequests[msg.sender]--;
        // Updated: Try-catch for reserve fund update
        try core.updateReserveFund(core.reserveFund() - request.amount) {
            _releasePayment(request.to, request.amount, request.paymentType);
            emit ReserveWithdrawalExecuted(requestId, request.to, request.amount, request.paymentType);
        } catch {
            revert ExternalCallFailed();
        }
    }

    /// @notice Batch executes reserve withdrawals
    /// @param requestIds Array of withdrawal request IDs
    function batchExecuteReserveWithdrawals(uint256[] calldata requestIds) external onlyFinancialAdmin {
        if (reserveWithdrawalPaused) revert ReserveWithdrawalPaused();
        for (uint256 i = 0; i < requestIds.length; i++) {
            ReserveWithdrawalRequest storage request = reserveWithdrawalRequests[requestIds[i]];
            if (request.to == address(0) || request.executed) continue;
            if (block.timestamp < request.requestTimestamp + 7 days) continue;
            if (block.timestamp > request.requestTimestamp + MAX_TIMELOCK) continue;

            uint256 availableFunds = reserveFunds(request.paymentType);
            if (request.amount > availableFunds) continue;
            if (availableFunds - request.amount < MIN_RESERVE_THRESHOLD) continue;

            request.executed = true;
            activeWithdrawalRequests[msg.sender]--;
            try core.updateReserveFund(core.reserveFund() - request.amount) {
                _releasePayment(request.to, request.amount, request.paymentType);
                emit ReserveWithdrawalExecuted(requestIds[i], request.to, request.amount, request.paymentType);
            } catch {
                continue;
            }
        }
    }

    /// @notice Toggles reserve withdrawal pause
    /// @param paused True to pause, false to unpause
    /// @param signatures Governance signatures
    function toggleReserveWithdrawalPause(bool paused, bytes[] calldata signatures) 
        external governanceApproved(signatures) 
    {
        reserveWithdrawalPaused = paused;
        emit ReserveWithdrawalPaused(paused);
    }

    /// @notice Updates the emergency admin
    /// @param newAdmin New emergency admin address
    /// @param signatures Governance signatures
    function updateEmergencyAdmin(address newAdmin, bytes[] calldata signatures) 
        external governanceApproved(signatures) 
    {
        if (newAdmin == address(0)) revert InvalidAddress();
        emergencyAdmin = newAdmin;
        emit EmergencyAdminUpdated(newAdmin);
    }

    /// @notice Emergency pause for reserve withdrawals
    /// @param signatures Governance signatures
    function emergencyPauseWithdrawals(bytes[] calldata signatures) external {
        if (msg.sender != emergencyAdmin) revert NotAuthorized();
        // Updated: Require signatures even for emergency admin
        if (signatures.length < requiredApprovals) revert InsufficientApprovals();
        bytes32 structHash = keccak256(abi.encode(
            keccak256("EmergencyAction(address sender,bytes32 actionId,uint256 nonce,uint256 timestamp,uint256 chainId)"),
            msg.sender,
            keccak256("emergencyPauseWithdrawals"),
            nonces[msg.sender][keccak256("emergencyPauseWithdrawals")],
            block.timestamp,
            block.chainid
        ));
        bytes32 digest = _hashTypedDataV4(structHash);
        address[] memory signers = new address[](signatures.length);
        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = digest.recover(signatures[i]);
            if (!governanceApprovers[signer] || _isSignerUsed(signers, signer, i)) revert InvalidSignature();
            signers[i] = signer;
        }
        nonces[msg.sender][keccak256("emergencyPauseWithdrawals")]++;

        reserveWithdrawalPaused = true;
        emit ReserveWithdrawalPaused(true);
    }

    /// @notice Authorizes contract upgrades
    /// @param newImplementation New implementation address
    function _authorizeUpgrade(address newImplementation) internal override onlyGovernance {
        if (!_isContract(newImplementation)) revert InvalidImplementation();
        versionNumber++;
    }

    /// @notice Validates dependency contract versions
    /// @return True if dependencies are valid
    function _validateDependencies() internal view returns (bool) {
        try core.version() returns (uint256 coreVersion) {
            try payments.version() returns (uint256 paymentsVersion) {
                return coreVersion >= 1 && paymentsVersion >= 1;
            } catch {
                return false;
            }
        } catch {
            return false;
        }
    }

    /// @notice Checks available reserve funds
    /// @param paymentType Payment type (ETH, USDC, SONIC)
    /// @return Available funds
    function reserveFunds(ITelemedicinePayments.PaymentType paymentType) internal view returns (uint256) {
        // Updated: Implement reserve funds logic
        if (paymentType == ITelemedicinePayments.PaymentType.ETH) {
            return address(payments).balance;
        } else if (paymentType == ITelemedicinePayments.PaymentType.USDC) {
            try payments.usdcToken() returns (IERC20Upgradeable usdc) {
                return usdc.balanceOf(address(payments));
            } catch {
                return 0;
            }
        } else if (paymentType == ITelemedicinePayments.PaymentType.SONIC) {
            try payments.sonicToken() returns (IERC20Upgradeable sonic) {
                return sonic.balanceOf(address(payments));
            } catch {
                return 0;
            }
        }
        revert InvalidPaymentType();
    }

    /// @notice Releases a payment to a recipient
    /// @param to Recipient address
    /// @param amount Amount to release
    /// @param paymentType Payment type (ETH, USDC, SONIC)
    function _releasePayment(address to, uint256 amount, ITelemedicinePayments.PaymentType paymentType) internal {
        // Updated: Implement payment release logic
        if (paymentType == ITelemedicinePayments.PaymentType.ETH) {
            (bool success, ) = to.call{value: amount, gas: 30000}("");
            if (!success) revert InsufficientFunds();
        } else if (paymentType == ITelemedicinePayments.PaymentType.USDC) {
            try payments.usdcToken() returns (IERC20Upgradeable usdc) {
                usdc.safeTransferFrom(address(payments), to, amount);
            } catch {
                revert ExternalCallFailed();
            }
        } else if (paymentType == ITelemedicinePayments.PaymentType.SONIC) {
            try payments.sonicToken() returns (IERC20Upgradeable sonic) {
                sonic.safeTransferFrom(address(payments), to, amount);
            } catch {
                revert ExternalCallFailed();
            }
        } else {
            revert InvalidPaymentType();
        }
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

    /// @notice Gets token decimals
    /// @param token Token address
    /// @return Decimals of the token
    function _getTokenDecimals(address token) internal view returns (uint8) {
        try IERC20Upgradeable(token).decimals() returns (uint8 decimals) {
            return decimals;
        } catch {
            revert InvalidToken();
        }
    }

    // Modifiers

    /// @notice Restricts to governance approvers
    modifier onlyGovernanceApprover() {
        if (!governanceApprovers[msg.sender]) revert NotAuthorized();
        _;
    }

    /// @notice Restricts to financial admins
    modifier onlyFinancialAdmin() {
        if (!financialAdmins[msg.sender]) revert NotAuthorized();
        _;
    }

    /// @notice Restricts to governance contract
    modifier onlyGovernance() {
        if (msg.sender != address(this)) revert NotGovernance();
        _;
    }

    /// @notice Requires governance approval via signatures
    /// @param signatures Array of EIP-712 signatures
    modifier governanceApproved(bytes[] calldata signatures) {
        if (signatures.length < requiredApprovals) revert InsufficientApprovals();
        bytes32 actionId = keccak256(msg.data[:32]); // Use first 32 bytes as actionId
        bytes32 structHash = keccak256(abi.encode(
            keccak256("GovernanceAction(address sender,bytes32 actionId,uint256 nonce,uint256 timestamp,uint256 chainid)"),
            msg.sender,
            actionId,
            nonces[msg.sender][actionId],
            block.timestamp,
            block.chainid
        ));
        bytes32 digest = _hashTypedDataV4(structHash);
        address[] memory signers = new address[](signatures.length);
        mapping(address => bool) storage usedSigners; // New: Optimize signer check
        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = digest.recover(signatures[i]);
            if (!governanceApprovers[signer] || usedSigners[signer]) revert InvalidSignature();
            usedSigners[signer] = true;
            signers[i] = signer;
        }
        nonces[msg.sender][actionId]++;
        _;
    }

    // New: Storage gap for future upgrades
    uint256[50] private __gap;

    // Events for Configuration Updates
    event ConfigurationUpdated(bytes4 indexed selector, uint256 value);
}
