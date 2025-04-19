// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {ECDSAUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/ECDSAUpgradeable.sol";
import {ITelemedicineCore} from "./Interfaces/ITelemedicineCore.sol";
import {ITelemedicinePayments} from "./Interfaces/ITelemedicinePayments.sol";

contract GovernanceManager is Initializable, UUPSUpgradeable, EIP712Upgradeable {
    using ECDSAUpgradeable for bytes32;

    ITelemedicineCore public immutable core;
    ITelemedicinePayments public immutable payments;

    address public emergencyAdmin;
    uint256 public requiredApprovals;
    mapping(address => bool) public governanceApprovers;
    mapping(address => bool) public financialAdmins;
    mapping(address => bool) public configAdmins;
    uint256 public governanceApproverCount;
    mapping(bytes4 => bool) public allowedGovernanceSelectors;
    mapping(address => uint256) public nonces;
    bool public reserveWithdrawalPaused;

    struct Proposal {
        bytes32 actionHash;
        uint256 proposalTimestamp;
        uint256 approvalCount;
        uint256 approvalsBitmap;
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

    mapping(uint256 => Proposal) public proposals;
    mapping(uint256 => ReserveWithdrawalRequest) public reserveWithdrawalRequests;
    mapping(address => uint256) public activeWithdrawalRequests;
    uint256 public proposalCounter;
    uint256 public reserveWithdrawalCounter;

    event ProposalCreated(uint256 indexed proposalId, bytes32 actionHash, bytes actionData, address newImplementation, uint256 timestamp, bytes32 actionId);
    event ProposalApproved(uint256 indexed proposalId, address indexed approver);
    event ProposalExecuted(uint256 indexed proposalId, bytes32 actionHash, address newImplementation);
    event ReserveWithdrawalRequested(uint256 indexed requestId, address to, uint256 amount, ITelemedicinePayments.PaymentType paymentType);
    event ReserveWithdrawalExecuted(uint256 indexed requestId, address to, uint256 amount, ITelemedicinePayments.PaymentType paymentType);
    event RoleAssigned(bytes32 indexed role, address indexed account);
    event RoleRevoked(bytes32 indexed role, address indexed account);
    event EmergencyAdminUpdated(address indexed newAdmin);
    event ReserveWithdrawalPaused(bool paused);

    constructor() {
        _disableInitializers();
    }

    function initialize(
        address _core,
        address _payments,
        address _initialApprover,
        address _emergencyAdmin,
        uint256 _requiredApprovals
    ) external initializer {
        if (_core == address(0) || _payments == address(0) || _initialApprover == address(0) || _emergencyAdmin == address(0)) revert InvalidAddress();
        if (_requiredApprovals < 2 || _requiredApprovals > 10) revert InvalidApprovalCount();

        if (ITelemedicineCore(_core).version() < 1) revert InvalidCoreImplementation();
        if (ITelemedicinePayments(_payments).version() < 1) revert InvalidPaymentsImplementation();

        __UUPSUpgradeable_init();
        __EIP712_init("GovernanceManager", "1");

        core = ITelemedicineCore(_core);
        payments = ITelemedicinePayments(_payments);

        requiredApprovals = _requiredApprovals;
        governanceApprovers[_initialApprover] = true;
        configAdmins[_initialApprover] = true;
        governanceApproverCount = 1;
        emergencyAdmin = _emergencyAdmin;

        allowedGovernanceSelectors[this.assignRole.selector] = true;
        allowedGovernanceSelectors[this.revokeRole.selector] = true;
        allowedGovernanceSelectors[this.addPaymentMethod.selector] = true;
        allowedGovernanceSelectors[this.removePaymentMethod.selector] = true;
        allowedGovernanceSelectors[this.setTokenAddress.selector] = true;

        emit RoleAssigned(keccak256("GOVERNANCE_APPROVER"), _initialApprover);
        emit RoleAssigned(keccak256("CONFIG_ADMIN"), _initialApprover);
        emit EmergencyAdminUpdated(_emergencyAdmin);
    }

    function proposeAction(bytes memory actionData, address newImplementation, bytes32 actionId) external onlyGovernanceApprover {
        if (newImplementation != address(0) && actionData.length > 0) revert InvalidProposal();
        if (newImplementation == address(0) && actionData.length > 0) {
            bytes4 selector = bytes4(actionData);
            if (!allowedGovernanceSelectors[selector]) revert InvalidActionSelector();
        }
        proposalCounter++;
        Proposal storage proposal = proposals[proposalCounter];
        bytes32 actionHash = actionData.length > 0 ? keccak256(actionData) : bytes32(0);
        proposal.actionHash = actionHash;
        proposal.proposalTimestamp = block.timestamp;
        proposal.approvalsBitmap = 1 << (uint256(uint160(msg.sender)) % 256);
        proposal.approvalCount = 1;
        proposal.actionData = actionData;
        proposal.newImplementation = newImplementation;
        proposal.actionId = actionId;
        emit ProposalCreated(proposalCounter, actionHash, actionData, newImplementation, block.timestamp, actionId);
    }

    function approveAction(uint256 proposalId) external onlyGovernanceApprover {
        Proposal storage proposal = proposals[proposalId];
        if ((proposal.actionHash == bytes32(0) && proposal.newImplementation == address(0)) || proposal.executed) revert InvalidProposal();
        uint256 approverBit = 1 << (uint256(uint160(msg.sender)) % 256);
        if (proposal.approvalsBitmap & approverBit != 0) revert AlreadyApproved();
        proposal.approvalsBitmap |= approverBit;
        proposal.approvalCount++;
        emit ProposalApproved(proposalId, msg.sender);
        if (proposal.approvalCount >= requiredApprovals && block.timestamp >= proposal.proposalTimestamp + 7 days) {
            if (!_validateDependencies()) revert InvalidDependencyVersion();
            if (proposal.newImplementation != address(0)) {
                _upgradeTo(proposal.newImplementation);
            } else {
                (bool success, bytes memory returnData) = address(this).call(proposal.actionData);
                if (!success) {
                    emit ProposalExecutionFailed(proposalId, returnData);
                    return;
                }
            }
            proposal.executed = true;
            emit ProposalExecuted(proposalId, proposal.actionHash, proposal.newImplementation);
        }
    }

    function assignRole(bytes32 role, address account) external onlyGovernance {
        if (account == address(0)) revert InvalidAddress();
        if (role == keccak256("GOVERNANCE_APPROVER")) {
            if (governanceApprovers[account]) revert AlreadyApprover();
            if (governanceApproverCount >= 10) revert TooManyApprovers();
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

    function revokeRole(bytes32 role, address account) external onlyGovernance {
        if (role == keccak256("GOVERNANCE_APPROVER")) {
            if (!governanceApprovers[account]) revert NotApprover();
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

    function addPaymentMethod(ITelemedicinePayments.PaymentType method, bytes[] calldata signatures) external governanceApproved(signatures) {
        if (method > ITelemedicinePayments.PaymentType.SONIC) revert InvalidPaymentType();
        if (isPaymentMethodSupported(method)) revert PaymentMethodExists();
        isPaymentMethodSupported(method) = true;
        emit PaymentMethodAdded(method);
    }

    function removePaymentMethod(ITelemedicinePayments.PaymentType method, bytes[] calldata signatures) external governanceApproved(signatures) {
        if (method > ITelemedicinePayments.PaymentType.SONIC) revert InvalidPaymentType();
        if (!isPaymentMethodSupported(method)) revert PaymentMethodNotExists();
        isPaymentMethodSupported(method) = false;
        emit PaymentMethodRemoved(method);
    }

    function setTokenAddress(ITelemedicinePayments.PaymentType paymentType, address newToken, bytes[] calldata signatures) external governanceApproved(signatures) {
        if (newToken == address(0)) revert InvalidAddress();
        if (paymentType > ITelemedicinePayments.PaymentType.SONIC) revert InvalidPaymentType();
        uint8 decimals = _getTokenDecimals(newToken);
        if (paymentType == ITelemedicinePayments.PaymentType.USDC) {
            payments.setUsdcToken(newToken);
        } else if (paymentType == ITelemedicinePayments.PaymentType.SONIC) {
            payments.setSonicToken(newToken);
        } else {
            revert InvalidPaymentType();
        }
        emit TokenAddressUpdated(paymentType, newToken);
    }

    function requestReserveWithdrawal(
        address to,
        uint256 amount,
        ITelemedicinePayments.PaymentType paymentType,
        bytes[] calldata signatures
    ) external onlyFinancialAdmin governanceApproved(signatures) {
        if (reserveWithdrawalPaused) revert ReserveWithdrawalPaused();
        if (to == address(0)) revert InvalidAddress();
        if (amount > reserveFunds(paymentType)) revert InsufficientFunds();
        if (amount > reserveFunds(paymentType) * maxReserveWithdrawalPercentage / 100) revert ExceedsWithdrawalLimit();
        if (reserveFunds(paymentType) - amount < minReserveFundThreshold) revert BelowReserveThreshold();
        if (activeWithdrawalRequests[msg.sender] >= 5) revert TooManyWithdrawals();

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

    function executeReserveWithdrawal(uint256 requestId) external onlyFinancialAdmin {
        if (reserveWithdrawalPaused) revert ReserveWithdrawalPaused();
        ReserveWithdrawalRequest storage request = reserveWithdrawalRequests[requestId];
        if (request.to == address(0) || request.executed) revert InvalidWithdrawalRequest();
        if (block.timestamp < request.requestTimestamp + 7 days) revert TimelockNotExpired();
        if (request.amount > reserveFunds(request.paymentType)) revert InsufficientFunds();
        if (reserveFunds(request.paymentType) - request.amount < minReserveFundThreshold) revert BelowReserveThreshold();

        request.executed = true;
        reserveFunds(request.paymentType) -= request.amount;
        reserveFundUsage[request.to] += request.amount;
        activeWithdrawalRequests[msg.sender]--;
        core.updateReserveFund(core.reserveFund() - request.amount);

        _releasePayment(request.to, request.amount, request.paymentType);
        emit ReserveWithdrawalExecuted(requestId, request.to, request.amount, request.paymentType);
    }

    function toggleReserveWithdrawalPause(bool paused, bytes[] calldata signatures) external governanceApproved(signatures) {
        reserveWithdrawalPaused = paused;
        emit ReserveWithdrawalPaused(paused);
    }

    function updateEmergencyAdmin(address newAdmin, bytes[] calldata signatures) external governanceApproved(signatures) {
        if (newAdmin == address(0)) revert InvalidAddress();
        emergencyAdmin = newAdmin;
        emit EmergencyAdminUpdated(newAdmin);
    }

    function _authorizeUpgrade(address newImplementation) internal override onlyGovernance {}

    function _validateDependencies() internal view returns (bool) {
        return core.version() >= 1 && payments.version() >= 1;
    }

    function isPaymentMethodSupported(ITelemedicinePayments.PaymentType paymentType) internal view returns (bool) {
        return false; // Handled by PaymentProcessor
    }

    function reserveFunds(ITelemedicinePayments.PaymentType paymentType) internal view returns (uint256) {
        return 0; // Handled by PaymentProcessor
    }

    function _releasePayment(address to, uint256 amount, ITelemedicinePayments.PaymentType paymentType) internal {
        // Delegate to PaymentProcessor
    }

    function _getTokenDecimals(address token) internal view returns (uint8) {
        (bool success, bytes memory data) = token.staticcall(abi.encodeWithSignature("decimals()"));
        if (!success) revert InvalidToken();
        return abi.decode(data, (uint8));
    }

    modifier onlyGovernanceApprover() {
        if (!governanceApprovers[msg.sender]) revert NotAuthorized();
        _;
    }

    modifier onlyFinancialAdmin() {
        if (!financialAdmins[msg.sender]) revert NotAuthorized();
        _;
    }

    modifier onlyGovernance() {
        if (msg.sender != address(this)) revert NotGovernance();
        _;
    }

    modifier governanceApproved(bytes[] calldata signatures) {
        if (signatures.length < requiredApprovals) revert InsufficientApprovals();
        bytes32 structHash = keccak256(abi.encode(
            keccak256("GovernanceAction(address sender,bytes32 actionId,uint256 nonce,uint256 timestamp,uint256 chainId)"),
            msg.sender,
            keccak256(msg.data[:32]), // Use actionId from msg.data
            nonces[msg.sender],
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
        nonces[msg.sender]++;
        _;
    }

    function _isSignerUsed(address[] memory signers, address signer, uint256 currentIndex) internal pure returns (bool) {
        for (uint256 i = 0; i < currentIndex; i++) {
            if (signers[i] == signer) return true;
        }
        return false;
    }

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
    error ProposalExecutionFailed(uint256 proposalId, bytes returnData);
}
