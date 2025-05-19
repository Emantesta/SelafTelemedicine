// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import {SafeMathUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";
import {IERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {UserOperation} from "@account-abstraction/contracts/interfaces/UserOperation.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {TelemedicineCore} from "./TelemedicineCore.sol";
import {TelemedicineMedicalCore} from "./TelemedicineMedicalCore.sol";
import {TelemedicineMedicalServices} from "./TelemedicineMedicalServices.sol";
import {TelemedicinePayments} from "./TelemedicinePayments.sol";
import {TelemedicineDisputeResolution} from "./TelemedicineDisputeResolution.sol";

/// @title TelemedicineGovernanceCore
/// @notice Manages governance, timelocks, and account abstraction
/// @dev UUPS upgradeable, integrates with core, medical, payments, and dispute contracts
contract TelemedicineGovernanceCore is Initializable, UUPSUpgradeable, ReentrancyGuardUpgradeable, PausableUpgradeable {
    using SafeMathUpgradeable for uint256;
    using ECDSA for bytes32;

    // Immutable Dependencies
    TelemedicineCore public immutable core;
    TelemedicineMedicalCore public immutable medicalCore;
    TelemedicineMedicalServices public immutable medicalServices;
    TelemedicinePayments public immutable payments;
    TelemedicineDisputeResolution public immutable disputeResolution;

    // Configurable State
    IEntryPoint public entryPoint;
    address public paymaster;
    address public dataAccessOracle;
    uint256 public timeLockDelay;
    uint256 public requiredApprovals;
    uint256 public versionNumber; // New: Track version

    // Constants
    uint256 public constant MIN_TIMELOCK_DELAY = 2 days;
    uint256 public constant MIN_FEE = 0.01 * 10**6; // New: 0.01 USDC (6 decimals)
    uint256 public constant MAX_COUNTER = 1_000_000; // New: Limit counter
    uint256 public constant MIN_IPFS_HASH_LENGTH = 46; // New: Minimum IPFS hash length

    // Private Mappings
    mapping(address => uint256) private nonces; // Updated: Private
    mapping(address => bool) private trustedPaymasters; // Updated: Private
    mapping(uint256 => TimeLock) private timeLocks; // Updated: Private
    uint256 private timeLockCounter;

    // Enums
    enum TimeLockAction {
        WithdrawFunds, AddAdmin, RemoveAdmin, AdjustFee, AdjustMaxEmergencyWithdrawal, UpgradeContract, DisputeResolution,
        UpdateChainlinkConfig, ToggleManualPriceOverride, ReleasePendingPayments, UpdateInvitationConfig,
        UpdateMultiSigConfig, UpdateLabTechPrice, UpdatePharmacyPrice, UpdateMedicalServiceConfig, ConfigurationUpdate // Updated: Align with TelemedicineBase
    }

    // Structs
    struct TimeLock {
        uint256 id;
        TimeLockAction action;
        address target;
        uint256 value;
        bytes32 dataHash; // Updated: Hashed data
        uint256 timestamp;
        address[] approvers; // Updated: Array instead of mapping
        bool executed;
        bool cancelled;
    }

    // Events
    event PaymasterUpdated(bytes32 indexed oldPaymasterHash, bytes32 indexed newPaymasterHash);
    event UserOperationExecuted(bytes32 indexed senderHash, uint256 nonce, bytes32 hash);
    event TrustedPaymasterAdded(bytes32 indexed paymasterHash);
    event TrustedPaymasterRemoved(bytes32 indexed paymasterHash);
    event TimeLockQueued(uint256 indexed id, TimeLockAction action, bytes32 targetHash, uint256 value, bytes32 dataHash, uint256 timestamp);
    event TimeLockApproved(uint256 indexed id, bytes32 indexed approverHash);
    event TimeLockExecuted(uint256 indexed id);
    event TimeLockCancelled(uint256 indexed id, bytes32 indexed cancellerHash);
    event ConstantUpdated(string indexed name, uint256 newValue);
    event DoctorFeeAdjustmentRequested(bytes32 indexed doctorHash, uint256 newFee, uint256 timeLockId);
    event GamificationParameterUpdated(string indexed parameter, uint256 newValue);
    event EntryPointUpdated(bytes32 indexed oldEntryPointHash, bytes32 indexed newEntryPointHash);
    event ConfigurationUpdated(string indexed parameter, uint256 value);
    event PaymentReleasedFromQueue(uint256 indexed paymentId, bytes32 recipientHash, uint256 amount);
    event MultiSigConfigUpdated(uint256 requiredSignatures, bytes32[] signerHashes);
    event LabTechPriceUpdated(bytes32 indexed labTechHash, bytes32 testTypeIpfsHash, uint256 price, uint48 timestamp);
    event PharmacyPriceUpdated(bytes32 indexed pharmacyHash, bytes32 medicationIpfsHash, uint256 price, uint48 timestamp);

    // Errors
    error InvalidAddress();
    error InvalidNonce();
    error InsufficientBalance();
    error InvalidSignature();
    error NotAuthorized();
    error ContractPaused();
    error InvalidTimeLock();
    error AlreadyExecuted();
    error AlreadyCancelled();
    error InsufficientApprovals();
    error TimeLockNotMatured();
    error AlreadyApproved();
    error InvalidFee();
    error InvalidParameter();
    error InvalidCounter();
    error ExternalCallFailed();
    error InvalidIPFSHash();
    error InvalidApprovalCount();
    error InvalidEntryPoint();
    error PaymasterPaymentFailed();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the contract
    /// @param _core Core contract address
    /// @param _medicalCore Medical core contract address
    /// @param _medicalServices Medical services contract address
    /// @param _payments Payments contract address
    /// @param _disputeResolution Dispute resolution contract address
    /// @param _entryPoint EntryPoint contract address
    /// @param _paymaster Paymaster address
    /// @param _dataAccessOracle Data access oracle address
    function initialize(
        address _core,
        address _medicalCore,
        address _medicalServices,
        address _payments,
        address _disputeResolution,
        address _entryPoint,
        address _paymaster,
        address _dataAccessOracle
    ) external initializer {
        if (_core == address(0) || _medicalCore == address(0) || _medicalServices == address(0) ||
            _payments == address(0) || _disputeResolution == address(0) || _entryPoint == address(0) ||
            _paymaster == address(0) || _dataAccessOracle == address(0)) revert InvalidAddress();
        if (!_isContract(_core) || !_isContract(_medicalCore) || !_isContract(_medicalServices) ||
            !_isContract(_payments) || !_isContract(_disputeResolution) || !_isContract(_entryPoint) ||
            !_isContract(_paymaster)) revert InvalidAddress();

        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        __Pausable_init();

        core = TelemedicineCore(_core);
        medicalCore = TelemedicineMedicalCore(_medicalCore);
        medicalServices = TelemedicineMedicalServices(_medicalServices);
        payments = TelemedicinePayments(_payments);
        disputeResolution = TelemedicineDisputeResolution(_disputeResolution);
        entryPoint = IEntryPoint(_entryPoint);
        paymaster = _paymaster;
        dataAccessOracle = _dataAccessOracle;
        trustedPaymasters[_paymaster] = true;
        timeLockDelay = MIN_TIMELOCK_DELAY;

        try core.admins() returns (address[] memory admins) {
            requiredApprovals = admins.length > 0 ? admins.length / 2 + 1 : 1;
        } catch {
            revert ExternalCallFailed();
        }
        versionNumber = 1;
    }

    /// @notice Returns the contract version
    /// @return Version number
    function version() external view returns (uint256) {
        return versionNumber;
    }

    /// @notice Authorizes an upgrade
    /// @param newImplementation New implementation address
    function _authorizeUpgrade(address newImplementation) internal override onlyConfigAdmin {
        if (!_isContract(newImplementation)) revert InvalidAddress();
        versionNumber++;
    }

    // Account Abstraction

    /// @notice Validates a user operation
    /// @param userOp User operation
    /// @param userOpHash User operation hash
    /// @param missingAccountFunds Missing funds
    /// @return Validation data
    function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        onlyEntryPoint
        whenNotPaused
        returns (uint256 validationData)
    {
        if (nonces[userOp.sender] != userOp.nonce) revert InvalidNonce();
        bytes32 messageHash = keccak256(abi.encodePacked("\x19\x01", block.chainid, address(this), userOpHash)).toEthSignedMessageHash();
        address signer;
        try ECDSA.recover(messageHash, userOp.signature) returns (address recovered) {
            signer = recovered;
        } catch {
            revert InvalidSignature();
        }
        if (signer != userOp.sender || signer == address(0)) revert InvalidSignature();

        nonces[userOp.sender] = nonces[userOp.sender].add(1) % 1_000_000; // New: Cap nonces
        if (missingAccountFunds > 0) {
            if (!trustedPaymasters[msg.sender]) revert NotAuthorized();
            if (!_isContract(msg.sender) || address(msg.sender).balance < missingAccountFunds) revert PaymasterPaymentFailed();
            (bool success, ) = paymaster.call{value: missingAccountFunds}("");
            if (!success) revert PaymasterPaymentFailed();
        }

        emit UserOperationExecuted(keccak256(abi.encode(userOp.sender)), userOp.nonce, userOpHash);
        return 0;
    }

    /// @notice Executes a user operation
    /// @param userOp User operation
    function executeUserOp(UserOperation calldata userOp) external onlyEntryPoint nonReentrant whenNotPaused {
        bool isAuthorized;
        try core.hasRole(core.PATIENT_ROLE(), userOp.sender) returns (bool isPatient) {
            isAuthorized = isPatient;
        } catch {
            revert ExternalCallFailed();
        }
        if (!isAuthorized) {
            try core.hasRole(core.DOCTOR_ROLE(), userOp.sender) returns (bool isDoctor) {
                isAuthorized = isDoctor || userOp.sender == msg.sender;
            } catch {
                revert ExternalCallFailed();
            }
        }
        if (!isAuthorized) revert NotAuthorized();

        (bool success, bytes memory result) = address(this).call(userOp.callData);
        if (!success) revert(string(abi.encodePacked("User op failed: ", _getRevertMsg(result))));
        if (userOp.callGasLimit > 0) {
            UserOperation[] memory ops = new UserOperation[](1);
            ops[0] = userOp;
            try entryPoint.handleOps(ops, payable(msg.sender)) {} catch {
                revert ExternalCallFailed();
            }
        }
    }

    // Paymaster Management

    /// @notice Updates the primary paymaster
    /// @param _newPaymaster New paymaster address
    function updatePaymaster(address _newPaymaster) external onlyConfigAdmin whenNotPaused {
        if (_newPaymaster == address(0) || !_isContract(_newPaymaster)) revert InvalidAddress();
        address oldPaymaster = paymaster;
        paymaster = _newPaymaster;
        trustedPaymasters[_newPaymaster] = true;
        trustedPaymasters[oldPaymaster] = false;
        emit PaymasterUpdated(keccak256(abi.encode(oldPaymaster)), keccak256(abi.encode(_newPaymaster)));
    }

    /// @notice Adds a trusted paymaster
    /// @param _paymaster Paymaster address
    function addTrustedPaymaster(address _paymaster) external onlyConfigAdmin whenNotPaused {
        if (_paymaster == address(0) || !_isContract(_paymaster)) revert InvalidAddress();
        if (trustedPaymasters[_paymaster]) revert InvalidAddress();
        trustedPaymasters[_paymaster] = true;
        emit TrustedPaymasterAdded(keccak256(abi.encode(_paymaster)));
    }

    /// @notice Removes a trusted paymaster
    /// @param _paymaster Paymaster address
    function removeTrustedPaymaster(address _paymaster) external onlyConfigAdmin whenNotPaused {
        if (_paymaster == address(0) || !trustedPaymasters[_paymaster] || _paymaster == paymaster) revert InvalidAddress();
        trustedPaymasters[_paymaster] = false;
        emit TrustedPaymasterRemoved(keccak256(abi.encode(_paymaster)));
    }

    // TimeLock Functions

    /// @notice Queues a timelock
    /// @param _action Action type
    /// @param _target Target address
    /// @param _value Value
    /// @param _data Calldata
    /// @return TimeLock ID
    function _queueTimeLock(TimeLockAction _action, address _target, uint256 _value, bytes memory _data)
        public
        onlyConfigAdmin
        returns (uint256)
    {
        if (timeLockCounter >= MAX_COUNTER) revert InvalidCounter();
        timeLockCounter = timeLockCounter.add(1);
        TimeLock storage tl = timeLocks[timeLockCounter];
        tl.id = timeLockCounter;
        tl.action = _action;
        tl.target = _target;
        tl.value = _value;
        tl.dataHash = keccak256(_data);
        tl.timestamp = block.timestamp;
        tl.approvers.push(msg.sender);
        emit TimeLockQueued(timeLockCounter, _action, keccak256(abi.encode(_target)), _value, tl.dataHash, block.timestamp);
        return timeLockCounter;
    }

    /// @notice Approves multiple timelocks
    /// @param _timeLockIds TimeLock IDs
    function batchApproveTimeLocks(uint256[] calldata _timeLockIds) external onlyConfigAdmin whenNotPaused {
        for (uint256 i = 0; i < _timeLockIds.length; i++) {
            uint256 _timeLockId = _timeLockIds[i];
            TimeLock storage tl = timeLocks[_timeLockId];
            if (tl.executed) revert AlreadyExecuted();
            if (tl.cancelled) revert AlreadyCancelled();
            bool alreadyApproved;
            for (uint256 j = 0; j < tl.approvers.length; j++) {
                if (tl.approvers[j] == msg.sender) {
                    alreadyApproved = true;
                    break;
                }
            }
            if (alreadyApproved) revert AlreadyApproved();
            tl.approvers.push(msg.sender);
            emit TimeLockApproved(_timeLockId, keccak256(abi.encode(msg.sender)));
        }
    }

    /// @notice Cancels a timelock
    /// @param _timeLockId TimeLock ID
    function cancelTimeLock(uint256 _timeLockId) external onlyConfigAdmin whenNotPaused {
        TimeLock storage tl = timeLocks[_timeLockId];
        if (tl.executed) revert AlreadyExecuted();
        if (tl.cancelled) revert AlreadyCancelled();
        if (tl.timestamp.add(timeLockDelay) <= block.timestamp) revert TimeLockNotMatured();
        tl.cancelled = true;
        emit TimeLockCancelled(_timeLockId, keccak256(abi.encode(msg.sender)));
    }

    /// @notice Executes multiple timelocks
    /// @param _timeLockIds TimeLock IDs
    /// @param _datas Calldatas
    function batchExecuteTimeLocks(uint256[] calldata _timeLockIds, bytes[] calldata _datas) external onlyConfigAdmin nonReentrant whenNotPaused {
        if (_timeLockIds.length != _datas.length) revert InvalidTimeLock();
        address[] memory admins;
        try core.admins() returns (address[] memory adminList) {
            admins = adminList;
        } catch {
            revert ExternalCallFailed();
        }
        for (uint256 i = 0; i < _timeLockIds.length; i++) {
            uint256 _timeLockId = _timeLockIds[i];
            TimeLock storage tl = timeLocks[_timeLockId];
            if (tl.executed) continue;
            if (tl.cancelled) continue;
            if (tl.approvers.length < requiredApprovals) revert InsufficientApprovals();
            if (block.timestamp < tl.timestamp.add(timeLockDelay)) revert TimeLockNotMatured();
            if (keccak256(_datas[i]) != tl.dataHash) revert InvalidTimeLock();

            tl.executed = true;
            (bool success, bytes memory result) = tl.target.call{value: tl.value}(_datas[i]);
            if (!success) revert(string(abi.encodePacked("Execution failed: ", _getRevertMsg(result))));

            if (tl.action == TimeLockAction.AddAdmin) {
                try core.grantRole(core.ADMIN_ROLE(), tl.target) {} catch {
                    revert ExternalCallFailed();
                }
                admins.push(tl.target);
                requiredApprovals = admins.length > 0 ? admins.length / 2 + 1 : 1;
            } else if (tl.action == TimeLockAction.RemoveAdmin) {
                bool found;
                for (uint256 j = 0; j < admins.length; j++) {
                    if (admins[j] == tl.target) {
                        admins[j] = admins[admins.length - 1];
                        admins.pop();
                        found = true;
                        break;
                    }
                }
                if (!found) revert InvalidAddress();
                try core.revokeRole(core.ADMIN_ROLE(), tl.target) {} catch {
                    revert ExternalCallFailed();
                }
                requiredApprovals = admins.length > 0 ? admins.length / 2 + 1 : 1;
            } else if (tl.action == TimeLockAction.ReleasePendingPayments) {
                emit PaymentReleasedFromQueue(tl.value, keccak256(abi.encode(tl.target)), tl.value);
            } else if (tl.action == TimeLockAction.UpdateLabTechPrice) {
                (string memory testTypeIpfsHash, uint256 price) = abi.decode(_datas[i], (string, uint256));
                emit LabTechPriceUpdated(keccak256(abi.encode(tl.target)), keccak256(abi.encode(testTypeIpfsHash)), price, uint48(block.timestamp));
            } else if (tl.action == TimeLockAction.UpdatePharmacyPrice) {
                (string memory medicationIpfsHash, uint256 price) = abi.decode(_datas[i], (string, uint256));
                emit PharmacyPriceUpdated(keccak256(abi.encode(tl.target)), keccak256(abi.encode(medicationIpfsHash)), price, uint48(block.timestamp));
            }
            emit TimeLockExecuted(_timeLockId);
        }
    }

    // Governance Actions

    /// @notice Queues fund withdrawal
    /// @param _to Recipient
    /// @param _amount Amount
    function queueWithdrawFunds(address payable _to, uint256 _amount) external onlyConfigAdmin {
        if (_to == address(0)) revert InvalidAddress();
        uint256 contractBalance;
        uint256 reserveBalance;
        try core.getContractBalance() returns (uint256 balance) {
            contractBalance = balance;
        } catch {
            revert ExternalCallFailed();
        }
        try core.getReserveFundBalance() returns (uint256 reserve) {
            reserveBalance = reserve;
        } catch {
            revert ExternalCallFailed();
        }
        if (_amount > contractBalance.sub(reserveBalance)) revert InsufficientBalance();
        bytes memory data = abi.encodeWithSignature("safeTransferETH(address,uint256)", _to, _amount);
        _queueTimeLock(TimeLockAction.WithdrawFunds, _to, _amount, data);
    }

    /// @notice Requests doctor fee adjustment
    /// @param _newFee New fee
    function requestFeeAdjustment(uint256 _newFee) external onlyRole(core.DOCTOR_ROLE()) whenNotPaused {
        TelemedicineCore.Doctor memory doctor;
        try core.doctors(msg.sender) returns (TelemedicineCore.Doctor memory d) {
            doctor = d;
        } catch {
            revert ExternalCallFailed();
        }
        if (!doctor.isVerified) revert NotAuthorized();
        if (_newFee <= MIN_FEE || _newFee > type(uint96).max) revert InvalidFee();
        bytes memory data = abi.encodeWithSignature("updateDoctorFee(address,uint256)", msg.sender, _newFee);
        uint256 timeLockId = _queueTimeLock(TimeLockAction.AdjustFee, msg.sender, _newFee, data);
        emit DoctorFeeAdjustmentRequested(keccak256(abi.encode(msg.sender)), _newFee, timeLockId);
    }

    /// @notice Updates doctor fee
    /// @param _doctor Doctor address
    /// @param _newFee New fee
    function updateDoctorFee(address _doctor, uint256 _newFee) external onlyConfigAdmin {
        if (_newFee <= MIN_FEE || _newFee > type(uint96).max) revert InvalidFee();
        try core.doctors(_doctor) returns (TelemedicineCore.Doctor storage doctor) {
            doctor.consultationFee = uint96(_newFee);
        } catch {
            revert ExternalCallFailed();
        }
    }

    /// @notice Queues admin addition
    /// @param _newAdmin New admin address
    function queueAddAdmin(address _newAdmin) external onlyConfigAdmin whenNotPaused {
        if (_newAdmin == address(0)) revert InvalidAddress();
        try core.MAX_ADMINS() returns (uint256 maxAdmins) {
            try core.admins() returns (address[] memory admins) {
                if (admins.length >= maxAdmins) revert InvalidAddress();
            } catch {
                revert ExternalCallFailed();
            }
        } catch {
            revert ExternalCallFailed();
        }
        bytes memory data = abi.encodeWithSignature("grantRole(bytes32,address)", core.ADMIN_ROLE(), _newAdmin);
        _queueTimeLock(TimeLockAction.AddAdmin, _newAdmin, 0, data);
    }

    /// @notice Queues admin removal
    /// @param _admin Admin address
    function queueRemoveAdmin(address _admin) external onlyConfigAdmin whenNotPaused {
        if (_admin == address(0)) revert InvalidAddress();
        try core.admins() returns (address[] memory admins) {
            if (admins.length <= 1) revert InvalidAddress();
        } catch {
            revert ExternalCallFailed();
        }
        bytes memory data = abi.encodeWithSignature("revokeRole(bytes32,address)", core.ADMIN_ROLE(), _admin);
        _queueTimeLock(TimeLockAction.RemoveAdmin, _admin, 0, data);
    }

    // Dispute Resolution Integration

    /// @notice Queues dispute resolution
    /// @param _disputeId Dispute ID
    /// @param _patientWins Patient win flag
    /// @param _resolutionReason Resolution reason hash
    function queueResolveDispute(uint256 _disputeId, bool _patientWins, bytes32 _resolutionReason)
        external
        onlyConfigAdmin
        nonReentrant
        whenNotPaused
    {
        try disputeResolution.disputes(_disputeId) returns (TelemedicineDisputeResolution.Dispute memory dispute) {
            if (dispute.status != TelemedicineDisputeResolution.DisputeStatus.Escalated) revert InvalidTimeLock();
        } catch {
            revert ExternalCallFailed();
        }
        if (_resolutionReason == bytes32(0)) revert InvalidParameter();
        bytes memory data = abi.encodeWithSignature("executeResolveDispute(uint256,bool,bytes32)", _disputeId, _patientWins, _resolutionReason);
        _queueTimeLock(TimeLockAction.DisputeResolution, address(disputeResolution), 0, data);
    }

    /// @notice Executes dispute resolution
    /// @param _disputeId Dispute ID
    /// @param _patientWins Patient win flag
    /// @param _resolutionReason Resolution reason hash
    function executeResolveDispute(uint256 _disputeId, bool _patientWins, bytes32 _resolutionReason)
        external
        onlyConfigAdmin
        nonReentrant
        whenNotPaused
    {
        try disputeResolution.executeResolveDispute(_disputeId, _patientWins, _resolutionReason) {} catch {
            revert ExternalCallFailed();
        }
    }

    // Configuration Updates with Timelock

    /// @notice Queues ramp fee update
    /// @param _rampType Ramp type
    /// @param _newFee New fee
    function queueUpdateRampFee(string calldata _rampType, uint256 _newFee) external onlyConfigAdmin {
        if (_newFee < MIN_FEE) revert InvalidFee();
        bytes memory data = abi.encodeWithSignature("setRampFee(string,uint256)", _rampType, _newFee);
        _queueTimeLock(TimeLockAction.AdjustFee, address(payments), _newFee, data);
    }

    /// @notice Sets ramp fee
    /// @param _rampType Ramp type
    /// @param _newFee New fee
    function setRampFee(string calldata _rampType, uint256 _newFee) external onlyConfigAdmin {
        if (_newFee < MIN_FEE) revert InvalidFee();
        bytes32 rampHash = keccak256(abi.encodePacked(_rampType));
        if (rampHash == keccak256(abi.encodePacked("onRamp"))) {
            payments.onRampFee = _newFee;
        } else if (rampHash == keccak256(abi.encodePacked("offRamp"))) {
            payments.offRampFee = _newFee;
        } else {
            revert InvalidParameter();
        }
        emit ConstantUpdated(_rampType, _newFee);
    }

    /// @notice Queues minimum booking buffer update
    /// @param _newBuffer New buffer
    function queueUpdateMinBookingBuffer(uint256 _newBuffer) external onlyConfigAdmin {
        if (_newBuffer < 5 minutes) revert InvalidParameter();
        bytes memory data = abi.encodeWithSignature("setMinBookingBuffer(uint256)", _newBuffer);
        _queueTimeLock(TimeLockAction.AdjustFee, address(core), _newBuffer, data);
    }

    /// @notice Sets minimum booking buffer
    /// @param _newBuffer New buffer
    function setMinBookingBuffer(uint256 _newBuffer) external onlyConfigAdmin {
        if (_newBuffer < 5 minutes) revert InvalidParameter();
        core.minBookingBuffer = _newBuffer;
        emit ConstantUpdated("minBookingBuffer", _newBuffer);
    }

    /// @notice Queues minimum cancellation buffer update
    /// @param _newBuffer New buffer
    function queueUpdateMinCancellationBuffer(uint256 _newBuffer) external onlyConfigAdmin {
        if (_newBuffer < 30 minutes) revert InvalidParameter();
        bytes memory data = abi.encodeWithSignature("setMinCancellationBuffer(uint256)", _newBuffer);
        _queueTimeLock(TimeLockAction.AdjustFee, address(core), _newBuffer, data);
    }

    /// @notice Sets minimum cancellation buffer
    /// @param _newBuffer New buffer
    function setMinCancellationBuffer(uint256 _newBuffer) external onlyConfigAdmin {
        if (_newBuffer < 30 minutes) revert InvalidParameter();
        core.minCancellationBuffer = _newBuffer;
        emit ConstantUpdated("minCancellationBuffer", _newBuffer);
    }

    /// @notice Queues verification timeout update
    /// @param _newTimeout New timeout
    function queueUpdateVerificationTimeout(uint256 _newTimeout) external onlyConfigAdmin {
        if (_newTimeout < 1 days) revert InvalidParameter();
        bytes memory data = abi.encodeWithSignature("setVerificationTimeout(uint256)", _newTimeout);
        _queueTimeLock(TimeLockAction.AdjustFee, address(core), _newTimeout, data);
    }

    /// @notice Sets verification timeout
    /// @param _newTimeout New timeout
    function setVerificationTimeout(uint256 _newTimeout) external onlyConfigAdmin {
        if (_newTimeout < 1 days) revert InvalidParameter();
        core.verificationTimeout = _newTimeout;
        emit ConstantUpdated("verificationTimeout", _newTimeout);
    }

    /// @notice Queues data monetization reward update
    /// @param _newReward New reward
    function queueUpdateDataMonetizationReward(uint256 _newReward) external onlyConfigAdmin {
        if (_newReward <= 0) revert InvalidParameter();
        try payments.sonicToken() returns (IERC20Upgradeable sonicToken) {
            try sonicToken.balanceOf(address(payments)) returns (uint256 balance) {
                if (balance < _newReward) revert InsufficientBalance();
            } catch {
                revert ExternalCallFailed();
            }
        } catch {
            revert ExternalCallFailed();
        }
        bytes memory data = abi.encodeWithSignature("setDataMonetizationReward(uint256)", _newReward);
        _queueTimeLock(TimeLockAction.AdjustFee, address(core), _newReward, data);
    }

    /// @notice Sets data monetization reward
    /// @param _newReward New reward
    function setDataMonetizationReward(uint256 _newReward) external onlyConfigAdmin {
        if (_newReward <= 0) revert InvalidParameter();
        core.dataMonetizationReward = _newReward;
        emit ConstantUpdated("dataMonetizationReward", _newReward);
    }

    /// @notice Queues AI analysis cost update
    /// @param _newCost New cost
    function queueUpdateAIAnalysisCost(uint256 _newCost) external onlyConfigAdmin {
        if (_newCost <= 0) revert InvalidParameter();
        bytes memory data = abi.encodeWithSignature("setAIAnalysisCost(uint256)", _newCost);
        _queueTimeLock(TimeLockAction.AdjustFee, address(core), _newCost, data);
    }

    /// @notice Sets AI analysis cost
    /// @param _newCost New cost
    function setAIAnalysisCost(uint256 _newCost) external onlyConfigAdmin {
        if (_newCost <= 0) revert InvalidParameter();
        core.aiAnalysisCost = _newCost;
        emit ConstantUpdated("aiAnalysisCost", _newCost);
    }

    /// @notice Queues points per level update
    /// @param _newPoints New points
    function queueUpdatePointsPerLevel(uint256 _newPoints) external onlyConfigAdmin {
        if (_newPoints <= 0) revert InvalidParameter();
        bytes memory data = abi.encodeWithSignature("setPointsPerLevel(uint256)", _newPoints);
        _queueTimeLock(TimeLockAction.AdjustFee, address(core), _newPoints, data);
    }

    /// @notice Sets points per level
    /// @param _newPoints New points
    function setPointsPerLevel(uint256 _newPoints) external onlyConfigAdmin {
        if (_newPoints <= 0) revert InvalidParameter();
        core.pointsPerLevel = _newPoints;
        emit GamificationParameterUpdated("pointsPerLevel", _newPoints);
    }

    /// @notice Queues max level update
    /// @param _newMax New max level
    function queueUpdateMaxLevel(uint8 _newMax) external onlyConfigAdmin {
        if (_newMax <= 0) revert InvalidParameter();
        bytes memory data = abi.encodeWithSignature("setMaxLevel(uint8)", _newMax);
        _queueTimeLock(TimeLockAction.AdjustFee, address(core), _newMax, data);
    }

    /// @notice Sets max level
    /// @param _newMax New max level
    function setMaxLevel(uint8 _newMax) external onlyConfigAdmin {
        if (_newMax <= 0) revert InvalidParameter();
        core.maxLevel = _newMax;
        emit GamificationParameterUpdated("maxLevel", _newMax);
    }

    /// @notice Queues decay rate update
    /// @param _newRate New rate
    function queueUpdateDecayRate(uint256 _newRate) external onlyConfigAdmin {
        if (_newRate <= 0) revert InvalidParameter();
        bytes memory data = abi.encodeWithSignature("setDecayRate(uint256)", _newRate);
        _queueTimeLock(TimeLockAction.AdjustFee, address(core), _newRate, data);
    }

    /// @notice Sets decay rate
    /// @param _newRate New rate
    function setDecayRate(uint256 _newRate) external onlyConfigAdmin {
        if (_newRate <= 0) revert InvalidParameter();
        core.decayRate = _newRate;
        emit GamificationParameterUpdated("decayRate", _newRate);
    }

    /// @notice Queues decay period update
    /// @param _newPeriod New period
    function queueUpdateDecayPeriod(uint256 _newPeriod) external onlyConfigAdmin {
        if (_newPeriod < 1 days) revert InvalidParameter();
        bytes memory data = abi.encodeWithSignature("setDecayPeriod(uint256)", _newPeriod);
        _queueTimeLock(TimeLockAction.AdjustFee, address(core), _newPeriod, data);
    }

    /// @notice Sets decay period
    /// @param _newPeriod New period
    function setDecayPeriod(uint256 _newPeriod) external onlyConfigAdmin {
        if (_newPeriod < 1 days) revert InvalidParameter();
        core.decayPeriod = _newPeriod;
        emit GamificationParameterUpdated("decayPeriod", _newPeriod);
    }

    /// @notice Queues free analysis period update
    /// @param _newPeriod New period
    function queueUpdateFreeAnalysisPeriod(uint256 _newPeriod) external onlyConfigAdmin {
        if (_newPeriod < 7 days) revert InvalidParameter();
        bytes memory data = abi.encodeWithSignature("setFreeAnalysisPeriod(uint256)", _newPeriod);
        _queueTimeLock(TimeLockAction.AdjustFee, address(core), _newPeriod, data);
    }

    /// @notice Sets free analysis period
    /// @param _newPeriod New period
    function setFreeAnalysisPeriod(uint256 _newPeriod) external onlyConfigAdmin {
        if (_newPeriod < 7 days) revert InvalidParameter();
        core.freeAnalysisPeriod = _newPeriod;
        emit GamificationParameterUpdated("freeAnalysisPeriod", _newPeriod);
    }

    /// @notice Queues minimum reserve balance update
    /// @param _newMin New minimum
    function queueUpdateMinReserveBalance(uint256 _newMin) external onlyConfigAdmin {
        try core.RESERVE_FUND_THRESHOLD() returns (uint256 threshold) {
            if (_newMin < threshold) revert InvalidParameter();
        } catch {
            revert ExternalCallFailed();
        }
        bytes memory data = abi.encodeWithSignature("setMinReserveBalance(uint256)", _newMin);
        _queueTimeLock(TimeLockAction.AdjustFee, address(core), _newMin, data);
    }

    /// @notice Sets minimum reserve balance
    /// @param _newMin New minimum
    function setMinReserveBalance(uint256 _newMin) external onlyConfigAdmin {
        try core.RESERVE_FUND_THRESHOLD() returns (uint256 threshold) {
            if (_newMin < threshold) revert InvalidParameter();
        } catch {
            revert ExternalCallFailed();
        }
        core.minReserveBalance = _newMin;
        emit ConstantUpdated("minReserveBalance", _newMin);
    }

    // TelemedicineMedicalCore Configuration Updates

    /// @notice Queues medical core configuration update
    /// @param _parameter Parameter name
    /// @param _value Value
    function queueUpdateMedicalCoreConfig(string calldata _parameter, uint256 _value) external onlyConfigAdmin {
        bytes memory data = abi.encodeWithSignature("updateConfiguration(string,uint256)", _parameter, _value);
        _queueTimeLock(TimeLockAction.ConfigurationUpdate, address(medicalCore), _value, data);
    }

    /// @notice Queues Chainlink configuration update
    /// @param _newOracle New oracle address
    /// @param _newJobId New job ID
    /// @param _newFee New fee
    function queueUpdateChainlinkConfig(address _newOracle, bytes32 _newJobId, uint256 _newFee)
        external
        onlyConfigAdmin
    {
        if (_newOracle == address(0) || !_isContract(_newOracle) || _newJobId == bytes32(0) || _newFee <= 0) revert InvalidParameter();
        bytes memory data = abi.encodeWithSignature("updateChainlinkConfig(address,bytes32,uint256)", _newOracle, _newJobId, _newFee);
        _queueTimeLock(TimeLockAction.UpdateChainlinkConfig, address(medicalCore), _newFee, data);
    }

    /// @notice Updates Chainlink configuration
    /// @param _newOracle New oracle address
    /// @param _newJobId New job ID
    /// @param _newFee New fee
    function updateChainlinkConfig(address _newOracle, bytes32 _newJobId, uint256 _newFee)
        external
        onlyConfigAdmin
    {
        if (_newOracle == address(0) || !_isContract(_newOracle) || _newJobId == bytes32(0) || _newFee <= 0) revert InvalidParameter();
        medicalCore.chainlinkOracle = _newOracle;
        medicalCore.priceListJobId = _newJobId;
        medicalCore.chainlinkFee = _newFee;
        emit ConfigurationUpdated("chainlinkConfig", _newFee);
    }

    /// @notice Queues manual price override toggle
    /// @param _enabled Enabled flag
    function queueToggleManualPriceOverride(bool _enabled) external onlyConfigAdmin {
        bytes memory data = abi.encodeWithSignature("toggleManualPriceOverride(bool)", _enabled);
        _queueTimeLock(TimeLockAction.ToggleManualPriceOverride, address(medicalCore), _enabled ? 1 : 0, data);
    }

    /// @notice Toggles manual price override
    /// @param _enabled Enabled flag
    function toggleManualPriceOverride(bool _enabled) external onlyConfigAdmin {
        try medicalCore.toggleManualPriceOverride(_enabled) {} catch {
            revert ExternalCallFailed();
        }
        emit ConfigurationUpdated("manualPriceOverride", _enabled ? 1 : 0);
    }

    /// @notice Queues release of pending payments
    /// @param _startId Start ID
    /// @param _count Count
    function queueReleasePendingPayments(uint256 _startId, uint256 _count) external onlyConfigAdmin {
        if (_count <= 0) revert InvalidParameter();
        bytes memory data = abi.encodeWithSignature("releasePendingPayments(uint256,uint256)", _startId, _count);
        _queueTimeLock(TimeLockAction.ReleasePendingPayments, address(medicalCore), _count, data);
    }

    /// @notice Queues invitation expiration period update
    /// @param _newPeriod New period
    function queueUpdateInvitationExpirationPeriod(uint48 _newPeriod) external onlyConfigAdmin {
        if (_newPeriod <= 0) revert InvalidParameter();
        bytes memory data = abi.encodeWithSignature("updateConfiguration(string,uint256)", "invitationExpirationPeriod", _newPeriod);
        _queueTimeLock(TimeLockAction.UpdateInvitationConfig, address(medicalCore), _newPeriod, data);
    }

    // TelemedicineMedicalServices Configuration Updates

    /// @notice Queues medical service configuration update
    /// @param _parameter Parameter name
    /// @param _value Value
    function queueUpdateMedicalServiceConfig(string calldata _parameter, uint256 _value) external onlyConfigAdmin {
        bytes memory data;
        if (keccak256(abi.encodePacked(_parameter)) == keccak256(abi.encodePacked("requiredSignatures"))) {
            data = abi.encodeWithSignature("updateRequiredSignatures(uint256)", _value);
        } else {
            revert InvalidParameter();
        }
        _queueTimeLock(TimeLockAction.UpdateMedicalServiceConfig, address(medicalServices), _value, data);
    }

    /// @notice Updates required signatures
    /// @param _newSignatures New signature count
    function updateRequiredSignatures(uint256 _newSignatures) external onlyConfigAdmin {
        try medicalServices.multiSigSigners() returns (address[] memory signers) {
            if (_newSignatures <= 0 || _newSignatures > signers.length) revert InvalidApprovalCount();
        } catch {
            revert ExternalCallFailed();
        }
        medicalServices.requiredSignatures = _newSignatures;
        emit ConfigurationUpdated("requiredSignatures", _newSignatures);
    }

    /// @notice Queues multi-sig configuration update
    /// @param _newSigners New signers
    /// @param _newRequiredSignatures New required signatures
    function queueUpdateMultiSigConfig(address[] calldata _newSigners, uint256 _newRequiredSignatures)
        external
        onlyConfigAdmin
    {
        if (_newSigners.length < _newRequiredSignatures || _newRequiredSignatures <= 0) revert InvalidApprovalCount();
        for (uint256 i = 0; i < _newSigners.length; i++) {
            if (_newSigners[i] == address(0)) revert InvalidAddress();
            for (uint256 j = i + 1; j < _newSigners.length; j++) {
                if (_newSigners[i] == _newSigners[j]) revert InvalidAddress();
            }
        }
        bytes memory data = abi.encodeWithSignature("updateMultiSigConfig(address[],uint256)", _newSigners, _newRequiredSignatures);
        _queueTimeLock(TimeLockAction.UpdateMultiSigConfig, address(medicalServices), _newRequiredSignatures, data);
    }

    /// @notice Updates multi-sig configuration
    /// @param _newSigners New signers
    /// @param _newRequiredSignatures New required signatures
    function updateMultiSigConfig(address[] calldata _newSigners, uint256 _newRequiredSignatures)
        external
        onlyConfigAdmin
    {
        if (_newSigners.length < _newRequiredSignatures || _newRequiredSignatures <= 0) revert InvalidApprovalCount();
        medicalServices.multiSigSigners = _newSigners;
        medicalServices.requiredSignatures = _newRequiredSignatures;
        bytes32[] memory signerHashes = new bytes32[](_newSigners.length);
        for (uint256 i = 0; i < _newSigners.length; i++) {
            signerHashes[i] = keccak256(abi.encode(_newSigners[i]));
        }
        emit MultiSigConfigUpdated(_newRequiredSignatures, signerHashes);
    }

    /// @notice Queues lab tech price update
    /// @param _labTech Lab tech address
    /// @param _testTypeIpfsHash Test type IPFS hash
    /// @param _price Price
    function queueUpdateLabTechPrice(address _labTech, string calldata _testTypeIpfsHash, uint256 _price)
        external
        onlyConfigAdmin
    {
        if (_labTech == address(0) || bytes(_testTypeIpfsHash).length < MIN_IPFS_HASH_LENGTH || _price <= 0) revert InvalidIPFSHash();
        bytes memory data = abi.encodeWithSignature("updateLabTechPrice(string,uint256)", _testTypeIpfsHash, _price);
        _queueTimeLock(TimeLockAction.UpdateLabTechPrice, _labTech, _price, data);
    }

    /// @notice Queues pharmacy price update
    /// @param _pharmacy Pharmacy address
    /// @param _medicationIpfsHash Medication IPFS hash
    /// @param _price Price
    function queueUpdatePharmacyPrice(address _pharmacy, string calldata _medicationIpfsHash, uint256 _price)
        external
        onlyConfigAdmin
    {
        if (_pharmacy == address(0) || bytes(_medicationIpfsHash).length < MIN_IPFS_HASH_LENGTH || _price <= 0) revert InvalidIPFSHash();
        bytes memory data = abi.encodeWithSignature("updatePharmacyPrice(string,uint256)", _medicationIpfsHash, _price);
        _queueTimeLock(TimeLockAction.UpdatePharmacyPrice, _pharmacy, _price, data);
    }

    // Additional Configuration Updates

    /// @notice Updates EntryPoint
    /// @param _newEntryPoint New EntryPoint address
    function updateEntryPoint(address _newEntryPoint) external onlyConfigAdmin {
        if (_newEntryPoint == address(0) || !_isContract(_newEntryPoint)) revert InvalidEntryPoint();
        address oldEntryPoint = address(entryPoint);
        entryPoint = IEntryPoint(_newEntryPoint);
        emit EntryPointUpdated(keccak256(abi.encode(oldEntryPoint)), keccak256(abi.encode(_newEntryPoint)));
    }

    /// @notice Updates data access oracle
    /// @param _newOracle New oracle address
    function updateDataAccessOracle(address _newOracle) external onlyConfigAdmin {
        if (_newOracle == address(0) || !_isContract(_newOracle)) revert InvalidAddress();
        dataAccessOracle = _newOracle;
        emit ConstantUpdated("dataAccessOracle", uint256(uint160(_newOracle)));
    }

    /// @notice Queues timelock delay update
    /// @param _newDelay New delay
    function queueUpdateTimeLockDelay(uint256 _newDelay) external onlyConfigAdmin {
        if (_newDelay < MIN_TIMELOCK_DELAY) revert InvalidParameter();
        bytes memory data = abi.encodeWithSignature("setTimeLockDelay(uint256)", _newDelay);
        _queueTimeLock(TimeLockAction.AdjustFee, address(this), _newDelay, data);
    }

    /// @notice Sets timelock delay
    /// @param _newDelay New delay
    function setTimeLockDelay(uint256 _newDelay) external onlyConfigAdmin {
        if (_newDelay < MIN_TIMELOCK_DELAY) revert InvalidParameter();
        timeLockDelay = _newDelay;
        emit ConstantUpdated("timeLockDelay", _newDelay);
    }

    /// @notice Queues required approvals update
    /// @param _newApprovals New approval count
    function queueUpdateRequiredApprovals(uint256 _newApprovals) external onlyConfigAdmin {
        try core.admins() returns (address[] memory admins) {
            if (_newApprovals < 1 || _newApprovals > admins.length) revert InvalidApprovalCount();
        } catch {
            revert ExternalCallFailed();
        }
        bytes memory data = abi.encodeWithSignature("setRequiredApprovals(uint256)", _newApprovals);
        _queueTimeLock(TimeLockAction.AdjustFee, address(this), _newApprovals, data);
    }

    /// @notice Sets required approvals
    /// @param _newApprovals New approval count
    function setRequiredApprovals(uint256 _newApprovals) external onlyConfigAdmin {
        try core.admins() returns (address[] memory admins) {
            if (_newApprovals < 1 || _newApprovals > admins.length) revert InvalidApprovalCount();
        } catch {
            revert ExternalCallFailed();
        }
        requiredApprovals = _newApprovals;
        emit ConstantUpdated("requiredApprovals", _newApprovals);
    }

    /// @notice Sets discount level
    /// @param _level Level
    /// @param _percentage Percentage
    function setDiscountLevel(uint8 _level, uint256 _percentage) external onlyConfigAdmin {
        try core.maxLevel() returns (uint8 maxLevel) {
            if (_level > maxLevel || _percentage > 100) revert InvalidParameter();
        } catch {
            revert ExternalCallFailed();
        }
        core.discountLevels(_level) = _percentage;
        emit GamificationParameterUpdated("discountLevel", _percentage);
    }

    /// @notice Sets points for action
    /// @param _action Action
    /// @param _points Points
    function setPointsForAction(string calldata _action, uint256 _points) external onlyConfigAdmin {
        if (_points <= 0) revert InvalidParameter();
        core.pointsForActions(_action) = _points;
        emit GamificationParameterUpdated(_action, _points);
    }

    // Utility Functions

    /// @notice Gets revert message
    /// @param _returnData Return data
    /// @return Revert message
    function _getRevertMsg(bytes memory _returnData) internal pure returns (string memory) {
        if (_returnData.length < 4) return "Transaction reverted silently";
        bytes4 selector = bytes4(_returnData);
        if (selector == bytes4(keccak256("Error(string)"))) {
            (, string memory reason) = abi.decode(_returnData, (bytes4, string));
            return reason;
        }
        return "Unknown revert reason";
    }

    /// @notice Checks if an address is a contract
    /// @param addr Address
    /// @return True if contract
    function _isContract(address addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }

    /// @notice Transfers ETH safely
    /// @param _to Recipient
    /// @param _amount Amount
    function safeTransferETH(address _to, uint256 _amount) internal {
        if (_amount == 0) return;
        (bool success, ) = _to.call{value: _amount}("");
        if (!success) revert InsufficientBalance();
    }

    // View Functions

    /// @notice Gets nonce
    /// @param _sender Sender address
    /// @return Nonce
    function getNonce(address _sender) external view onlyConfigAdmin returns (uint256) {
        return nonces[_sender];
    }

    /// @notice Checks trusted paymaster
    /// @param _paymaster Paymaster address
    /// @return True if trusted
    function isTrustedPaymaster(address _paymaster) external view onlyConfigAdmin returns (bool) {
        return trustedPaymasters[_paymaster];
    }

    /// @notice Gets timelock
    /// @param _timeLockId TimeLock ID
    /// @return TimeLock details
    function getTimeLock(uint256 _timeLockId) external view onlyConfigAdmin returns (
        uint256 id,
        TimeLockAction action,
        address target,
        uint256 value,
        bytes32 dataHash,
        uint256 timestamp,
        address[] memory approvers,
        bool executed,
        bool cancelled
    ) {
        TimeLock storage tl = timeLocks[_timeLockId];
        return (tl.id, tl.action, tl.target, tl.value, tl.dataHash, tl.timestamp, tl.approvers, tl.executed, tl.cancelled);
    }

    // Modifiers

    modifier onlyRole(bytes32 role) {
        try core.hasRole(role, msg.sender) returns (bool hasRole) {
            if (!hasRole) revert NotAuthorized();
            _;
        } catch {
            revert ExternalCallFailed();
        }
    }

    modifier onlyConfigAdmin() {
        try core.isConfigAdmin(msg.sender) returns (bool isAdmin) {
            if (!isAdmin) revert NotAuthorized();
            _;
        } catch {
            revert ExternalCallFailed();
        }
    }

    modifier onlyEntryPoint() {
        if (msg.sender != address(entryPoint)) revert InvalidEntryPoint();
        _;
    }

    modifier whenNotPaused() {
        try core.paused() returns (bool corePaused) {
            if (corePaused != paused()) {
                corePaused ? _pause() : _unpause();
            }
            if (paused()) revert ContractPaused();
            _;
        } catch {
            revert ExternalCallFailed();
        }
    }

    // Fallback
    receive() external payable {}

    // New: Storage gap
    uint256[50] private __gap;
}
