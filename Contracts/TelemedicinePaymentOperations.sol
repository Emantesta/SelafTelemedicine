// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {SafeMathUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";
import {SafeERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {TelemedicineCore} from "./TelemedicineCore.sol";
import {TelemedicinePayments} from "./TelemedicinePayments.sol";
import {TelemedicineDisputeResolution} from "./TelemedicineDisputeResolution.sol";
import {TelemedicineBase} from "./TelemedicineBase.sol";
import {TelemedicineClinicalOperations} from "./TelemedicineClinicalOperations.sol";
import {ChainlinkClient} from "@chainlink/contracts/src/v0.8/ChainlinkClient.sol";
import {IERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import {ITelemedicinePayments} from "./Interfaces/ITelemedicinePayments.sol";

/// @title TelemedicinePaymentOperations
/// @notice Manages payment operations, provider invitations, and pricing
/// @dev UUPS upgradeable, integrates with core, payments, dispute, base, and clinical ops
contract TelemedicinePaymentOperations is Initializable, UUPSUpgradeable, ReentrancyGuardUpgradeable, ChainlinkClient {
    using SafeMathUpgradeable for uint256;
    using Chainlink for Chainlink.Request;
    using SafeERC20Upgradeable for IERC20Upgradeable;
    using Strings for uint256;

    // Immutable Dependencies
    TelemedicineCore public immutable core;
    TelemedicinePayments public immutable payments;
    TelemedicineDisputeResolution public immutable disputeResolution;
    TelemedicineBase public immutable base;
    TelemedicineClinicalOperations public immutable clinicalOps;

    // Chainlink Configuration
    mapping(bytes32 => uint256) private requestToLabTestId; // Updated: Private
    mapping(bytes32 => uint256) private requestToPrescriptionId; // Updated: Private
    mapping(bytes32 => uint48) private requestTimestamps; // Updated: Private
    mapping(bytes32 => uint256) private chainlinkRetryCounts; // New: Track retries

    // State Variables
    mapping(uint256 => bool) private labTestPayments; // Updated: Private
    mapping(uint256 => bool) private prescriptionPayments; // Updated: Private
    mapping(uint256 => uint48) public labTestPaymentDeadlines;
    mapping(uint256 => uint48) public prescriptionPaymentDeadlines;

    struct PendingPayment {
        address recipient;
        uint256 amount;
        ITelemedicinePayments.PaymentType paymentType; // Updated: Use interface
        bool processed;
    }
    mapping(uint256 => PendingPayment) private pendingPayments; // Updated: Private
    uint256 public pendingPaymentCounter;

    struct Invitation {
        address patient;
        string locality;
        bytes32 inviteeContactHash; // Updated: Hashed contact
        bool isLabTech;
        bool fulfilled;
        uint48 expirationTimestamp;
    }
    mapping(bytes32 => Invitation) private invitations; // Updated: Private
    uint256 public invitationCounter;

    // Medical Services State
    mapping(address => mapping(string => PriceEntry)) private labTechPrices;
    mapping(address => mapping(string => PriceEntry)) private pharmacyPrices;
    mapping(address => uint256) private labTechIndex;
    mapping(address => uint256) private pharmacyIndex;
    mapping(address => mapping(bytes32 => bool)) private multiSigApprovals; // Updated: Private
    mapping(address => string) private labTechLocalities;
    mapping(address => string) private pharmacyLocalities;
    mapping(string => address[]) private localityToLabTechs; // New: Optimize locality lookup
    mapping(string => address[]) private localityToPharmacies; // New: Optimize locality lookup

    address[] public labTechList;
    address[] public pharmacyList;
    address[] public multiSigSigners;
    uint256 public requiredSignatures;
    uint256 public versionNumber; // New: Track version

    // Structs
    struct PriceEntry {
        uint256 price;
        uint48 timestamp;
    }

    // Constants
    uint256 public constant MIN_PRICE = 0.01 * 10**6; // New: 0.01 USDC (6 decimals)
    uint256 public constant MAX_COUNTER = 1_000_000; // New: Limit counters
    uint256 public constant MAX_RETRIES = 3; // New: Chainlink retry limit

    // Events
    event FundsWithdrawn(bytes32 indexed recipientHash, uint256 amount, ITelemedicinePayments.PaymentType paymentType);
    event LabTestRefunded(uint256 indexed testId, bytes32 patientHash, uint256 amount);
    event PrescriptionRefunded(uint256 indexed prescriptionId, bytes32 patientHash, uint256 amount);
    event InvitationSubmitted(bytes32 indexed invitationId, bytes32 patientHash, string locality, bool isLabTech);
    event InvitationFulfilled(bytes32 indexed invitationId, bytes32 inviteeHash);
    event InvitationExpired(bytes32 indexed invitationId);
    event LabTestPaymentConfirmed(uint256 indexed testId, uint256 amount);
    event PrescriptionPaymentConfirmed(uint256 indexed prescriptionId, uint256 amount);
    event LabTestPaymentPending(uint256 indexed testId, uint256 patientCost, uint48 deadline);
    event PrescriptionPaymentPending(uint256 indexed prescriptionId, uint256 patientCost, uint48 deadline);
    event LabTestPaymentReleased(uint256 indexed testId, bytes32 labTechHash, uint256 amount, ITelemedicinePayments.PaymentType paymentType);
    event PrescriptionPaymentReleased(uint256 indexed prescriptionId, bytes32 pharmacyHash, uint256 amount, ITelemedicinePayments.PaymentType paymentType);
    event PaymentQueued(uint256 indexed paymentId, bytes32 recipientHash, uint256 amount, ITelemedicinePayments.PaymentType paymentType);
    event PaymentReleasedFromQueue(uint256 indexed paymentId, bytes32 recipientHash, uint256 amount);
    event LabTechRegistered(bytes32 indexed labTechHash);
    event PharmacyRegistered(bytes32 indexed pharmacyHash);
    event LabTechPriceUpdated(bytes32 indexed labTechHash, string testTypeIpfsHash, uint256 price, uint48 timestamp);
    event PharmacyPriceUpdated(bytes32 indexed pharmacyHash, string medicationIpfsHash, uint256 price, uint48 timestamp);
    event DataRewardClaimed(bytes32 indexed patientHash, uint256 amount);
    event MultiSigApproval(bytes32 indexed signerHash, bytes32 indexed operationHash);
    event ConfigurationUpdated(string indexed parameter, uint256 value); // New: Config updates
    event MultiSigConfigUpdated(address[] signers, uint256 requiredSignatures); // New: Multi-sig updates

    // Errors
    error InvalidAddress();
    error InvalidStatus();
    error NotAuthorized();
    error ContractPaused();
    error InsufficientFunds();
    error InvalidIndex();
    error InvalidIpfsHash();
    error MultiSigNotApproved();
    error PaymentFailed();
    error OracleResponseInvalid();
    error InvalidLocality();
    error InvitationAlreadyExists();
    error ProvidersAlreadyExist();
    error PaymentNotConfirmed();
    error PaymentDeadlineMissed();
    error InvitationExpired();
    error ChainlinkRequestFailed();
    error AlreadyRegistered();
    error NotRegistered();
    error InvalidPrice();
    error CounterOverflow();
    error InvalidPaymentType();
    error ExternalCallFailed();
    error MaxRetriesExceeded();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the contract
    /// @param _core Core contract address
    /// @param _payments Payments contract address
    /// @param _disputeResolution Dispute resolution contract address
    /// @param _base Base contract address
    /// @param _clinicalOps Clinical operations contract address
    /// @param _multiSigSigners Multi-signature signers
    /// @param _requiredSignatures Required signatures
    function initialize(
        address _core,
        address _payments,
        address _disputeResolution,
        address _base,
        address _clinicalOps,
        address[] memory _multiSigSigners,
        uint256 _requiredSignatures
    ) external initializer {
        if (_core == address(0) || _payments == address(0) || _disputeResolution == address(0) ||
            _base == address(0) || _clinicalOps == address(0)) revert InvalidAddress();
        if (_multiSigSigners.length < _requiredSignatures || _requiredSignatures == 0) revert InvalidAddress();
        if (!_isContract(_core) || !_isContract(_payments) || !_isContract(_disputeResolution) ||
            !_isContract(_base) || !_isContract(_clinicalOps)) revert InvalidAddress();

        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        __ChainlinkClient_init();

        core = TelemedicineCore(_core);
        payments = TelemedicinePayments(_payments);
        disputeResolution = TelemedicineDisputeResolution(_disputeResolution);
        base = TelemedicineBase(_base);
        clinicalOps = TelemedicineClinicalOperations(_clinicalOps);
        multiSigSigners = _multiSigSigners;
        requiredSignatures = _requiredSignatures;
        versionNumber = 1;

        invitationCounter = 0;
        pendingPaymentCounter = 0;
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

    /// @notice Confirms multiple payments
    /// @param _ids IDs of lab tests or prescriptions
    /// @param _isLabTests Flags indicating lab test or prescription
    /// @param _paymentTypes Payment types
    function batchConfirmPayments(
        uint256[] calldata _ids,
        bool[] calldata _isLabTests,
        ITelemedicinePayments.PaymentType[] calldata _paymentTypes
    ) external payable onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
        if (_ids.length != _isLabTests.length || _ids.length != _paymentTypes.length || _ids.length > 100) revert InvalidIndex();
        uint256 totalEthRequired;

        for (uint256 i = 0; i < _ids.length; i++) {
            if (_isLabTests[i]) {
                TelemedicineClinicalOperations.LabTestOrder storage order = clinicalOps.labTestOrders(_ids[i]);
                if (_ids[i] == 0 || _ids[i] > clinicalOps.labTestCounter()) revert InvalidIndex();
                if (order.patient != msg.sender) revert NotAuthorized();
                if (order.status != TelemedicineClinicalOperations.LabTestStatus.PaymentPending) revert InvalidStatus();
                if (block.timestamp > labTestPaymentDeadlines[_ids[i]]) {
                    order.status = TelemedicineClinicalOperations.LabTestStatus.Cancelled;
                    continue;
                }

                if (_paymentTypes[i] == ITelemedicinePayments.PaymentType.ETH) {
                    totalEthRequired = totalEthRequired.add(order.patientCost);
                } else {
                    try payments._processPayment(_paymentTypes[i], order.patientCost) {} catch {
                        revert ExternalCallFailed();
                    }
                    order.paymentType = _paymentTypes[i];
                    labTestPayments[_ids[i]] = true;
                    order.status = TelemedicineClinicalOperations.LabTestStatus.Requested;
                    emit LabTestPaymentConfirmed(_ids[i], order.patientCost);
                }
            } else {
                TelemedicineClinicalOperations.Prescription storage prescription = clinicalOps.prescriptions(_ids[i]);
                if (_ids[i] == 0 || _ids[i] > clinicalOps.prescriptionCounter()) revert InvalidIndex();
                if (prescription.patient != msg.sender) revert NotAuthorized();
                if (prescription.status != TelemedicineClinicalOperations.PrescriptionStatus.PaymentPending) revert InvalidStatus();
                if (block.timestamp > prescriptionPaymentDeadlines[_ids[i]]) {
                    prescription.status = TelemedicineClinicalOperations.PrescriptionStatus.Cancelled;
                    continue;
                }

                if (_paymentTypes[i] == ITelemedicinePayments.PaymentType.ETH) {
                    totalEthRequired = totalEthRequired.add(prescription.patientCost);
                } else {
                    try payments._processPayment(_paymentTypes[i], prescription.patientCost) {} catch {
                        revert ExternalCallFailed();
                    }
                    prescription.paymentType = _paymentTypes[i];
                    prescriptionPayments[_ids[i]] = true;
                    prescription.status = TelemedicineClinicalOperations.PrescriptionStatus.Generated;
                    emit PrescriptionPaymentConfirmed(_ids[i], prescription.patientCost);
                }
            }
        }

        if (totalEthRequired > 0) {
            if (msg.value < totalEthRequired) revert InsufficientFunds();
            for (uint256 i = 0; i < _ids.length; i++) {
                if (_paymentTypes[i] != ITelemedicinePayments.PaymentType.ETH) continue;
                if (_isLabTests[i]) {
                    TelemedicineClinicalOperations.LabTestOrder storage order = clinicalOps.labTestOrders(_ids[i]);
                    if (order.status != TelemedicineClinicalOperations.LabTestStatus.PaymentPending) continue;
                    order.paymentType = _paymentTypes[i];
                    labTestPayments[_ids[i]] = true;
                    order.status = TelemedicineClinicalOperations.LabTestStatus.Requested;
                    emit LabTestPaymentConfirmed(_ids[i], order.patientCost);
                } else {
                    TelemedicineClinicalOperations.Prescription storage prescription = clinicalOps.prescriptions(_ids[i]);
                    if (prescription.status != TelemedicineClinicalOperations.PrescriptionStatus.PaymentPending) continue;
                    prescription.paymentType = _paymentTypes[i];
                    prescriptionPayments[_ids[i]] = true;
                    prescription.status = TelemedicineClinicalOperations.PrescriptionStatus.Generated;
                    emit PrescriptionPaymentConfirmed(_ids[i], prescription.patientCost);
                }
            }
            if (msg.value > totalEthRequired) {
                safeTransferETH(msg.sender, msg.value - totalEthRequired);
            }
        }
    }

    /// @notice Invites a provider
    /// @param _locality Provider locality
    /// @param _inviteeContactHash Hashed contact
    /// @param _isLabTech Lab tech flag
    function inviteProvider(string calldata _locality, bytes32 _inviteeContactHash, bool _isLabTech)
        external onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
        if (bytes(_locality).length == 0 || _inviteeContactHash == bytes32(0)) revert InvalidLocality();
        if (_isLabTech ? hasLabTechInLocality(_locality) : hasPharmacyInLocality(_locality)) revert ProvidersAlreadyExist();

        bytes32 invitationId = keccak256(abi.encodePacked(msg.sender, _locality, _isLabTech, block.timestamp));
        if (invitations[invitationId].patient != address(0)) revert InvitationAlreadyExists();
        if (invitationCounter >= MAX_COUNTER) revert CounterOverflow();

        invitationCounter = invitationCounter.add(1);
        invitations[invitationId] = Invitation({
            patient: msg.sender,
            locality: _locality,
            inviteeContactHash: _inviteeContactHash,
            isLabTech: _isLabTech,
            fulfilled: false,
            expirationTimestamp: uint48(block.timestamp).add(base.invitationExpirationPeriod())
        });

        emit InvitationSubmitted(invitationId, keccak256(abi.encode(msg.sender)), _locality, _isLabTech);
    }

    /// @notice Registers an invited provider
    /// @param _invitationId Invitation ID
    /// @param _providerAddress Provider address
    function registerAsInvitedProvider(bytes32 _invitationId, address _providerAddress)
        external onlyConfigAdmin nonReentrant whenNotPaused {
        Invitation storage invitation = invitations[_invitationId];
        if (invitation.patient == address(0)) revert InvalidIndex();
        if (invitation.fulfilled) revert InvalidStatus();
        if (block.timestamp > invitation.expirationTimestamp) revert InvitationExpired();
        if (_providerAddress == address(0)) revert InvalidAddress();

        if (invitation.isLabTech) {
            registerLabTech(_providerAddress, invitation.locality);
        } else {
            registerPharmacy(_providerAddress, invitation.locality);
        }

        invitation.fulfilled = true;
        emit InvitationFulfilled(_invitationId, keccak256(abi.encode(_providerAddress)));
    }

    /// @notice Checks and expires invitations
    /// @param _invitationIds Invitation IDs
    function batchCheckInvitationExpiration(bytes32[] calldata _invitationIds) external nonReentrant whenNotPaused {
        for (uint256 i = 0; i < _invitationIds.length; i++) {
            Invitation storage invitation = invitations[_invitationIds[i]];
            if (invitation.patient == address(0) || invitation.fulfilled) continue;
            if (block.timestamp <= invitation.expirationTimestamp) continue;

            delete invitations[_invitationIds[i]];
            emit InvitationExpired(_invitationIds[i]);
        }
    }

    /// @notice Requests lab test price
    /// @param _labTech Lab technician address
    /// @param _testTypeIpfsHash Test type IPFS hash
    /// @param _labTestId Lab test ID
    /// @return Request ID
    function requestLabTestPrice(address _labTech, string calldata _testTypeIpfsHash, uint256 _labTestId)
        external onlyClinicalOps returns (bytes32) {
        bool manualOverride;
        try base.manualPriceOverride() returns (bool override) {
            manualOverride = override;
        } catch {
            revert ExternalCallFailed();
        }
        if (manualOverride) return bytes32(0);

        if (bytes(_testTypeIpfsHash).length == 0) revert InvalidIpfsHash();
        Chainlink.Request memory req = buildChainlinkRequest(
            base.priceListJobId(),
            address(this),
            this.fulfillLabTestPrice.selector
        );
        req.add("testType", _testTypeIpfsHash);
        req.add("labTech", _labTech.toString());
        bytes32 requestId;
        try this.sendChainlinkRequestTo(base.chainlinkOracle(), req, base.chainlinkFee()) returns (bytes32 id) {
            requestId = id;
        } catch {
            chainlinkRetryCounts[keccak256(abi.encode(_labTestId))] = chainlinkRetryCounts[keccak256(abi.encode(_labTestId))].add(1);
            if (chainlinkRetryCounts[keccak256(abi.encode(_labTestId))] >= MAX_RETRIES) {
                try base.manualPriceOverride() returns (bool override) {
                    if (!override) {
                        try base.toggleManualPriceOverride(true) {} catch {
                            revert ExternalCallFailed();
                        }
                    }
                } catch {
                    revert ExternalCallFailed();
                }
                return bytes32(0);
            }
            return requestLabTestPrice(_labTech, _testTypeIpfsHash, _labTestId);
        }

        requestToLabTestId[requestId] = _labTestId;
        requestTimestamps[requestId] = uint48(block.timestamp);
        return requestId;
    }

    /// @notice Fulfills lab test price
    /// @param _requestId Request ID
    /// @param _price Price
    function fulfillLabTestPrice(bytes32 _requestId, uint256 _price) public recordChainlinkFulfillment(_requestId) {
        uint256 labTestId = requestToLabTestId[_requestId];
        if (labTestId == 0 || labTestId > clinicalOps.labTestCounter()) revert InvalidIndex();
        TelemedicineClinicalOperations.LabTestOrder storage order = clinicalOps.labTestOrders(labTestId);
        if (order.status != TelemedicineClinicalOperations.LabTestStatus.Requested) revert InvalidStatus();
        if (_price < MIN_PRICE) {
            try base.manualPriceOverride() returns (bool override) {
                if (!override) {
                    try base.toggleManualPriceOverride(true) {} catch {
                        revert ExternalCallFailed();
                    }
                }
            } catch {
                revert ExternalCallFailed();
            }
            delete requestToLabTestId[_requestId];
            delete requestTimestamps[_requestId];
            return;
        }

        try base.PERCENTAGE_DENOMINATOR() returns (uint256 denominator) {
            order.patientCost = _price.mul(120).div(denominator);
        } catch {
            revert ExternalCallFailed();
        }
        order.status = TelemedicineClinicalOperations.LabTestStatus.PaymentPending;
        labTestPaymentDeadlines[labTestId] = uint48(block.timestamp).add(base.paymentConfirmationDeadline());
        delete requestToLabTestId[_requestId];
        delete requestTimestamps[_requestId];
        emit LabTestPaymentPending(labTestId, order.patientCost, labTestPaymentDeadlines[labTestId]);
    }

    /// @notice Requests prescription price
    /// @param _pharmacy Pharmacy address
    /// @param _medicationIpfsHash Medication IPFS hash
    /// @param _prescriptionId Prescription ID
    /// @return Request ID
    function requestPrescriptionPrice(address _pharmacy, string calldata _medicationIpfsHash, uint256 _prescriptionId)
        external onlyClinicalOps returns (bytes32) {
        bool manualOverride;
        try base.manualPriceOverride() returns (bool override) {
            manualOverride = override;
        } catch {
            revert ExternalCallFailed();
        }
        if (manualOverride) return bytes32(0);

        if (bytes(_medicationIpfsHash).length == 0) revert InvalidIpfsHash();
        Chainlink.Request memory req = buildChainlinkRequest(
            base.priceListJobId(),
            address(this),
            this.fulfillPrescriptionPrice.selector
        );
        req.add("medication", _medicationIpfsHash);
        req.add("pharmacy", _pharmacy.toString());
        bytes32 requestId;
        try this.sendChainlinkRequestTo(base.chainlinkOracle(), req, base.chainlinkFee()) returns (bytes32 id) {
            requestId = id;
        } catch {
            chainlinkRetryCounts[keccak256(abi.encode(_prescriptionId))] = chainlinkRetryCounts[keccak256(abi.encode(_prescriptionId))].add(1);
            if (chainlinkRetryCounts[keccak256(abi.encode(_prescriptionId))] >= MAX_RETRIES) {
                try base.manualPriceOverride() returns (bool override) {
                    if (!override) {
                        try base.toggleManualPriceOverride(true) {} catch {
                            revert ExternalCallFailed();
                        }
                    }
                } catch {
                    revert ExternalCallFailed();
                }
                return bytes32(0);
            }
            return requestPrescriptionPrice(_pharmacy, _medicationIpfsHash, _prescriptionId);
        }

        requestToPrescriptionId[requestId] = _prescriptionId;
        requestTimestamps[requestId] = uint48(block.timestamp);
        return requestId;
    }

    /// @notice Fulfills prescription price
    /// @param _requestId Request ID
    /// @param _price Price
    function fulfillPrescriptionPrice(bytes32 _requestId, uint256 _price) public recordChainlinkFulfillment(_requestId) {
        uint256 prescriptionId = requestToPrescriptionId[_requestId];
        if (prescriptionId == 0 || prescriptionId > clinicalOps.prescriptionCounter()) revert InvalidIndex();
        TelemedicineClinicalOperations.Prescription storage prescription = clinicalOps.prescriptions(prescriptionId);
        if (prescription.status != TelemedicineClinicalOperations.PrescriptionStatus.Generated) revert InvalidStatus();
        if (_price < MIN_PRICE) {
            try base.manualPriceOverride() returns (bool override) {
                if (!override) {
                    try base.toggleManualPriceOverride(true) {} catch {
                        revert ExternalCallFailed();
                    }
                }
            } catch {
                revert ExternalCallFailed();
            }
            delete requestToPrescriptionId[_requestId];
            delete requestTimestamps[_requestId];
            return;
        }

        try base.PERCENTAGE_DENOMINATOR() returns (uint256 denominator) {
            prescription.patientCost = _price.mul(120).div(denominator);
        } catch {
            revert ExternalCallFailed();
        }
        prescription.status = TelemedicineClinicalOperations.PrescriptionStatus.PaymentPending;
        prescriptionPaymentDeadlines[prescriptionId] = uint48(block.timestamp).add(base.paymentConfirmationDeadline());
        delete requestToPrescriptionId[_requestId];
        delete requestTimestamps[_requestId];
        emit PrescriptionPaymentPending(prescriptionId, prescription.patientCost, prescriptionPaymentDeadlines[prescriptionId]);
    }

    /// @notice Cancels Chainlink request
    /// @param _requestId Request ID
    function cancelChainlinkRequest(bytes32 _requestId) external onlyConfigAdmin {
        if (requestToLabTestId[_requestId] == 0 && requestToPrescriptionId[_requestId] == 0) revert InvalidIndex();
        try base.chainlinkRequestTimeout() returns (uint256 timeout) {
            if (block.timestamp <= requestTimestamps[_requestId].add(timeout)) revert InvalidTimestamp();
        } catch {
            revert ExternalCallFailed();
        }

        try this.cancelChainlinkRequest(_requestId) {} catch {
            revert ExternalCallFailed();
        }
        delete requestToLabTestId[_requestId];
        delete requestToPrescriptionId[_requestId];
        delete requestTimestamps[_requestId];
    }

    /// @notice Releases lab test payment
    /// @param _labTestId Lab test ID
    function releaseLabTestPayment(uint256 _labTestId) external nonReentrant whenNotPaused {
        TelemedicineClinicalOperations.LabTestOrder storage order = clinicalOps.labTestOrders(_labTestId);
        if (_labTestId == 0 || _labTestId > clinicalOps.labTestCounter()) revert InvalidIndex();
        if (order.status != TelemedicineClinicalOperations.LabTestStatus.ResultsUploaded &&
            order.status != TelemedicineClinicalOperations.LabTestStatus.Reviewed &&
            order.status != TelemedicineClinicalOperations.LabTestStatus.Disputed) revert InvalidStatus();
        if (block.timestamp <= order.disputeWindowEnd) revert InvalidTimestamp();
        if (!labTestPayments[_labTestId]) revert PaymentNotConfirmed();

        bool isDisputed;
        try disputeResolution.isDisputed(_labTestId) returns (bool disputed) {
            isDisputed = disputed;
        } catch {
            revert ExternalCallFailed();
        }

        if (isDisputed) {
            TelemedicineMedicalCore.DisputeOutcome outcome; // Updated: Standardize
            try disputeResolution.getDisputeOutcome(_labTestId) returns (TelemedicineMedicalCore.DisputeOutcome o) {
                outcome = o;
            } catch {
                revert ExternalCallFailed();
            }
            if (outcome == TelemedicineMedicalCore.DisputeOutcome.Unresolved) revert InvalidStatus();

            if (outcome == TelemedicineMedicalCore.DisputeOutcome.PatientFavored) {
                try payments._refundPatient(order.patient, order.patientCost, order.paymentType) {} catch {
                    revert ExternalCallFailed();
                }
                emit LabTestRefunded(_labTestId, keccak256(abi.encode(order.patient)), order.patientCost);
            } else if (outcome == TelemedicineMedicalCore.DisputeOutcome.ProviderFavored ||
                       outcome == TelemedicineMedicalCore.DisputeOutcome.MutualAgreement) {
                _releasePayment(order.labTech, order.patientCost, order.paymentType);
                emit LabTestPaymentReleased(_labTestId, keccak256(abi.encode(order.labTech)), order.patientCost, order.paymentType);
            }
            order.status = TelemedicineClinicalOperations.LabTestStatus.Disputed;
            try this.notifyDisputeResolved(_labTestId, "LabTest", outcome) {} catch {
                revert ExternalCallFailed();
            }
        } else {
            _releasePayment(order.labTech, order.patientCost, order.paymentType);
            emit LabTestPaymentReleased(_labTestId, keccak256(abi.encode(order.labTech)), order.patientCost, order.paymentType);
        }

        labTestPayments[_labTestId] = false;
    }

    /// @notice Releases prescription payment
    /// @param _prescriptionId Prescription ID
    function releasePrescriptionPayment(uint256 _prescriptionId) external nonReentrant whenNotPaused {
        TelemedicineClinicalOperations.Prescription storage prescription = clinicalOps.prescriptions(_prescriptionId);
        if (_prescriptionId == 0 || _prescriptionId > clinicalOps.prescriptionCounter()) revert InvalidIndex();
        if (prescription.status != TelemedicineClinicalOperations.PrescriptionStatus.Fulfilled &&
            prescription.status != TelemedicineClinicalOperations.PrescriptionStatus.Disputed) revert InvalidStatus();
        if (block.timestamp <= prescription.disputeWindowEnd) revert InvalidTimestamp();
        if (!prescriptionPayments[_prescriptionId]) revert PaymentNotConfirmed();

        bool isDisputed;
        try disputeResolution.isDisputed(_prescriptionId) returns (bool disputed) {
            isDisputed = disputed;
        } catch {
            revert ExternalCallFailed();
        }

        if (isDisputed) {
            TelemedicineMedicalCore.DisputeOutcome outcome; // Updated: Standardize
            try disputeResolution.getDisputeOutcome(_prescriptionId) returns (TelemedicineMedicalCore.DisputeOutcome o) {
                outcome = o;
            } catch {
                revert ExternalCallFailed();
            }
            if (outcome == TelemedicineMedicalCore.DisputeOutcome.Unresolved) revert InvalidStatus();

            if (outcome == TelemedicineMedicalCore.DisputeOutcome.PatientFavored) {
                try payments._refundPatient(prescription.patient, prescription.patientCost, prescription.paymentType) {} catch {
                    revert ExternalCallFailed();
                }
                emit PrescriptionRefunded(_prescriptionId, keccak256(abi.encode(prescription.patient)), prescription.patientCost);
            } else if (outcome == TelemedicineMedicalCore.DisputeOutcome.ProviderFavored ||
                       outcome == TelemedicineMedicalCore.DisputeOutcome.MutualAgreement) {
                _releasePayment(prescription.pharmacy, prescription.patientCost, prescription.paymentType);
                emit PrescriptionPaymentReleased(_prescriptionId, keccak256(abi.encode(prescription.pharmacy)), prescription.patientCost, prescription.paymentType);
            }
            prescription.status = TelemedicineClinicalOperations.PrescriptionStatus.Disputed;
            try this.notifyDisputeResolved(_prescriptionId, "Prescription", outcome) {} catch {
                revert ExternalCallFailed();
            }
        } else {
            _releasePayment(prescription.pharmacy, prescription.patientCost, prescription.paymentType);
            emit PrescriptionPaymentReleased(_prescriptionId, keccak256(abi.encode(prescription.pharmacy)), prescription.patientCost, prescription.paymentType);
        }

        prescriptionPayments[_prescriptionId] = false;
    }

    /// @notice Queues fund withdrawal
    /// @param _recipient Recipient address
    /// @param _amount Amount
    /// @param _paymentType Payment type
    function queueWithdrawFunds(
        address _recipient,
        uint256 _amount,
        ITelemedicinePayments.PaymentType _paymentType
    ) external onlyConfigAdmin nonReentrant whenNotPaused {
        if (_recipient == address(0)) revert InvalidAddress();
        if (_amount == 0) revert InsufficientFunds();

        bytes memory data = abi.encodeWithSignature(
            "executeWithdrawFunds(address,uint256,enum ITelemedicinePayments.PaymentType)",
            _recipient,
            _amount,
            _paymentType
        );
        try core._queueTimeLock(
            TelemedicineCore.TimeLockAction.FundWithdrawal, // Assumes GovernanceManager enum
            address(this),
            0,
            data
        ) {} catch {
            revert ExternalCallFailed();
        }
    }

    /// @notice Executes fund withdrawal
    /// @param _recipient Recipient address
    /// @param _amount Amount
    /// @param _paymentType Payment type
    function executeWithdrawFunds(
        address _recipient,
        uint256 _amount,
        ITelemedicinePayments.PaymentType _paymentType
    ) external onlyConfigAdmin nonReentrant whenNotPaused onlyMultiSig(keccak256(abi.encode(_recipient, _amount, _paymentType))) {
        _releasePayment(_recipient, _amount, _paymentType);
        emit FundsWithdrawn(keccak256(abi.encode(_recipient)), _amount, _paymentType);
        _resetMultiSigApprovals(keccak256(abi.encode(_recipient, _amount, _paymentType)));
    }

    /// @notice Sets manual lab test price
    /// @param _labTestId Lab test ID
    /// @param _price Price
    function queueSetManualLabTestPrice(uint256 _labTestId, uint256 _price) external onlyConfigAdmin {
        bool manualOverride;
        try base.manualPriceOverride() returns (bool override) {
            manualOverride = override;
        } catch {
            revert ExternalCallFailed();
        }
        if (!manualOverride) revert NotAuthorized();
        if (_labTestId == 0 || _labTestId > clinicalOps.labTestCounter()) revert InvalidIndex();
        if (_price < MIN_PRICE) revert InvalidPrice();

        bytes memory data = abi.encodeWithSignature("executeSetManualLabTestPrice(uint256,uint256)", _labTestId, _price);
        try core._queueTimeLock(
            TelemedicineCore.TimeLockAction.ConfigurationUpdate,
            address(this),
            0,
            data
        ) {} catch {
            revert ExternalCallFailed();
        }
    }

    /// @notice Executes manual lab test price
    /// @param _labTestId Lab test ID
    /// @param _price Price
    function executeSetManualLabTestPrice(uint256 _labTestId, uint256 _price) external onlyConfigAdmin {
        TelemedicineClinicalOperations.LabTestOrder storage order = clinicalOps.labTestOrders(_labTestId);
        if (order.status != TelemedicineClinicalOperations.LabTestStatus.Requested) revert InvalidStatus();

        try base.PERCENTAGE_DENOMINATOR() returns (uint256 denominator) {
            order.patientCost = _price.mul(120).div(denominator);
        } catch {
            revert ExternalCallFailed();
        }
        order.status = TelemedicineClinicalOperations.LabTestStatus.PaymentPending;
        labTestPaymentDeadlines[_labTestId] = uint48(block.timestamp).add(base.paymentConfirmationDeadline());
        emit LabTestPaymentPending(_labTestId, order.patientCost, labTestPaymentDeadlines[_labTestId]);
    }

    /// @notice Sets manual prescription price
    /// @param _prescriptionId Prescription ID
    /// @param _price Price
    function queueSetManualPrescriptionPrice(uint256 _prescriptionId, uint256 _price) external onlyConfigAdmin {
        bool manualOverride;
        try base.manualPriceOverride() returns (bool override) {
            manualOverride = override;
        } catch {
            revert ExternalCallFailed();
        }
        if (!manualOverride) revert NotAuthorized();
        if (_prescriptionId == 0 || _prescriptionId > clinicalOps.prescriptionCounter()) revert InvalidIndex();
        if (_price < MIN_PRICE) revert InvalidPrice();

        bytes memory data = abi.encodeWithSignature("executeSetManualPrescriptionPrice(uint256,uint256)", _prescriptionId, _price);
        try core._queueTimeLock(
            TelemedicineCore.TimeLockAction.ConfigurationUpdate,
            address(this),
            0,
            data
        ) {} catch {
            revert ExternalCallFailed();
        }
    }

    /// @notice Executes manual prescription price
    /// @param _prescriptionId Prescription ID
    /// @param _price Price
    function executeSetManualPrescriptionPrice(uint256 _prescriptionId, uint256 _price) external onlyConfigAdmin {
        TelemedicineClinicalOperations.Prescription storage prescription = clinicalOps.prescriptions(_prescriptionId);
        if (prescription.status != TelemedicineClinicalOperations.PrescriptionStatus.Generated) revert InvalidStatus();

        try base.PERCENTAGE_DENOMINATOR() returns (uint256 denominator) {
            prescription.patientCost = _price.mul(120).div(denominator);
        } catch {
            revert ExternalCallFailed();
        }
        prescription.status = TelemedicineClinicalOperations.PrescriptionStatus.PaymentPending;
        prescriptionPaymentDeadlines[_prescriptionId] = uint48(block.timestamp).add(base.paymentConfirmationDeadline());
        emit PrescriptionPaymentPending(_prescriptionId, prescription.patientCost, prescriptionPaymentDeadlines[_prescriptionId]);
    }

    /// @notice Toggles manual price override
    /// @param _enabled Enabled flag
    function queueToggleManualPriceOverride(bool _enabled) external onlyConfigAdmin {
        bytes memory data = abi.encodeWithSignature("executeToggleManualPriceOverride(bool)", _enabled);
        try core._queueTimeLock(
            TelemedicineCore.TimeLockAction.ConfigurationUpdate,
            address(this),
            0,
            data
        ) {} catch {
            revert ExternalCallFailed();
        }
    }

    /// @notice Executes manual price override toggle
    /// @param _enabled Enabled flag
    function executeToggleManualPriceOverride(bool _enabled) external onlyConfigAdmin {
        try base.toggleManualPriceOverride(_enabled) {} catch {
            revert ExternalCallFailed();
        }
    }

    /// @notice Updates multi-signature configuration
    /// @param _newSigners New signers
    /// @param _newRequiredSignatures New required signatures
    function queueUpdateMultiSigConfig(address[] calldata _newSigners, uint256 _newRequiredSignatures) external onlyConfigAdmin {
        if (_newSigners.length < _newRequiredSignatures || _newRequiredSignatures == 0) revert InvalidAddress();
        bytes memory data = abi.encodeWithSignature("executeUpdateMultiSigConfig(address[],uint256)", _newSigners, _newRequiredSignatures);
        try core._queueTimeLock(
            TelemedicineCore.TimeLockAction.ConfigurationUpdate,
            address(this),
            0,
            data
        ) {} catch {
            revert ExternalCallFailed();
        }
    }

    /// @notice Executes multi-signature configuration update
    /// @param _newSigners New signers
    /// @param _newRequiredSignatures New required signatures
    function executeUpdateMultiSigConfig(address[] calldata _newSigners, uint256 _newRequiredSignatures) external onlyConfigAdmin {
        multiSigSigners = _newSigners;
        requiredSignatures = _newRequiredSignatures;
        emit MultiSigConfigUpdated(_newSigners, _newRequiredSignatures);
    }

    /// @notice Releases pending payments
    /// @param _startId Start ID
    /// @param _count Number of payments
    function releasePendingPayments(uint256 _startId, uint256 _count) external onlyConfigAdmin nonReentrant {
        uint256 endId = _startId.add(_count) > pendingPaymentCounter ? pendingPaymentCounter : _startId.add(_count);
        for (uint256 i = _startId; i < endId; i++) {
            PendingPayment storage payment = pendingPayments[i];
            if (payment.processed || payment.amount == 0) continue;

            if (_hasSufficientFunds(payment.amount, payment.paymentType)) {
                _releasePayment(payment.recipient, payment.amount, payment.paymentType);
                payment.processed = true;
                emit PaymentReleasedFromQueue(i, keccak256(abi.encode(payment.recipient)), payment.amount);
            }
        }
    }

    /// @notice Selects best lab technician
    /// @param _testTypeIpfsHash Test type IPFS hash
    /// @param _locality Locality
    /// @return Best lab technician address
    function selectBestLabTech(string memory _testTypeIpfsHash, string memory _locality) public view returns (address) {
        if (bytes(_testTypeIpfsHash).length == 0) revert InvalidIpfsHash();
        address[] memory labTechs = localityToLabTechs[_locality];
        if (labTechs.length == 0) return address(0);

        address bestLabTech = address(0);
        uint256 highestScore = 0;
        address fallbackTech = address(0);

        for (uint256 i = 0; i < labTechs.length; i++) {
            if (!isLabTechRegistered(labTechs[i])) continue;
            (uint256 price, bool isValid, , ) = getLabTestDetails(labTechs[i], _testTypeIpfsHash);
            if (!isValid || price == 0) continue;
            uint256 capacity = getLabTechCapacity(labTechs[i]);
            if (capacity == 0) continue;

            if (fallbackTech == address(0)) fallbackTech = labTechs[i];
            (uint256 avgRating, uint256 ratingCount) = getLabTechRating(labTechs[i]);
            uint256 score = (avgRating > 0 && ratingCount > 0) ? avgRating.mul(ratingCount).div(price) : 0;

            if (score > highestScore) {
                highestScore = score;
                bestLabTech = labTechs[i];
            }
        }
        return bestLabTech != address(0) ? bestLabTech : fallbackTech;
    }

    /// @notice Releases payment
    /// @param _to Recipient
    /// @param _amount Amount
    /// @param _paymentType Payment type
    function _releasePayment(address _to, uint256 _amount, ITelemedicinePayments.PaymentType _paymentType) internal {
        if (!_hasSufficientFunds(_amount, _paymentType)) {
            if (pendingPaymentCounter >= MAX_COUNTER) revert CounterOverflow();
            pendingPaymentCounter = pendingPaymentCounter.add(1);
            pendingPayments[pendingPaymentCounter] = PendingPayment(_to, _amount, _paymentType, false);
            emit PaymentQueued(pendingPaymentCounter, keccak256(abi.encode(_to)), _amount, _paymentType);
            return;
        }

        if (_paymentType == ITelemedicinePayments.PaymentType.ETH) {
            safeTransferETH(_to, _amount);
        } else if (_paymentType == ITelemedicinePayments.PaymentType.USDC) {
            try payments.usdcToken().safeTransfer(_to, _amount) {} catch {
                revert ExternalCallFailed();
            }
        } else if (_paymentType == ITelemedicinePayments.PaymentType.SONIC) {
            try payments.sonicToken().safeTransfer(_to, _amount) {} catch {
                revert ExternalCallFailed();
            }
        } else {
            revert InvalidPaymentType();
        }
    }

    /// @notice Checks sufficient funds
    /// @param _amount Amount
    /// @param _paymentType Payment type
    /// @return True if sufficient
    function _hasSufficientFunds(uint256 _amount, ITelemedicinePayments.PaymentType _paymentType) internal view returns (bool) {
        if (_paymentType == ITelemedicinePayments.PaymentType.ETH) {
            return address(this).balance >= _amount;
        } else if (_paymentType == ITelemedicinePayments.PaymentType.USDC) {
            try payments.usdcToken().balanceOf(address(this)) returns (uint256 balance) {
                return balance >= _amount;
            } catch {
                return false;
            }
        } else if (_paymentType == ITelemedicinePayments.PaymentType.SONIC) {
            try payments.sonicToken().balanceOf(address(this)) returns (uint256 balance) {
                return balance >= _amount;
            } catch {
                return false;
            }
        }
        return false;
    }

    /// @notice Transfers ETH safely
    /// @param _to Recipient
    /// @param _amount Amount
    function safeTransferETH(address _to, uint256 _amount) public {
        (bool success, ) = _to.call{value: _amount}("");
        if (!success) revert PaymentFailed();
    }

    /// @notice Sets lab test payment status
    /// @param _labTestId Lab test ID
    /// @param _status Status
    function setLabTestPayment(uint256 _labTestId, bool _status) external onlyClinicalOps {
        labTestPayments[_labTestId] = _status;
    }

    /// @notice Sets prescription payment status
    /// @param _prescriptionId Prescription ID
    /// @param _status Status
    function setPrescriptionPayment(uint256 _prescriptionId, bool _status) external onlyClinicalOps {
        prescriptionPayments[_prescriptionId] = _status;
    }

    /// @notice Registers lab technician
    /// @param _labTech Lab technician address
    /// @param _locality Locality
    function registerLabTech(address _labTech, string memory _locality) public onlyConfigAdmin {
        if (_labTech == address(0) || bytes(_locality).length == 0) revert InvalidAddress();
        if (labTechIndex[_labTech] != 0 && labTechList[labTechIndex[_labTech].sub(1)] == _labTech) revert AlreadyRegistered();
        try core.hasRole(core.LAB_TECH_ROLE(), _labTech) returns (bool hasRole) {
            if (!hasRole) revert NotAuthorized();
        } catch {
            revert ExternalCallFailed();
        }

        labTechList.push(_labTech);
        labTechIndex[_labTech] = labTechList.length;
        labTechLocalities[_labTech] = _locality;
        localityToLabTechs[_locality].push(_labTech);
        emit LabTechRegistered(keccak256(abi.encode(_labTech)));
    }

    /// @notice Registers pharmacy
    /// @param _pharmacy Pharmacy address
    /// @param _locality Locality
    function registerPharmacy(address _pharmacy, string memory _locality) public onlyConfigAdmin {
        if (_pharmacy == address(0) || bytes(_locality).length == 0) revert InvalidAddress();
        if (pharmacyIndex[_pharmacy] != 0 && pharmacyList[pharmacyIndex[_pharmacy].sub(1)] == _pharmacy) revert AlreadyRegistered();
        try core.hasRole(core.PHARMACY_ROLE(), _pharmacy) returns (bool hasRole) {
            if (!hasRole) revert NotAuthorized();
        } catch {
            revert ExternalCallFailed();
        }

        pharmacyList.push(_pharmacy);
        pharmacyIndex[_pharmacy] = pharmacyList.length;
        pharmacyLocalities[_pharmacy] = _locality;
        localityToPharmacies[_locality].push(_pharmacy);
        emit PharmacyRegistered(keccak256(abi.encode(_pharmacy)));
    }

    /// @notice Monetizes patient data
    /// @param _patient Patient address
    function monetizeData(address _patient) public onlyClinicalOps {
        try core.patients(_patient) returns (TelemedicineCore.Patient memory patient) {
            if (!core.hasRole(core.PATIENT_ROLE(), _patient)) revert NotAuthorized();
            if (patient.dataSharing != TelemedicineCore.DataSharingStatus.Enabled ||
                block.timestamp < patient.lastRewardTimestamp.add(1 days)) return;

            uint256 reward;
            try core.dataMonetizationReward() returns (uint256 r) {
                reward = r;
            } catch {
                revert ExternalCallFailed();
            }
            if (payments.sonicToken().balanceOf(address(payments)) < reward) return;

            patient.lastRewardTimestamp = uint48(block.timestamp);
            try payments.sonicToken().safeTransfer(_patient, reward) {} catch {
                revert ExternalCallFailed();
            }
            emit DataRewardClaimed(keccak256(abi.encode(_patient)), reward);
        } catch {
            revert ExternalCallFailed();
        }
    }

    /// @notice Notifies dispute resolution
    /// @param _id Entity ID
    /// @param _entityType Entity type
    /// @param _outcome Dispute outcome
    function notifyDisputeResolved(
        uint256 _id,
        string memory _entityType,
        TelemedicineMedicalCore.DisputeOutcome _outcome
    ) public onlyClinicalOps {
        // No-op, handled by ClinicalOperations
    }

    /// @notice Notifies data reward claimed
    /// @param _patient Patient address
    /// @param _amount Amount
    function notifyDataRewardClaimed(address _patient, uint256 _amount) public onlyClinicalOps {
        emit DataRewardClaimed(keccak256(abi.encode(_patient)), _amount);
    }

    /// @notice Checks if lab tech exists in locality
    /// @param _locality Locality
    /// @return True if exists
    function hasLabTechInLocality(string memory _locality) public view returns (bool) {
        return localityToLabTechs[_locality].length > 0;
    }

    /// @notice Checks if pharmacy exists in locality
    /// @param _locality Locality
    /// @return True if exists
    function hasPharmacyInLocality(string memory _locality) public view returns (bool) {
        return localityToPharmacies[_locality].length > 0;
    }

    /// @notice Gets lab test details
    /// @param _labTech Lab technician
    /// @param _testTypeIpfsHash Test type IPFS hash
    /// @return Price, validity, timestamps
    function getLabTestDetails(address _labTech, string memory _testTypeIpfsHash)
        public view
        returns (uint256 price, bool isValid, uint48 orderedTimestamp, uint48 completedTimestamp) {
        if (_labTech == address(0) || bytes(_testTypeIpfsHash).length == 0) revert InvalidIpfsHash();
        PriceEntry storage entry = labTechPrices[_labTech][_testTypeIpfsHash];
        if (entry.price > 0 && block.timestamp <= entry.timestamp.add(30 days)) {
            return (entry.price, true, 0, 0);
        }
        return (0, false, 0, 0);
    }

    /// @notice Gets pharmacy price
    /// @param _pharmacy Pharmacy
    /// @param _medicationIpfsHash Medication IPFS hash
    /// @return Price, validity
    function getPharmacyPrice(address _pharmacy, string memory _medicationIpfsHash)
        public view
        returns (uint256 price, bool isValid) {
        if (_pharmacy == address(0) || bytes(_medicationIpfsHash).length == 0) revert InvalidIpfsHash();
        PriceEntry storage entry = pharmacyPrices[_pharmacy][_medicationIpfsHash];
        if (entry.price > 0 && block.timestamp <= entry.timestamp.add(30 days)) {
            return (entry.price, true);
        }
        return (0, false);
    }

    /// @notice Checks if pharmacy is registered
    /// @param _pharmacy Pharmacy address
    /// @return True if registered
    function isPharmacyRegistered(address _pharmacy) public view returns (bool) {
        return pharmacyIndex[_pharmacy] != 0 && pharmacyList[pharmacyIndex[_pharmacy].sub(1)] == _pharmacy;
    }

    /// @notice Checks if lab tech is registered
    /// @param _labTech Lab technician address
    /// @return True if registered
    function isLabTechRegistered(address _labTech) public view returns (bool) {
        return labTechIndex[_labTech] != 0 && labTechList[labTechIndex[_labTech].sub(1)] == _labTech;
    }

    /// @notice Gets lab techs in locality
    /// @param _locality Locality
    /// @param _startIndex Start index
    /// @param _pageSize Page size
    /// @return Lab techs, total count
    function getLabTechsInLocality(string memory _locality, uint256 _startIndex, uint256 _pageSize)
        public view
        returns (address[] memory labTechs, uint256 totalCount) {
        try base.maxBatchSize() returns (uint256 maxBatch) {
            if (_pageSize == 0 || _pageSize > maxBatch) revert InvalidIndex();
        } catch {
            revert ExternalCallFailed();
        }

        address[] memory allLabTechs = localityToLabTechs[_locality];
        totalCount = allLabTechs.length;
        if (_startIndex >= totalCount) return (new address[](0), totalCount);

        uint256 endIndex = _startIndex.add(_pageSize) > totalCount ? totalCount : _startIndex.add(_pageSize);
        labTechs = new address[](endIndex.sub(_startIndex));
        for (uint256 i = _startIndex; i < endIndex; i++) {
            labTechs[i.sub(_startIndex)] = allLabTechs[i];
        }
        return (labTechs, totalCount);
    }

    /// @notice Gets lab tech capacity
    /// @param _labTech Lab technician
    /// @return Capacity
    function getLabTechCapacity(address _labTech) public view returns (uint256) {
        return type(uint256).max; // Placeholder
    }

    /// @notice Gets lab tech rating
    /// @param _labTech Lab technician
    /// @return Average rating, rating count
    function getLabTechRating(address _labTech) public view returns (uint256, uint256) {
        return (0, 0); // Placeholder
    }

    /// @notice Gets lab tech locality
    /// @param _labTech Lab technician
    /// @return Locality
    function getLabTechLocality(address _labTech) public view returns (string memory) {
        return labTechLocalities[_labTech];
    }

    /// @notice Checks multi-signature approval
    /// @param _operationHash Operation hash
    /// @return True if approved
    function checkMultiSigApproval(bytes32 _operationHash) public view returns (bool) {
        uint256 approvalCount = 0;
        for (uint256 i = 0; i < multiSigSigners.length; i++) {
            if (multiSigApprovals[multiSigSigners[i]][_operationHash]) {
                approvalCount = approvalCount.add(1);
            }
        }
        return approvalCount >= requiredSignatures;
    }

    /// @notice Approves critical operation
    /// @param _operationHash Operation hash
    function approveCriticalOperation(bytes32 _operationHash) external {
        bool isSigner;
        for (uint256 i = 0; i < multiSigSigners.length; i++) {
            if (multiSigSigners[i] == msg.sender) {
                isSigner = true;
                break;
            }
        }
        if (!isSigner) revert NotAuthorized();
        if (multiSigApprovals[msg.sender][_operationHash]) revert AlreadyRegistered();

        multiSigApprovals[msg.sender][_operationHash] = true;
        emit MultiSigApproval(keccak256(abi.encode(msg.sender)), _operationHash);
    }

    /// @notice Resets multi-signature approvals
    /// @param _operationHash Operation hash
    function _resetMultiSigApprovals(bytes32 _operationHash) internal {
        for (uint256 i = 0; i < multiSigSigners.length; i++) {
            multiSigApprovals[multiSigSigners[i]][_operationHash] = false;
        }
    }

    // View Functions

    /// @notice Gets payment status
    /// @param _id Lab test or prescription ID
    /// @param _isLabTest Lab test flag
    /// @return Payment status
    function getPaymentStatus(uint256 _id, bool _isLabTest) external view onlyConfigAdmin returns (bool) {
        return _isLabTest ? labTestPayments[_id] : prescriptionPayments[_id];
    }

    /// @notice Gets invitation
    /// @param _invitationId Invitation ID
    /// @return Invitation details
    function getInvitation(bytes32 _invitationId) external view onlyConfigAdmin returns (Invitation memory) {
        return invitations[_invitationId];
    }

    /// @notice Gets pending payment
    /// @param _paymentId Payment ID
    /// @return Pending payment details
    function getPendingPayment(uint256 _paymentId) external view onlyConfigAdmin returns (PendingPayment memory) {
        return pendingPayments[_paymentId];
    }

    /// @notice Gets Chainlink request IDs
    /// @param _requestId Request ID
    /// @return Lab test ID, prescription ID
    function getChainlinkRequestIds(bytes32 _requestId) external view onlyConfigAdmin returns (uint256, uint256) {
        return (requestToLabTestId[_requestId], requestToPrescriptionId[_requestId]);
    }

    // Utility Functions

    /// @notice Checks if an address is a contract
    /// @param addr Address
    /// @return True if contract
    function _isContract(address addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(addr) }
        return size > 0;
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

    modifier onlyClinicalOps() {
        if (msg.sender != address(clinicalOps)) revert NotAuthorized();
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

    modifier onlyMultiSig(bytes32 _operationHash) {
        if (!checkMultiSigApproval(_operationHash)) revert MultiSigNotApproved();
        _;
    }

    receive() external payable {}

    // New: Storage gap
    uint256[50] private __gap;
}
