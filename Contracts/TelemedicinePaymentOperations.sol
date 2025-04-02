// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {SafeMathUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";
import {SafeERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import {TelemedicineCore} from "./TelemedicineCore.sol";
import {TelemedicinePayments} from "./TelemedicinePayments.sol";
import {TelemedicineDisputeResolution} from "./TelemedicineDisputeResolution.sol";
import {ChainlinkClient, Chainlink} from "@chainlink/contracts/src/v0.8/ChainlinkClient.sol";
import {IERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import {TelemedicineBase} from "./TelemedicineBase.sol";
import {TelemedicineClinicalOperations} from "./TelemedicineClinicalOperations.sol";

contract TelemedicinePaymentOperations is Initializable, ReentrancyGuardUpgradeable, ChainlinkClient {
    using SafeMathUpgradeable for uint256;
    using Chainlink for Chainlink.Request;
    using SafeERC20Upgradeable for IERC20Upgradeable;

    // Custom Errors
    error NotAuthorized();
    error ContractPaused();
    error InvalidAddress();
    error InvalidStatus();
    error InvalidTimestamp();
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
    error ChainlinkRequestTimeout();
    error AlreadyRegistered();
    error NotRegistered();
    error InvalidPrice();

    // Contract dependencies
    TelemedicineCore public core;
    TelemedicinePayments public payments;
    TelemedicineDisputeResolution public disputeResolution;
    TelemedicineBase public base;
    TelemedicineClinicalOperations public clinicalOps;

    // Chainlink Configuration
    mapping(bytes32 => uint256) public requestToLabTestId;
    mapping(bytes32 => uint256) public requestToPrescriptionId;
    mapping(bytes32 => uint48) public requestTimestamps;

    // State Variables
    mapping(uint256 => bool) public labTestPayments;
    mapping(uint256 => bool) public prescriptionPayments;
    mapping(uint256 => uint48) public labTestPaymentDeadlines;
    mapping(uint256 => uint48) public prescriptionPaymentDeadlines;

    struct PendingPayment {
        address recipient;
        uint256 amount;
        TelemedicinePayments.PaymentType paymentType;
        bool processed;
    }
    mapping(uint256 => PendingPayment) public pendingPayments;
    uint256 public pendingPaymentCounter;

    struct Invitation {
        address patient;
        string locality;
        string inviteeContact;
        bool isLabTech;
        bool fulfilled;
        uint48 expirationTimestamp;
    }
    mapping(bytes32 => Invitation) public invitations;
    uint256 public invitationCounter;

    // Medical Services State Variables (from TelemedicineMedicalServices)
    mapping(address => mapping(string => PriceEntry)) private labTechPrices;
    mapping(address => mapping(string => PriceEntry)) private pharmacyPrices;
    mapping(address => uint256) private labTechIndex;
    mapping(address => uint256) private pharmacyIndex;
    mapping(address => mapping(bytes32 => bool)) public multiSigApprovals;
    mapping(address => string) private labTechLocalities;
    mapping(address => string) private pharmacyLocalities;

    address[] public labTechList;
    address[] public pharmacyList;
    address[] public multiSigSigners;
    uint256 public requiredSignatures;

    // Structs (from TelemedicineMedicalServices)
    struct PriceEntry {
        uint256 price;
        uint48 timestamp;
    }

    // Events
    event FundsWithdrawn(address indexed recipient, uint256 amount, TelemedicinePayments.PaymentType paymentType);
    event LabTestRefunded(uint256 indexed testId, address patient, uint256 amount);
    event PrescriptionRefunded(uint256 indexed prescriptionId, address patient, uint256 amount);
    event InvitationSubmitted(bytes32 indexed invitationId, address patient, string locality, string inviteeContact, bool isLabTech);
    event InvitationFulfilled(bytes32 indexed invitationId, address invitee);
    event InvitationExpired(bytes32 indexed invitationId);
    event LabTestPaymentConfirmed(uint256 indexed testId, uint256 amount);
    event PrescriptionPaymentConfirmed(uint256 indexed prescriptionId, uint256 amount);
    event LabTestPaymentPending(uint256 indexed testId, uint256 patientCost, uint48 deadline);
    event PrescriptionPaymentPending(uint256 indexed prescriptionId, uint256 patientCost, uint48 deadline);
    event LabTestPaymentReleased(uint256 indexed testId, address labTech, uint256 amount, TelemedicinePayments.PaymentType paymentType);
    event PrescriptionPaymentReleased(uint256 indexed prescriptionId, address pharmacy, uint256 amount, TelemedicinePayments.PaymentType paymentType);
    event PaymentQueued(uint256 indexed paymentId, address recipient, uint256 amount, TelemedicinePayments.PaymentType paymentType);
    event PaymentReleasedFromQueue(uint256 indexed paymentId, address recipient, uint256 amount);
    event LabTechRegistered(address indexed labTech);
    event PharmacyRegistered(address indexed pharmacy);
    event LabTechPriceUpdated(address indexed labTech, string testTypeIpfsHash, uint256 price, uint48 timestamp);
    event PharmacyPriceUpdated(address indexed pharmacy, string medicationIpfsHash, uint256 price, uint48 timestamp);
    event DataRewardClaimed(address indexed patient, uint256 amount);
    event MultiSigApproval(address indexed signer, bytes32 indexed operationHash);

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

        __ReentrancyGuard_init();
        core = TelemedicineCore(_core);
        payments = TelemedicinePayments(_payments);
        disputeResolution = TelemedicineDisputeResolution(_disputeResolution);
        base = TelemedicineBase(_base);
        clinicalOps = TelemedicineClinicalOperations(_clinicalOps);
        multiSigSigners = _multiSigSigners;
        requiredSignatures = _requiredSignatures;

        invitationCounter = 0;
        pendingPaymentCounter = 0;
    }

    function confirmPayment(uint256 _id, bool _isLabTest, TelemedicinePayments.PaymentType _paymentType)
        external payable onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
        if (_isLabTest) {
            TelemedicineClinicalOperations.LabTestOrder storage order = clinicalOps.labTestOrders(_id);
            if (_id == 0 || _id > clinicalOps.labTestCounter()) revert InvalidIndex();
            if (order.patient != msg.sender) revert NotAuthorized();
            if (order.status != TelemedicineClinicalOperations.LabTestStatus.PaymentPending) revert InvalidStatus();
            if (block.timestamp > labTestPaymentDeadlines[_id]) revert PaymentDeadlineMissed();

            if (_paymentType == TelemedicinePayments.PaymentType.ETH) {
                if (msg.value < order.patientCost) revert InsufficientFunds();
                order.paymentType = _paymentType;
                labTestPayments[_id] = true;
                order.status = TelemedicineClinicalOperations.LabTestStatus.Requested;
                emit LabTestPaymentConfirmed(_id, order.patientCost);
                if (msg.value > order.patientCost) {
                    uint256 refund = msg.value - order.patientCost;
                    safeTransferETH(msg.sender, refund);
                }
            } else {
                payments._processPayment(_paymentType, order.patientCost);
                order.paymentType = _paymentType;
                labTestPayments[_id] = true;
                order.status = TelemedicineClinicalOperations.LabTestStatus.Requested;
                emit LabTestPaymentConfirmed(_id, order.patientCost);
            }
        } else {
            TelemedicineClinicalOperations.Prescription storage prescription = clinicalOps.prescriptions(_id);
            if (_id == 0 || _id > clinicalOps.prescriptionCounter()) revert InvalidIndex();
            if (prescription.patient != msg.sender) revert NotAuthorized();
            if (prescription.status != TelemedicineClinicalOperations.PrescriptionStatus.PaymentPending) revert InvalidStatus();
            if (block.timestamp > prescriptionPaymentDeadlines[_id]) revert PaymentDeadlineMissed();

            if (_paymentType == TelemedicinePayments.PaymentType.ETH) {
                if (msg.value < prescription.patientCost) revert InsufficientFunds();
                prescription.paymentType = _paymentType;
                prescriptionPayments[_id] = true;
                prescription.status = TelemedicineClinicalOperations.PrescriptionStatus.Generated;
                emit PrescriptionPaymentConfirmed(_id, prescription.patientCost);
                if (msg.value > prescription.patientCost) {
                    uint256 refund = msg.value - prescription.patientCost;
                    safeTransferETH(msg.sender, refund);
                }
            } else {
                payments._processPayment(_paymentType, prescription.patientCost);
                prescription.paymentType = _paymentType;
                prescriptionPayments[_id] = true;
                prescription.status = TelemedicineClinicalOperations.PrescriptionStatus.Generated;
                emit PrescriptionPaymentConfirmed(_id, prescription.patientCost);
            }
        }
    }

    function inviteProvider(string calldata _locality, string calldata _inviteeContact, bool _isLabTech)
        external onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
        if (bytes(_locality).length == 0 || bytes(_inviteeContact).length == 0) revert InvalidLocality();

        bool hasProvider = _isLabTech ? hasLabTechInLocality(_locality) : hasPharmacyInLocality(_locality);
        if (hasProvider) revert ProvidersAlreadyExist();

        bytes32 invitationId = keccak256(abi.encodePacked(msg.sender, _locality, _isLabTech, block.timestamp));
        if (invitations[invitationId].patient != address(0)) revert InvitationAlreadyExists();

        invitationCounter = invitationCounter + 1;
        invitations[invitationId] = Invitation({
            patient: msg.sender,
            locality: _locality,
            inviteeContact: _inviteeContact,
            isLabTech: _isLabTech,
            fulfilled: false,
            expirationTimestamp: uint48(block.timestamp) + base.invitationExpirationPeriod()
        });

        emit InvitationSubmitted(invitationId, msg.sender, _locality, _inviteeContact, _isLabTech);
    }

    function registerAsInvitedProvider(bytes32 _invitationId, address _providerAddress)
        external onlyRole(core.ADMIN_ROLE()) nonReentrant whenNotPaused {
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
        emit InvitationFulfilled(_invitationId, _providerAddress);
    }

    function checkInvitationExpiration(bytes32 _invitationId) external nonReentrant whenNotPaused {
        Invitation storage invitation = invitations[_invitationId];
        if (invitation.patient == address(0)) revert InvalidIndex();
        if (invitation.fulfilled) return;
        if (block.timestamp <= invitation.expirationTimestamp) return;

        delete invitations[_invitationId];
        emit InvitationExpired(_invitationId);
    }

    function requestLabTestPrice(address _labTech, string calldata _testTypeIpfsHash, uint256 _labTestId)
        external onlyClinicalOps returns (bytes32) {
        if (base.manualPriceOverride()) return bytes32(0);
        Chainlink.Request memory req = buildChainlinkRequest(
            base.priceListJobId(),
            address(this),
            this.fulfillLabTestPrice.selector
        );
        req.add("testType", _testTypeIpfsHash);
        req.add("labTech", toString(_labTech));
        bytes32 requestId = sendChainlinkRequestTo(base.chainlinkOracle(), req, base.chainlinkFee());
        requestToLabTestId[requestId] = _labTestId;
        requestTimestamps[requestId] = uint48(block.timestamp);
        return requestId;
    }

    function fulfillLabTestPrice(bytes32 _requestId, uint256 _price) public recordChainlinkFulfillment(_requestId) {
        uint256 labTestId = requestToLabTestId[_requestId];
        if (labTestId == 0 || labTestId > clinicalOps.labTestCounter()) revert InvalidIndex();
        TelemedicineClinicalOperations.LabTestOrder storage order = clinicalOps.labTestOrders(labTestId);
        if (order.status != TelemedicineClinicalOperations.LabTestStatus.Requested) revert InvalidStatus();
        if (_price == 0) revert OracleResponseInvalid();

        order.patientCost = _price * 120 / base.PERCENTAGE_DENOMINATOR();
        order.status = TelemedicineClinicalOperations.LabTestStatus.PaymentPending;
        labTestPaymentDeadlines[labTestId] = uint48(block.timestamp) + base.paymentConfirmationDeadline();
        delete requestToLabTestId[_requestId];
        delete requestTimestamps[_requestId];
        emit LabTestPaymentPending(labTestId, order.patientCost, labTestPaymentDeadlines[labTestId]);
    }

    function requestPrescriptionPrice(address _pharmacy, string calldata _medicationIpfsHash, uint256 _prescriptionId)
        external onlyClinicalOps returns (bytes32) {
        if (base.manualPriceOverride()) return bytes32(0);
        Chainlink.Request memory req = buildChainlinkRequest(
            base.priceListJobId(),
            address(this),
            this.fulfillPrescriptionPrice.selector
        );
        req.add("medication", _medicationIpfsHash);
        req.add("pharmacy", toString(_pharmacy));
        bytes32 requestId = sendChainlinkRequestTo(base.chainlinkOracle(), req, base.chainlinkFee());
        requestToPrescriptionId[requestId] = _prescriptionId;
        requestTimestamps[requestId] = uint48(block.timestamp);
        return requestId;
    }

    function fulfillPrescriptionPrice(bytes32 _requestId, uint256 _price) public recordChainlinkFulfillment(_requestId) {
        uint256 prescriptionId = requestToPrescriptionId[_requestId];
        if (prescriptionId == 0 || prescriptionId > clinicalOps.prescriptionCounter()) revert InvalidIndex();
        TelemedicineClinicalOperations.Prescription storage prescription = clinicalOps.prescriptions(prescriptionId);
        if (prescription.status != TelemedicineClinicalOperations.PrescriptionStatus.Generated) revert InvalidStatus();
        if (_price == 0) revert OracleResponseInvalid();

        prescription.patientCost = _price * 120 / base.PERCENTAGE_DENOMINATOR();
        prescription.status = TelemedicineClinicalOperations.PrescriptionStatus.PaymentPending;
        prescriptionPaymentDeadlines[prescriptionId] = uint48(block.timestamp) + base.paymentConfirmationDeadline();
        delete requestToPrescriptionId[_requestId];
        delete requestTimestamps[_requestId];
        emit PrescriptionPaymentPending(prescriptionId, prescription.patientCost, prescriptionPaymentDeadlines[prescriptionId]);
    }

    function cancelChainlinkRequest(bytes32 _requestId) external onlyRole(core.ADMIN_ROLE()) {
        if (requestToLabTestId[_requestId] == 0 && requestToPrescriptionId[_requestId] == 0) revert InvalidIndex();
        if (block.timestamp <= requestTimestamps[_requestId] + base.chainlinkRequestTimeout()) revert InvalidTimestamp();

        cancelChainlinkRequest(_requestId);
        delete requestToLabTestId[_requestId];
        delete requestToPrescriptionId[_requestId];
        delete requestTimestamps[_requestId];
    }

    function releaseLabTestPayment(uint256 _labTestId) external nonReentrant whenNotPaused {
        TelemedicineClinicalOperations.LabTestOrder storage order = clinicalOps.labTestOrders(_labTestId);
        if (_labTestId == 0 || _labTestId > clinicalOps.labTestCounter()) revert InvalidIndex();
        if (order.status != TelemedicineClinicalOperations.LabTestStatus.ResultsUploaded && 
            order.status != TelemedicineClinicalOperations.LabTestStatus.Reviewed && 
            order.status != TelemedicineClinicalOperations.LabTestStatus.Disputed) revert InvalidStatus();
        if (block.timestamp <= order.disputeWindowEnd) revert InvalidTimestamp();
        if (!labTestPayments[_labTestId]) revert PaymentNotConfirmed();

        bool isDisputed = disputeResolution.isDisputed(_labTestId);
        if (isDisputed) {
            TelemedicineClinicalOperations.DisputeOutcome outcome = disputeResolution.getDisputeOutcome(_labTestId);
            if (outcome == TelemedicineClinicalOperations.DisputeOutcome.Unresolved) revert InvalidStatus();

            if (outcome == TelemedicineClinicalOperations.DisputeOutcome.PatientFavored) {
                payments._refundPatient(order.patient, order.patientCost, order.paymentType);
                emit LabTestRefunded(_labTestId, order.patient, order.patientCost);
            } else if (outcome == TelemedicineClinicalOperations.DisputeOutcome.ProviderFavored || 
                       outcome == TelemedicineClinicalOperations.DisputeOutcome.MutualAgreement) {
                _releasePayment(order.labTech, order.patientCost, order.paymentType);
                emit LabTestPaymentReleased(_labTestId, order.labTech, order.patientCost, order.paymentType);
            }
            order.status = TelemedicineClinicalOperations.LabTestStatus.Disputed;
            notifyDisputeResolved(_labTestId, "LabTest", outcome);
        } else {
            _releasePayment(order.labTech, order.patientCost, order.paymentType);
            emit LabTestPaymentReleased(_labTestId, order.labTech, order.patientCost, order.paymentType);
        }

        labTestPayments[_labTestId] = false;
    }

    function releasePrescriptionPayment(uint256 _prescriptionId) external nonReentrant whenNotPaused {
        TelemedicineClinicalOperations.Prescription storage prescription = clinicalOps.prescriptions(_prescriptionId);
        if (_prescriptionId == 0 || _prescriptionId > clinicalOps.prescriptionCounter()) revert InvalidIndex();
        if (prescription.status != TelemedicineClinicalOperations.PrescriptionStatus.Fulfilled && 
            prescription.status != TelemedicineClinicalOperations.PrescriptionStatus.Disputed) revert InvalidStatus();
        if (block.timestamp <= prescription.disputeWindowEnd) revert InvalidTimestamp();
        if (!prescriptionPayments[_prescriptionId]) revert PaymentNotConfirmed();

        bool isDisputed = disputeResolution.isDisputed(_prescriptionId);
        if (isDisputed) {
            TelemedicineClinicalOperations.DisputeOutcome outcome = disputeResolution.getDisputeOutcome(_prescriptionId);
            if (outcome == TelemedicineClinicalOperations.DisputeOutcome.Unresolved) revert InvalidStatus();

            if (outcome == TelemedicineClinicalOperations.DisputeOutcome.PatientFavored) {
                payments._refundPatient(prescription.patient, prescription.patientCost, prescription.paymentType);
                emit PrescriptionRefunded(_prescriptionId, prescription.patient, prescription.patientCost);
            } else if (outcome == TelemedicineClinicalOperations.DisputeOutcome.ProviderFavored || 
                       outcome == TelemedicineClinicalOperations.DisputeOutcome.MutualAgreement) {
                _releasePayment(prescription.pharmacy, prescription.patientCost, prescription.paymentType);
                emit PrescriptionPaymentReleased(_prescriptionId, prescription.pharmacy, prescription.patientCost, prescription.paymentType);
            }
            prescription.status = TelemedicineClinicalOperations.PrescriptionStatus.Disputed;
            notifyDisputeResolved(_prescriptionId, "Prescription", outcome);
        } else {
            _releasePayment(prescription.pharmacy, prescription.patientCost, prescription.paymentType);
            emit PrescriptionPaymentReleased(_prescriptionId, prescription.pharmacy, prescription.patientCost, prescription.paymentType);
        }

        prescriptionPayments[_prescriptionId] = false;
    }

    function withdrawFunds(
        address _recipient,
        uint256 _amount,
        TelemedicinePayments.PaymentType _paymentType,
        bytes32 _operationHash
    ) external onlyRole(core.ADMIN_ROLE()) nonReentrant whenNotPaused onlyMultiSig(_operationHash) {
        bytes32 expectedHash = keccak256(abi.encodePacked(
            "withdrawFunds",
            _recipient,
            _amount,
            _paymentType,
            msg.sender,
            block.timestamp,
            base.nonces(msg.sender)++
        ));
        if (_operationHash != expectedHash) revert MultiSigNotApproved();

        if (_recipient == address(0)) revert InvalidAddress();
        if (_amount == 0) revert InsufficientFunds();

        _releasePayment(_recipient, _amount, _paymentType);
        emit FundsWithdrawn(_recipient, _amount, _paymentType);
    }

    function setManualLabTestPrice(uint256 _labTestId, uint256 _price) external onlyRole(core.ADMIN_ROLE()) {
        if (!base.manualPriceOverride()) revert NotAuthorized();
        if (_labTestId == 0 || _labTestId > clinicalOps.labTestCounter()) revert InvalidIndex();
        TelemedicineClinicalOperations.LabTestOrder storage order = clinicalOps.labTestOrders(_labTestId);
        if (order.status != TelemedicineClinicalOperations.LabTestStatus.Requested) revert InvalidStatus();
        if (_price == 0) revert InsufficientFunds();

        order.patientCost = _price * 120 / base.PERCENTAGE_DENOMINATOR();
        order.status = TelemedicineClinicalOperations.LabTestStatus.PaymentPending;
        labTestPaymentDeadlines[_labTestId] = uint48(block.timestamp) + base.paymentConfirmationDeadline();
        emit LabTestPaymentPending(_labTestId, order.patientCost, labTestPaymentDeadlines[_labTestId]);
    }

    function setManualPrescriptionPrice(uint256 _prescriptionId, uint256 _price) external onlyRole(core.ADMIN_ROLE()) {
        if (!base.manualPriceOverride()) revert NotAuthorized();
        if (_prescriptionId == 0 || _prescriptionId > clinicalOps.prescriptionCounter()) revert InvalidIndex();
        TelemedicineClinicalOperations.Prescription storage prescription = clinicalOps.prescriptions(_prescriptionId);
        if (prescription.status != TelemedicineClinicalOperations.PrescriptionStatus.Generated) revert InvalidStatus();
        if (_price == 0) revert InsufficientFunds();

        prescription.patientCost = _price * 120 / base.PERCENTAGE_DENOMINATOR();
        prescription.status = TelemedicineClinicalOperations.PrescriptionStatus.PaymentPending;
        prescriptionPaymentDeadlines[_prescriptionId] = uint48(block.timestamp) + base.paymentConfirmationDeadline();
        emit PrescriptionPaymentPending(_prescriptionId, prescription.patientCost, prescriptionPaymentDeadlines[_prescriptionId]);
    }

    function toggleManualPriceOverride(bool _enabled) external onlyRole(core.ADMIN_ROLE()) {
        base.toggleManualPriceOverride(_enabled);
    }

    function releasePendingPayments(uint256 _startId, uint256 _count) external onlyRole(core.ADMIN_ROLE()) nonReentrant {
        uint256 endId = _startId + _count > pendingPaymentCounter ? pendingPaymentCounter : _startId + _count;
        for (uint256 i = _startId; i < endId; i++) {
            PendingPayment storage payment = pendingPayments[i];
            if (payment.processed || payment.amount == 0) continue;

            if (_hasSufficientFunds(payment.amount, payment.paymentType)) {
                _releasePayment(payment.recipient, payment.amount, payment.paymentType);
                payment.processed = true;
                emit PaymentReleasedFromQueue(i, payment.recipient, payment.amount);
            }
        }
    }

    function selectBestLabTech(string memory _testTypeIpfsHash, string memory _locality) public view returns (address) {
        (address[] memory labTechs, ) = getLabTechsInLocality(_locality, 0, base.maxBatchSize());
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
            uint256 score = (avgRating > 0 && ratingCount > 0) ? avgRating * ratingCount / price : 0;

            if (score > highestScore) {
                highestScore = score;
                bestLabTech = labTechs[i];
            }
        }
        return bestLabTech != address(0) ? bestLabTech : fallbackTech;
    }

    function _releasePayment(address _to, uint256 _amount, TelemedicinePayments.PaymentType _paymentType) internal {
        if (!_hasSufficientFunds(_amount, _paymentType)) {
            pendingPaymentCounter++;
            pendingPayments[pendingPaymentCounter] = PendingPayment(_to, _amount, _paymentType, false);
            emit PaymentQueued(pendingPaymentCounter, _to, _amount, _paymentType);
            return;
        }

        if (_paymentType == TelemedicinePayments.PaymentType.ETH) {
            safeTransferETH(_to, _amount);
        } else if (_paymentType == TelemedicinePayments.PaymentType.USDC) {
            payments.usdcToken().safeTransfer(_to, _amount);
        } else if (_paymentType == TelemedicinePayments.PaymentType.SONIC) {
            payments.sonicToken().safeTransfer(_to, _amount);
        } else {
            revert InvalidStatus();
        }
    }

    function _hasSufficientFunds(uint256 _amount, TelemedicinePayments.PaymentType _paymentType) internal view returns (bool) {
        if (_paymentType == TelemedicinePayments.PaymentType.ETH) {
            return address(this).balance >= _amount;
        } else if (_paymentType == TelemedicinePayments.PaymentType.USDC) {
            return payments.usdcToken().balanceOf(address(this)) >= _amount;
        } else if (_paymentType == TelemedicinePayments.PaymentType.SONIC) {
            return payments.sonicToken().balanceOf(address(this)) >= _amount;
        }
        return false;
    }

    function safeTransferETH(address _to, uint256 _amount) public {
        (bool success, ) = _to.call{value: _amount}("");
        if (!success) revert PaymentFailed();
    }

    function setLabTestPayment(uint256 _labTestId, bool _status) external onlyClinicalOps {
        labTestPayments[_labTestId] = _status;
    }

    function setPrescriptionPayment(uint256 _prescriptionId, bool _status) external onlyClinicalOps {
        prescriptionPayments[_prescriptionId] = _status;
    }

    function getLabTestPaymentStatus(uint256 _labTestId) external view returns (bool) {
        return labTestPayments[_labTestId];
    }

    function getPrescriptionPaymentStatus(uint256 _prescriptionId) external view returns (bool) {
        return prescriptionPayments[_prescriptionId];
    }

    function getLabTestPaymentDeadline(uint256 _labTestId) external view returns (uint48) {
        return labTestPaymentDeadlines[_labTestId];
    }

    function getPrescriptionPaymentDeadline(uint256 _prescriptionId) external view returns (uint48) {
        return prescriptionPaymentDeadlines[_prescriptionId];
    }

    function toString(address _addr) internal pure returns (string memory) {
        bytes32 value = bytes32(uint256(uint160(_addr)));
        bytes memory alphabet = "0123456789abcdef";
        bytes memory str = new bytes(42);
        str[0] = "0";
        str[1] = "x";
        for (uint256 i = 0; i < 20; i++) {
            str[2 + i * 2] = alphabet[uint8(value[i + 12] >> 4)];
            str[3 + i * 2] = alphabet[uint8(value[i + 12] & 0x0f)];
        }
        return string(str);
    }

    // Implemented Functions from TelemedicineMedicalServices

    function hasLabTechInLocality(string memory _locality) public view returns (bool) {
        for (uint256 i = 0; i < labTechList.length; i++) {
            if (keccak256(abi.encodePacked(labTechLocalities[labTechList[i]])) == keccak256(abi.encodePacked(_locality))) {
                return true;
            }
        }
        return false;
    }

    function hasPharmacyInLocality(string memory _locality) public view returns (bool) {
        for (uint256 i = 0; i < pharmacyList.length; i++) {
            if (keccak256(abi.encodePacked(pharmacyLocalities[pharmacyList[i]])) == keccak256(abi.encodePacked(_locality))) {
                return true;
            }
        }
        return false;
    }

    function registerLabTech(address _labTech, string memory _locality) public onlyRole(core.ADMIN_ROLE()) {
        if (labTechIndex[_labTech] != 0 && labTechList[labTechIndex[_labTech] - 1] == _labTech) 
            revert AlreadyRegistered();
        labTechList.push(_labTech);
        labTechIndex[_labTech] = labTechList.length;
        labTechLocalities[_labTech] = _locality;
        emit LabTechRegistered(_labTech);
    }

    function registerPharmacy(address _pharmacy, string memory _locality) public onlyRole(core.ADMIN_ROLE()) {
        if (pharmacyIndex[_pharmacy] != 0 && pharmacyList[pharmacyIndex[_pharmacy] - 1] == _pharmacy) 
            revert AlreadyRegistered();
        pharmacyList.push(_pharmacy);
        pharmacyIndex[_pharmacy] = pharmacyList.length;
        pharmacyLocalities[_pharmacy] = _locality;
        emit PharmacyRegistered(_pharmacy);
    }

    function getLabTestDetails(address _labTech, string memory _testTypeIpfsHash) 
        public view 
        returns (uint256 price, bool isValid, uint48 orderedTimestamp, uint48 completedTimestamp) {
        if (_labTech == address(0)) revert InvalidAddress();
        if (bytes(_testTypeIpfsHash).length == 0) revert InvalidIpfsHash();
        PriceEntry storage entry = labTechPrices[_labTech][_testTypeIpfsHash];
        if (entry.price > 0 && block.timestamp <= entry.timestamp + 30 days) {
            return (entry.price, true, 0, 0); // Timestamps not stored here, return 0
        }
        return (0, false, 0, 0);
    }

    function getPharmacyPrice(address _pharmacy, string memory _medicationIpfsHash) 
        public view 
        returns (uint256 price, bool isValid) {
        if (_pharmacy == address(0)) revert InvalidAddress();
        if (bytes(_medicationIpfsHash).length == 0) revert InvalidIpfsHash();
        PriceEntry storage entry = pharmacyPrices[_pharmacy][_medicationIpfsHash];
        if (entry.price > 0 && block.timestamp <= entry.timestamp + 30 days) {
            return (entry.price, true);
        }
        return (0, false);
    }

    function isPharmacyRegistered(address _pharmacy) public view returns (bool) {
        return pharmacyIndex[_pharmacy] != 0 && pharmacyList[pharmacyIndex[_pharmacy] - 1] == _pharmacy;
    }

    function isLabTechRegistered(address _labTech) public view returns (bool) {
        return labTechIndex[_labTech] != 0 && labTechList[labTechIndex[_labTech] - 1] == _labTech;
    }

    function monetizeData(address _patient) public onlyClinicalOps {
        TelemedicineCore.Patient storage patient = core.patients(_patient);
        if (patient.dataSharing == TelemedicineCore.DataSharingStatus.Enabled && 
            block.timestamp >= patient.lastRewardTimestamp.add(1 days)) {
            uint256 reward = core.dataMonetizationReward();
            if (payments.sonicToken().balanceOf(address(payments)) >= reward) {
                patient.lastRewardTimestamp = uint48(block.timestamp);
                payments.sonicToken().safeTransfer(_patient, reward);
                emit DataRewardClaimed(_patient, reward);
            }
        }
    }

    function notifyDisputeResolved(
        uint256 _id, 
        string memory _entityType, 
        TelemedicineClinicalOperations.DisputeOutcome _outcome
    ) public onlyClinicalOps {
        // No-op implementation since ClinicalOperations handles state updates
    }

    function notifyDataRewardClaimed(address _patient, uint256 _amount) public onlyClinicalOps {
        emit DataRewardClaimed(_patient, _amount);
    }

    function getLabTechsInLocality(string memory _locality, uint256 _startIndex, uint256 _pageSize) 
        public view 
        returns (address[] memory labTechs, uint256 totalCount) {
        if (_pageSize == 0 || _pageSize > base.maxBatchSize()) revert InvalidIndex();

        address[] memory tempLabTechs = new address[](labTechList.length);
        uint256 count = 0;
        for (uint256 i = 0; i < labTechList.length; i++) {
            if (keccak256(abi.encodePacked(labTechLocalities[labTechList[i]])) == keccak256(abi.encodePacked(_locality))) {
                tempLabTechs[count] = labTechList[i];
                count++;
            }
        }

        totalCount = count;
        if (_startIndex >= count) return (new address[](0), totalCount);

        uint256 endIndex = _startIndex + _pageSize > count ? count : _startIndex + _pageSize;
        labTechs = new address[](endIndex - _startIndex);
        for (uint256 i = _startIndex; i < endIndex; i++) {
            labTechs[i - _startIndex] = tempLabTechs[i];
        }
        return (labTechs, totalCount);
    }

    function getLabTechCapacity(address _labTech) public view returns (uint256) {
        // Placeholder: Assume infinite capacity since not tracked in this contract
        return type(uint256).max;
    }

    function getLabTechRating(address _labTech) public view returns (uint256, uint256) {
        // Placeholder: Ratings not tracked in this contract, return 0
        return (0, 0);
    }

    function getLabTechLocality(address _labTech) public view returns (string memory) {
        return labTechLocalities[_labTech];
    }

    function checkMultiSigApproval(bytes32 _operationHash) public view returns (bool) {
        uint256 approvalCount = 0;
        for (uint256 i = 0; i < multiSigSigners.length; i++) {
            if (multiSigApprovals[multiSigSigners[i]][_operationHash]) {
                approvalCount = approvalCount.add(1);
            }
        }
        return approvalCount >= requiredSignatures;
    }

    function approveCriticalOperation(bytes32 _operationHash) external {
        bool isSigner = false;
        for (uint256 i = 0; i < multiSigSigners.length; i++) {
            if (multiSigSigners[i] == msg.sender) {
                isSigner = true;
                break;
            }
        }
        if (!isSigner) revert NotAuthorized();
        if (multiSigApprovals[msg.sender][_operationHash]) revert AlreadyRegistered();

        multiSigApprovals[msg.sender][_operationHash] = true;
        emit MultiSigApproval(msg.sender, _operationHash);
    }

    modifier onlyRole(bytes32 role) {
        if (!core.hasRole(role, msg.sender)) revert NotAuthorized();
        _;
    }

    modifier onlyClinicalOps() {
        if (msg.sender != address(clinicalOps)) revert NotAuthorized();
        _;
    }

    modifier whenNotPaused() {
        if (core.paused()) revert ContractPaused();
        _;
    }

    modifier onlyMultiSig(bytes32 _operationHash) {
        if (!checkMultiSigApproval(_operationHash)) revert MultiSigNotApproved();
        _;
    }

    receive() external payable {}
}
