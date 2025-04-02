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
import {LinkTokenInterface} from "@chainlink/contracts/src/v0.8/interfaces/LinkTokenInterface.sol";
import {IERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import {TelemedicineBase} from "./TelemedicineBase.sol";

contract TelemedicineOperations is Initializable, ReentrancyGuardUpgradeable, ChainlinkClient {
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
    error DeadlineMissed();
    error NoLabTechAvailable();
    error PaymentFailed();
    error OracleResponseInvalid();
    error InvalidLocality();
    error InvitationAlreadyExists();
    error ProvidersAlreadyExist();
    error PaymentNotConfirmed();
    error PaymentDeadlineMissed();
    error InvitationExpired();
    error ChainlinkRequestTimeout();

    // Contract dependencies
    TelemedicineCore public core;
    TelemedicinePayments public payments;
    TelemedicineDisputeResolution public disputeResolution;
    TelemedicineBase public base;

    // Chainlink Configuration
    mapping(bytes32 => uint256) public requestToLabTestId;
    mapping(bytes32 => uint256) public requestToPrescriptionId;
    mapping(bytes32 => uint48) public requestTimestamps;

    // State Variables
    mapping(uint256 => LabTestOrder) public labTestOrders;
    mapping(uint256 => Prescription) public prescriptions;
    mapping(uint256 => AISymptomAnalysis) public aiAnalyses;
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

    uint256 public labTestCounter;
    uint256 public prescriptionCounter;
    uint256 public aiAnalysisCounter;

    // Enums
    enum LabTestStatus { Requested, PaymentPending, Collected, ResultsUploaded, Reviewed, Disputed, Expired }
    enum PrescriptionStatus { Generated, PaymentPending, Verified, Fulfilled, Revoked, Expired, Disputed }
    enum DisputeOutcome { Unresolved, PatientFavored, ProviderFavored, MutualAgreement }

    // Structs
    struct LabTestOrder {
        uint256 id;
        address patient;
        address doctor;
        address labTech;
        LabTestStatus status;
        uint48 orderedTimestamp;
        uint48 completedTimestamp;
        string testTypeIpfsHash;
        string sampleCollectionIpfsHash;
        string resultsIpfsHash;
        uint256 patientCost;
        uint48 disputeWindowEnd;
        DisputeOutcome disputeOutcome;
        uint48 sampleCollectionDeadline;
        uint48 resultsUploadDeadline;
        TelemedicinePayments.PaymentType paymentType;
    }

    struct Prescription {
        uint256 id;
        address patient;
        address doctor;
        bytes32 verificationCodeHash;
        PrescriptionStatus status;
        address pharmacy;
        uint48 generatedTimestamp;
        uint48 expirationTimestamp;
        string medicationIpfsHash;
        string prescriptionIpfsHash;
        uint256 patientCost;
        uint48 disputeWindowEnd;
        DisputeOutcome disputeOutcome;
    }

    struct AISymptomAnalysis {
        uint256 id;
        address patient;
        bool doctorReviewed;
        string symptoms;
        string analysisIpfsHash;
    }

    // Events
    event LabTestOrdered(uint256 indexed testId, address patient, address doctor, string testTypeIpfsHash, uint48 orderedAt);
    event LabTestCollected(uint256 indexed testId, string ipfsHash);
    event LabTestUploaded(uint256 indexed testId, string ipfsHash);
    event LabTestReviewed(uint256 indexed testId);
    event LabTestReordered(uint256 indexed originalTestId, uint256 indexed newTestId, address newLabTech, address patient);
    event PrescriptionIssued(uint256 indexed prescriptionId, address patient, address doctor, bytes32 verificationCodeHash, uint48 issuedAt);
    event PrescriptionVerified(uint256 indexed prescriptionId, address pharmacy);
    event PrescriptionFulfilled(uint256 indexed prescriptionId);
    event PrescriptionRevoked(uint256 indexed prescriptionId);
    event PrescriptionExpired(uint256 indexed prescriptionId);
    event AISymptomAnalyzed(uint256 indexed id, address indexed patient);
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
    event PrescriptionDetailsSet(uint256 indexed prescriptionId, string prescriptionIpfsHash);
    event LabTestDisputeWindowStarted(uint256 indexed testId, address patient, uint48 disputeWindowEnd);
    event PrescriptionDisputeWindowStarted(uint256 indexed prescriptionId, address patient, uint48 disputeWindowEnd);
    event LabTestPaymentReleased(uint256 indexed testId, address labTech, uint256 amount, TelemedicinePayments.PaymentType paymentType);
    event PrescriptionPaymentReleased(uint256 indexed prescriptionId, address pharmacy, uint256 amount, TelemedicinePayments.PaymentType paymentType);
    event ReplacementPrescriptionOrdered(uint256 indexed originalPrescriptionId, uint256 indexed newPrescriptionId);
    event PaymentQueued(uint256 indexed paymentId, address recipient, uint256 amount, TelemedicinePayments.PaymentType paymentType);
    event PaymentReleasedFromQueue(uint256 indexed paymentId, address recipient, uint256 amount);

    function initialize(
        address _core,
        address _payments,
        address _disputeResolution,
        address _base
    ) external initializer {
        if (_core == address(0) || _payments == address(0) || _disputeResolution == address(0) || _base == address(0)) revert InvalidAddress();

        __ReentrancyGuard_init();
        core = TelemedicineCore(_core);
        payments = TelemedicinePayments(_payments);
        disputeResolution = TelemedicineDisputeResolution(_disputeResolution);
        base = TelemedicineBase(_base);

        labTestCounter = 0;
        prescriptionCounter = 0;
        aiAnalysisCounter = 0;
        invitationCounter = 0;
        pendingPaymentCounter = 0;
    }

    function confirmPayment(uint256 _id, bool _isLabTest, TelemedicinePayments.PaymentType _paymentType)
        external payable onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
        if (_isLabTest) {
            LabTestOrder storage order = labTestOrders[_id];
            if (_id == 0 || _id > labTestCounter) revert InvalidIndex();
            if (order.patient != msg.sender) revert NotAuthorized();
            if (order.status != LabTestStatus.PaymentPending) revert InvalidStatus();
            if (block.timestamp > labTestPaymentDeadlines[_id]) revert PaymentDeadlineMissed();

            if (_paymentType == TelemedicinePayments.PaymentType.ETH) {
                if (msg.value < order.patientCost) revert InsufficientFunds();
                order.paymentType = _paymentType;
                labTestPayments[_id] = true;
                order.status = LabTestStatus.Requested;
                emit LabTestPaymentConfirmed(_id, order.patientCost);
                if (msg.value > order.patientCost) {
                    uint256 refund = msg.value - order.patientCost;
                    _safeTransferETH(msg.sender, refund);
                }
            } else {
                payments._processPayment(_paymentType, order.patientCost);
                order.paymentType = _paymentType;
                labTestPayments[_id] = true;
                order.status = LabTestStatus.Requested;
                emit LabTestPaymentConfirmed(_id, order.patientCost);
            }
        } else {
            Prescription storage prescription = prescriptions[_id];
            if (_id == 0 || _id > prescriptionCounter) revert InvalidIndex();
            if (prescription.patient != msg.sender) revert NotAuthorized();
            if (prescription.status != PrescriptionStatus.PaymentPending) revert InvalidStatus();
            if (block.timestamp > prescriptionPaymentDeadlines[_id]) revert PaymentDeadlineMissed();

            if (_paymentType == TelemedicinePayments.PaymentType.ETH) {
                if (msg.value < prescription.patientCost) revert InsufficientFunds();
                prescription.paymentType = _paymentType;
                prescriptionPayments[_id] = true;
                prescription.status = PrescriptionStatus.Generated;
                emit PrescriptionPaymentConfirmed(_id, prescription.patientCost);
                if (msg.value > prescription.patientCost) {
                    uint256 refund = msg.value - prescription.patientCost;
                    _safeTransferETH(msg.sender, refund);
                }
            } else {
                payments._processPayment(_paymentType, prescription.patientCost);
                prescription.paymentType = _paymentType;
                prescriptionPayments[_id] = true;
                prescription.status = PrescriptionStatus.Generated;
                emit PrescriptionPaymentConfirmed(_id, prescription.patientCost);
            }
        }
    }

    function setPrescriptionDetails(uint256 _prescriptionId, string calldata _prescriptionIpfsHash)
        external onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
        Prescription storage prescription = prescriptions[_prescriptionId];
        if (_prescriptionId == 0 || _prescriptionId > prescriptionCounter) revert InvalidIndex();
        if (prescription.patient != msg.sender) revert NotAuthorized();
        if (prescription.status != PrescriptionStatus.Generated) revert InvalidStatus();
        if (!prescriptionPayments[_prescriptionId]) revert PaymentNotConfirmed();
        if (bytes(_prescriptionIpfsHash).length == 0) revert InvalidIpfsHash();
        if (bytes(prescription.prescriptionIpfsHash).length != 0) revert InvalidStatus();

        prescription.prescriptionIpfsHash = _prescriptionIpfsHash;
        emit PrescriptionDetailsSet(_prescriptionId, _prescriptionIpfsHash);
    }

    function checkPrescriptionDeadlines(uint256 _prescriptionId) external nonReentrant whenNotPaused {
        Prescription storage prescription = prescriptions[_prescriptionId];
        if (_prescriptionId == 0 || _prescriptionId > prescriptionCounter) revert InvalidIndex();
        if (prescription.status == PrescriptionStatus.Fulfilled ||
            prescription.status == PrescriptionStatus.Revoked ||
            prescription.status == PrescriptionStatus.Expired ||
            prescription.status == PrescriptionStatus.Disputed) return;

        if (prescription.status == PrescriptionStatus.PaymentPending &&
            block.timestamp > prescriptionPaymentDeadlines[_prescriptionId]) {
            prescription.status = PrescriptionStatus.Expired;
            emit PrescriptionExpired(_prescriptionId);
        } else if ((prescription.status == PrescriptionStatus.Generated || prescription.status == PrescriptionStatus.Verified) &&
                   block.timestamp > prescription.expirationTimestamp) {
            prescription.status = PrescriptionStatus.Expired;
            emit PrescriptionExpired(_prescriptionId);
        }
    }

    function inviteProvider(string calldata _locality, string calldata _inviteeContact, bool _isLabTech)
        external onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
        if (bytes(_locality).length == 0 || bytes(_inviteeContact).length == 0) revert InvalidLocality();

        bool hasProvider = _isLabTech ?
            hasLabTechInLocality(_locality) :
            hasPharmacyInLocality(_locality);
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
        internal returns (bytes32) {
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
        if (labTestId == 0 || labTestId > labTestCounter) revert InvalidIndex();
        LabTestOrder storage order = labTestOrders[labTestId];
        if (order.status != LabTestStatus.Requested) revert InvalidStatus();
        if (_price == 0) revert OracleResponseInvalid();

        order.patientCost = _price * 120 / base.PERCENTAGE_DENOMINATOR();
        order.status = LabTestStatus.PaymentPending;
        labTestPaymentDeadlines[labTestId] = uint48(block.timestamp) + base.paymentConfirmationDeadline();
        delete requestToLabTestId[_requestId];
        delete requestTimestamps[_requestId];
        emit LabTestPaymentPending(labTestId, order.patientCost, labTestPaymentDeadlines[labTestId]);
    }

    function requestPrescriptionPrice(address _pharmacy, string calldata _medicationIpfsHash, uint256 _prescriptionId)
        internal returns (bytes32) {
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
        if (prescriptionId == 0 || prescriptionId > prescriptionCounter) revert InvalidIndex();
        Prescription storage prescription = prescriptions[prescriptionId];
        if (prescription.status != PrescriptionStatus.Generated) revert InvalidStatus();
        if (_price == 0) revert OracleResponseInvalid();

        prescription.patientCost = _price * 120 / base.PERCENTAGE_DENOMINATOR();
        prescription.status = PrescriptionStatus.PaymentPending;
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

    function orderLabTest(address _patient, string calldata _testTypeIpfsHash, string calldata _locality)
        external payable onlyRole(core.DOCTOR_ROLE()) nonReentrant whenNotPaused {
        if (_patient == address(0)) revert InvalidAddress();
        if (!core.patients(_patient).isRegistered) revert NotAuthorized();
        if (bytes(_testTypeIpfsHash).length == 0 || bytes(_locality).length == 0) revert InvalidIpfsHash();

        address selectedLabTech = selectBestLabTech(_testTypeIpfsHash, _locality);
        if (selectedLabTech == address(0)) revert NoLabTechAvailable();

        (uint256 price, bool isValid, uint48 sampleDeadline, uint48 resultsDeadline) = getLabTestDetails(selectedLabTech, _testTypeIpfsHash);
        labTestCounter = labTestCounter + 1;
        uint256 newTestId = labTestCounter;

        LabTestOrder storage order = labTestOrders[newTestId];
        order.id = newTestId;
        order.patient = _patient;
        order.doctor = msg.sender;
        order.labTech = selectedLabTech;
        order.status = LabTestStatus.Requested;
        order.orderedTimestamp = uint48(block.timestamp);
        order.testTypeIpfsHash = _testTypeIpfsHash;
        order.sampleCollectionDeadline = sampleDeadline;
        order.resultsUploadDeadline = resultsDeadline;
        order.paymentType = TelemedicinePayments.PaymentType.ETH;

        if (!isValid || price == 0) {
            requestLabTestPrice(selectedLabTech, _testTypeIpfsHash, newTestId);
        } else {
            order.patientCost = price * 120 / base.PERCENTAGE_DENOMINATOR();
            if (msg.value < order.patientCost) revert InsufficientFunds();
            labTestPayments[newTestId] = true;
            emit LabTestPaymentConfirmed(newTestId, order.patientCost);
            if (msg.value > order.patientCost) {
                uint256 refund = msg.value - order.patientCost;
                _safeTransferETH(msg.sender, refund);
            }
        }

        emit LabTestOrdered(newTestId, _patient, msg.sender, _testTypeIpfsHash, uint48(block.timestamp));
        monetizeData(_patient);
    }

    function collectSample(uint256 _labTestId, string calldata _ipfsHash)
        external onlyRole(core.LAB_TECH_ROLE()) nonReentrant whenNotPaused {
        LabTestOrder storage order = labTestOrders[_labTestId];
        if (order.status != LabTestStatus.Requested) revert InvalidStatus();
        if (order.labTech != msg.sender) revert NotAuthorized();
        if (_labTestId == 0 || _labTestId > labTestCounter) revert InvalidIndex();
        if (bytes(_ipfsHash).length == 0) revert InvalidIpfsHash();
        if (block.timestamp > order.orderedTimestamp + order.sampleCollectionDeadline) revert DeadlineMissed();
        if (!labTestPayments[_labTestId]) revert PaymentNotConfirmed();

        order.sampleCollectionIpfsHash = _ipfsHash;
        order.status = LabTestStatus.Collected;
        emit LabTestCollected(_labTestId, _ipfsHash);
    }

    function uploadLabResults(uint256 _labTestId, string calldata _resultsIpfsHash)
        external onlyRole(core.LAB_TECH_ROLE()) nonReentrant whenNotPaused {
        LabTestOrder storage order = labTestOrders[_labTestId];
        if (order.labTech != msg.sender) revert NotAuthorized();
        if (order.status != LabTestStatus.Collected) revert InvalidStatus();
        if (_labTestId == 0 || _labTestId > labTestCounter) revert InvalidIndex();
        if (bytes(_resultsIpfsHash).length == 0) revert InvalidIpfsHash();
        if (block.timestamp > order.orderedTimestamp + order.resultsUploadDeadline) revert DeadlineMissed();
        if (!labTestPayments[_labTestId]) revert PaymentNotConfirmed();

        order.resultsIpfsHash = _resultsIpfsHash;
        order.status = LabTestStatus.ResultsUploaded;
        order.disputeWindowEnd = uint48(block.timestamp) + base.disputeWindow();
        emit LabTestUploaded(_labTestId, _resultsIpfsHash);
        emit LabTestDisputeWindowStarted(_labTestId, order.patient, order.disputeWindowEnd);
        monetizeData(order.patient);
    }

    function releaseLabTestPayment(uint256 _labTestId) external nonReentrant whenNotPaused {
        LabTestOrder storage order = labTestOrders[_labTestId];
        if (_labTestId == 0 || _labTestId > labTestCounter) revert InvalidIndex();
        if (order.status != LabTestStatus.ResultsUploaded && order.status != LabTestStatus.Reviewed && order.status != LabTestStatus.Disputed) revert InvalidStatus();
        if (block.timestamp <= order.disputeWindowEnd) revert InvalidTimestamp();
        if (!labTestPayments[_labTestId]) revert PaymentNotConfirmed();

        bool isDisputed = disputeResolution.isDisputed(_labTestId);
        if (isDisputed) {
            DisputeOutcome outcome = disputeResolution.getDisputeOutcome(_labTestId);
            if (outcome == DisputeOutcome.Unresolved) revert InvalidStatus();

            if (outcome == DisputeOutcome.PatientFavored) {
                payments._refundPatient(order.patient, order.patientCost, order.paymentType);
                emit LabTestRefunded(_labTestId, order.patient, order.patientCost);
            } else if (outcome == DisputeOutcome.ProviderFavored || outcome == DisputeOutcome.MutualAgreement) {
                _releasePayment(order.labTech, order.patientCost, order.paymentType);
                emit LabTestPaymentReleased(_labTestId, order.labTech, order.patientCost, order.paymentType);
            }
            order.status = LabTestStatus.Disputed;
            notifyDisputeResolved(_labTestId, "LabTest", outcome);
        } else {
            _releasePayment(order.labTech, order.patientCost, order.paymentType);
            emit LabTestPaymentReleased(_labTestId, order.labTech, order.patientCost, order.paymentType);
        }

        labTestPayments[_labTestId] = false;
    }

    function checkLabTestDeadlines(uint256 _labTestId) external nonReentrant whenNotPaused {
        LabTestOrder storage order = labTestOrders[_labTestId];
        if (_labTestId == 0 || _labTestId > labTestCounter) revert InvalidIndex();
        if (order.status == LabTestStatus.Reviewed || order.status == LabTestStatus.Disputed || order.status == LabTestStatus.Expired) return;

        bool missedDeadline = false;
        if (order.status == LabTestStatus.Requested && block.timestamp > order.orderedTimestamp + order.sampleCollectionDeadline) {
            missedDeadline = true;
        } else if (order.status == LabTestStatus.Collected && block.timestamp > order.orderedTimestamp + order.resultsUploadDeadline) {
            missedDeadline = true;
        } else if (order.status == LabTestStatus.PaymentPending && block.timestamp > labTestPaymentDeadlines[_labTestId]) {
            missedDeadline = true;
        }

        if (missedDeadline) {
            string memory locality = getLabTechLocality(order.labTech);
            address newLabTech = selectBestLabTech(order.testTypeIpfsHash, locality);
            if (newLabTech == order.labTech || newLabTech == address(0)) revert NoLabTechAvailable();

            (uint256 price, bool isValid, uint48 sampleDeadline, uint48 resultsDeadline) = getLabTestDetails(newLabTech, order.testTypeIpfsHash);
            if (!isValid) revert InvalidStatus();

            if (order.patientCost > 0 && labTestPayments[_labTestId]) {
                payments._refundPatient(order.patient, order.patientCost, order.paymentType);
                emit LabTestRefunded(_labTestId, order.patient, order.patientCost);
            }

            order.status = LabTestStatus.Expired;
            labTestCounter = labTestCounter + 1;
            uint256 newTestId = labTestCounter;
            uint256 patientCost = price * 120 / base.PERCENTAGE_DENOMINATOR();

            labTestOrders[newTestId] = LabTestOrder({
                id: newTestId,
                patient: order.patient,
                doctor: order.doctor,
                labTech: newLabTech,
                status: LabTestStatus.Requested,
                orderedTimestamp: uint48(block.timestamp),
                completedTimestamp: 0,
                testTypeIpfsHash: order.testTypeIpfsHash,
                sampleCollectionIpfsHash: "",
                resultsIpfsHash: "",
                patientCost: patientCost,
                disputeWindowEnd: 0,
                disputeOutcome: DisputeOutcome.Unresolved,
                sampleCollectionDeadline: sampleDeadline,
                resultsUploadDeadline: resultsDeadline,
                paymentType: order.paymentType
            });

            if (!isValid || price == 0) {
                requestLabTestPrice(newLabTech, order.testTypeIpfsHash, newTestId);
            } else {
                labTestPayments[newTestId] = true;
                emit LabTestPaymentConfirmed(newTestId, patientCost);
            }

            emit LabTestOrdered(newTestId, order.patient, order.doctor, order.testTypeIpfsHash, uint48(block.timestamp));
            emit LabTestReordered(_labTestId, newTestId, newLabTech, order.patient);
            monetizeData(order.patient);
        }
    }

    function reviewLabResults(uint256 _labTestId, string calldata _medicationIpfsHash, string calldata _prescriptionIpfsHash, address _pharmacy, string calldata _locality)
        external payable onlyRole(core.DOCTOR_ROLE()) nonReentrant whenNotPaused {
        LabTestOrder storage order = labTestOrders[_labTestId];
        if (order.doctor != msg.sender) revert NotAuthorized();
        if (order.status != LabTestStatus.ResultsUploaded) revert InvalidStatus();
        if (_labTestId == 0 || _labTestId > labTestCounter) revert InvalidIndex();
        if (_pharmacy == address(0)) revert InvalidAddress();
        if (!isPharmacyRegistered(_pharmacy) && !hasPharmacyInLocality(_locality)) revert NotAuthorized();
        if (bytes(_medicationIpfsHash).length == 0 || bytes(_prescriptionIpfsHash).length == 0 || bytes(_locality).length == 0) revert InvalidIpfsHash();

        (uint256 price, bool isValid) = getPharmacyPrice(_pharmacy, _medicationIpfsHash);
        order.status = LabTestStatus.Reviewed;
        order.completedTimestamp = uint48(block.timestamp);

        prescriptionCounter = prescriptionCounter + 1;
        uint256 newPrescriptionId = prescriptionCounter;
        bytes32 verificationCodeHash = keccak256(abi.encodePacked(newPrescriptionId, msg.sender, block.timestamp));

        Prescription storage prescription = prescriptions[newPrescriptionId];
        prescription.id = newPrescriptionId;
        prescription.patient = order.patient;
        prescription.doctor = msg.sender;
        prescription.verificationCodeHash = verificationCodeHash;
        prescription.status = PrescriptionStatus.Generated;
        prescription.pharmacy = _pharmacy;
        prescription.generatedTimestamp = uint48(block.timestamp);
        prescription.expirationTimestamp = uint48(block.timestamp + 30 days);
        prescription.medicationIpfsHash = _medicationIpfsHash;

        if (!isValid || price == 0) {
            requestPrescriptionPrice(_pharmacy, _medicationIpfsHash, newPrescriptionId);
        } else {
            prescription.patientCost = price * 120 / base.PERCENTAGE_DENOMINATOR();
            if (msg.value < prescription.patientCost) revert InsufficientFunds();
            prescription.prescriptionIpfsHash = _prescriptionIpfsHash;
            prescriptionPayments[newPrescriptionId] = true;
            emit PrescriptionPaymentConfirmed(newPrescriptionId, prescription.patientCost);
            if (msg.value > prescription.patientCost) {
                uint256 refund = msg.value - prescription.patientCost;
                _safeTransferETH(msg.sender, refund);
            }
        }

        emit PrescriptionIssued(newPrescriptionId, order.patient, msg.sender, verificationCodeHash, uint48(block.timestamp));
        monetizeData(order.patient);
    }

    function verifyPrescription(uint256 _prescriptionId, bytes32 _verificationCodeHash)
        external onlyRole(core.PHARMACY_ROLE()) nonReentrant whenNotPaused {
        Prescription storage prescription = prescriptions[_prescriptionId];
        if (prescription.pharmacy != msg.sender) revert NotAuthorized();
        if (prescription.status != PrescriptionStatus.Generated) revert InvalidStatus();
        if (prescription.verificationCodeHash != _verificationCodeHash) revert NotAuthorized();
        if (block.timestamp > prescription.expirationTimestamp) revert InvalidTimestamp();
        if (_prescriptionId == 0 || _prescriptionId > prescriptionCounter) revert InvalidIndex();
        if (!prescriptionPayments[_prescriptionId]) revert PaymentNotConfirmed();
        if (bytes(prescription.prescriptionIpfsHash).length == 0) revert InvalidIpfsHash();

        prescription.status = PrescriptionStatus.Verified;
        emit PrescriptionVerified(_prescriptionId, msg.sender);
    }

    function fulfillPrescription(uint256 _prescriptionId)
        external onlyRole(core.PHARMACY_ROLE()) nonReentrant whenNotPaused {
        Prescription storage prescription = prescriptions[_prescriptionId];
        if (prescription.pharmacy != msg.sender) revert NotAuthorized();
        if (prescription.status != PrescriptionStatus.Verified) revert InvalidStatus();
        if (block.timestamp > prescription.expirationTimestamp) revert InvalidTimestamp();
        if (_prescriptionId == 0 || _prescriptionId > prescriptionCounter) revert InvalidIndex();
        if (!prescriptionPayments[_prescriptionId]) revert PaymentNotConfirmed();

        prescription.status = PrescriptionStatus.Fulfilled;
        prescription.disputeWindowEnd = uint48(block.timestamp) + base.disputeWindow();
        emit PrescriptionFulfilled(_prescriptionId);
        emit PrescriptionDisputeWindowStarted(_prescriptionId, prescription.patient, prescription.disputeWindowEnd);
    }

    function releasePrescriptionPayment(uint256 _prescriptionId) external nonReentrant whenNotPaused {
        Prescription storage prescription = prescriptions[_prescriptionId];
        if (_prescriptionId == 0 || _prescriptionId > prescriptionCounter) revert InvalidIndex();
        if (prescription.status != PrescriptionStatus.Fulfilled && prescription.status != PrescriptionStatus.Disputed) revert InvalidStatus();
        if (block.timestamp <= prescription.disputeWindowEnd) revert InvalidTimestamp();
        if (!prescriptionPayments[_prescriptionId]) revert PaymentNotConfirmed();

        bool isDisputed = disputeResolution.isDisputed(_prescriptionId);
        if (isDisputed) {
            DisputeOutcome outcome = disputeResolution.getDisputeOutcome(_prescriptionId);
            if (outcome == DisputeOutcome.Unresolved) revert InvalidStatus();

            if (outcome == DisputeOutcome.PatientFavored) {
                payments._refundPatient(prescription.patient, prescription.patientCost, prescription.paymentType);
                emit PrescriptionRefunded(_prescriptionId, prescription.patient, prescription.patientCost);
            } else if (outcome == DisputeOutcome.ProviderFavored || outcome == DisputeOutcome.MutualAgreement) {
                _releasePayment(prescription.pharmacy, prescription.patientCost, prescription.paymentType);
                emit PrescriptionPaymentReleased(_prescriptionId, prescription.pharmacy, prescription.patientCost, prescription.paymentType);
            }
            prescription.status = PrescriptionStatus.Disputed;
            notifyDisputeResolved(_prescriptionId, "Prescription", outcome);
        } else {
            _releasePayment(prescription.pharmacy, prescription.patientCost, prescription.paymentType);
            emit PrescriptionPaymentReleased(_prescriptionId, prescription.pharmacy, prescription.patientCost, prescription.paymentType);
        }

        prescriptionPayments[_prescriptionId] = false;
    }

    function orderReplacementPrescription(uint256 _originalPrescriptionId, bytes32 _operationHash)
        external onlyDisputeResolution nonReentrant whenNotPaused onlyMultiSig(_operationHash) {
        bytes32 expectedHash = keccak256(abi.encodePacked(
            "orderReplacementPrescription",
            _originalPrescriptionId,
            msg.sender,
            block.timestamp,
            base.nonces(msg.sender)++
        ));
        if (_operationHash != expectedHash) revert MultiSigNotApproved();

        Prescription storage original = prescriptions[_originalPrescriptionId];
        if (original.status != PrescriptionStatus.Fulfilled) revert InvalidStatus();
        if (original.pharmacy == address(0)) revert InvalidAddress();
        if (_originalPrescriptionId == 0 || _originalPrescriptionId > prescriptionCounter) revert InvalidIndex();

        prescriptionCounter = prescriptionCounter + 1;
        uint256 newPrescriptionId = prescriptionCounter;
        bytes32 newVerificationCodeHash = keccak256(abi.encodePacked(newPrescriptionId, original.doctor, block.timestamp));
        prescriptions[newPrescriptionId] = Prescription({
            id: newPrescriptionId,
            patient: original.patient,
            doctor: original.doctor,
            verificationCodeHash: newVerificationCodeHash,
            status: PrescriptionStatus.Generated,
            pharmacy: original.pharmacy,
            generatedTimestamp: uint48(block.timestamp),
            expirationTimestamp: uint48(block.timestamp + 30 days),
            medicationIpfsHash: original.medicationIpfsHash,
            prescriptionIpfsHash: original.prescriptionIpfsHash,
            patientCost: original.patientCost,
            disputeWindowEnd: 0,
            disputeOutcome: DisputeOutcome.Unresolved
        });
        prescriptionPayments[newPrescriptionId] = true;

        emit PrescriptionIssued(newPrescriptionId, original.patient, original.doctor, newVerificationCodeHash, uint48(block.timestamp));
        emit ReplacementPrescriptionOrdered(_originalPrescriptionId, newPrescriptionId);
    }

    function requestAISymptomAnalysis(string calldata _symptoms)
        external onlyRole(core.PATIENT_ROLE()) nonReentrant whenNotPaused {
        if (bytes(_symptoms).length == 0) revert InvalidIpfsHash();
        core.decayPoints(msg.sender);
        TelemedicineCore.Patient storage patient = core.patients(msg.sender);
        bool isFree = patient.gamification.currentLevel == core.maxLevel() &&
                      block.timestamp >= patient.lastFreeAnalysisTimestamp + core.freeAnalysisPeriod();

        aiAnalysisCounter = aiAnalysisCounter + 1;
        aiAnalyses[aiAnalysisCounter] = AISymptomAnalysis(aiAnalysisCounter, msg.sender, false, _symptoms, "");
        patient.gamification.mediPoints = uint96(patient.gamification.mediPoints + core.pointsForActions("aiAnalysis"));
        patient.lastActivityTimestamp = uint48(block.timestamp);

        if (!isFree) {
            if (core.getAIFundBalance() < core.aiAnalysisCost()) revert InsufficientFunds();
            core.aiAnalysisFund = core.aiAnalysisFund - core.aiAnalysisCost();
        } else {
            patient.lastFreeAnalysisTimestamp = uint48(block.timestamp);
            notifyDataRewardClaimed(msg.sender, 0);
        }

        core._levelUp(msg.sender);
        emit AISymptomAnalyzed(aiAnalysisCounter, msg.sender);
        monetizeData(msg.sender);
    }

    function reviewAISymptomAnalysis(uint256 _aiAnalysisId, string calldata _analysisIpfsHash)
        external onlyRole(core.DOCTOR_ROLE()) nonReentrant whenNotPaused {
        AISymptomAnalysis storage analysis = aiAnalyses[_aiAnalysisId];
        if (analysis.doctorReviewed) revert InvalidStatus();
        if (_aiAnalysisId == 0 || _aiAnalysisId > aiAnalysisCounter) revert InvalidIndex();
        if (bytes(_analysisIpfsHash).length == 0) revert InvalidIpfsHash();

        analysis.analysisIpfsHash = _analysisIpfsHash;
        analysis.doctorReviewed = true;
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
        if (_labTestId == 0 || _labTestId > labTestCounter) revert InvalidIndex();
        LabTestOrder storage order = labTestOrders[_labTestId];
        if (order.status != LabTestStatus.Requested) revert InvalidStatus();
        if (_price == 0) revert InsufficientFunds();

        order.patientCost = _price * 120 / base.PERCENTAGE_DENOMINATOR();
        order.status = LabTestStatus.PaymentPending;
        labTestPaymentDeadlines[_labTestId] = uint48(block.timestamp) + base.paymentConfirmationDeadline();
        emit LabTestPaymentPending(_labTestId, order.patientCost, labTestPaymentDeadlines[_labTestId]);
    }

    function setManualPrescriptionPrice(uint256 _prescriptionId, uint256 _price) external onlyRole(core.ADMIN_ROLE()) {
        if (!base.manualPriceOverride()) revert NotAuthorized();
        if (_prescriptionId == 0 || _prescriptionId > prescriptionCounter) revert InvalidIndex();
        Prescription storage prescription = prescriptions[_prescriptionId];
        if (prescription.status != PrescriptionStatus.Generated) revert InvalidStatus();
        if (_price == 0) revert InsufficientFunds();

        prescription.patientCost = _price * 120 / base.PERCENTAGE_DENOMINATOR();
        prescription.status = PrescriptionStatus.PaymentPending;
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

    function selectBestLabTech(string memory _testTypeIpfsHash, string memory _locality) internal view returns (address) {
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
            _safeTransferETH(_to, _amount);
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

    function _safeTransferETH(address _to, uint256 _amount) internal {
        (bool success, ) = _to.call{value: _amount}("");
        if (!success) revert PaymentFailed();
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

    // Placeholder functions (to be implemented or imported from TelemedicineMedicalServices)
    function hasLabTechInLocality(string memory _locality) public view returns (bool) { return false; }
    function hasPharmacyInLocality(string memory _locality) public view returns (bool) { return false; }
    function registerLabTech(address _labTech, string memory _locality) public {}
    function registerPharmacy(address _pharmacy, string memory _locality) public {}
    function getLabTestDetails(address _labTech, string memory _testTypeIpfsHash) public view returns (uint256, bool, uint48, uint48) { return (0, false, 0, 0); }
    function getPharmacyPrice(address _pharmacy, string memory _medicationIpfsHash) public view returns (uint256, bool) { return (0, false); }
    function isPharmacyRegistered(address _pharmacy) public view returns (bool) { return false; }
    function monetizeData(address _patient) public {}
    function notifyDisputeResolved(uint256 _id, string memory _entityType, DisputeOutcome _outcome) public {}
    function notifyDataRewardClaimed(address _patient, uint256 _amount) public {}
    function getLabTechsInLocality(string memory _locality, uint256 _startIndex, uint256 _pageSize) public view returns (address[] memory, uint256) { return (new address[](0), 0); }
    function isLabTechRegistered(address _labTech) public view returns (bool) { return false; }
    function getLabTechCapacity(address _labTech) public view returns (uint256) { return 0; }
    function getLabTechRating(address _labTech) public view returns (uint256, uint256) { return (0, 0); }
    function getLabTechLocality(address _labTech) public view returns (string memory) { return ""; }
    function checkMultiSigApproval(bytes32 _operationHash) public view returns (bool) { return true; }

    modifier onlyRole(bytes32 role) {
        if (!core.hasRole(role, msg.sender)) revert NotAuthorized();
        _;
    }

    modifier onlyDisputeResolution() {
        if (msg.sender != address(disputeResolution)) revert NotAuthorized();
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
