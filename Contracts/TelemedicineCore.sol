// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
import {Initializable} from "@openzeppelin
/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin
/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin
/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin
/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin
/contracts-upgradeable/security/PausableUpgradeable.sol";
import {SafeMathUpgradeable} from "@openzeppelin
/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";
import {AddressUpgradeable} from "@openzeppelin
/contracts-upgradeable/utils/AddressUpgradeable.sol";
import {IERC20Upgradeable} from "@openzeppelin
/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
contract TelemedicineCore is Initializable, UUPSUpgradeable, AccessControlUpgradeable, ReentrancyGuardUpgradeable, PausableUpgradeable {
    using SafeMathUpgradeable for uint256;
    using AddressUpgradeable for address payable;

bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
bytes32 public constant DOCTOR_ROLE = keccak256("DOCTOR_ROLE");
bytes32 public constant PATIENT_ROLE = keccak256("PATIENT_ROLE");
bytes32 public constant LAB_TECH_ROLE = keccak256("LAB_TECH_ROLE");
bytes32 public constant PHARMACY_ROLE = keccak256("PHARMACY_ROLE");

// Configuration Variables
uint256 public minBookingBuffer;
uint256 public minCancellationBuffer;
uint256 public verificationTimeout;
uint256 public dataMonetizationReward;
uint256 public aiAnalysisCost;
uint256 public pointsPerLevel;
uint8 public maxLevel;
uint256 public decayRate;
uint256 public decayPeriod;
uint256 public freeAnalysisPeriod;
uint256 public minReserveBalance;
uint256 public versionNumber;

// Constants
uint256 public constant MAX_ADMINS = 10;
uint256 public constant MAX_PENDING_APPOINTMENTS = 100;
uint256 public constant MAX_BATCH_SIZE = 50;
uint256 public constant RESERVE_FUND_THRESHOLD = 1 ether;

// State Variables
mapping(address => Patient) public patients;
mapping(address => Doctor) public doctors;
mapping(address => LabTechnician) public labTechnicians;
mapping(address => Pharmacy) public pharmacies;
mapping(uint8 => uint256) public discountLevels;
mapping(string => uint256) public pointsForActions;
address[] public admins;
uint256 public aiAnalysisFund;
uint256 public reserveFund;

// Structs
struct Patient {
    bool isRegistered;
    bytes32 medicalHistoryHash;
    GamificationData gamification;
    DataSharingStatus dataSharing;
    uint48 GalileeTimestamp;
    uint48 lastActivityTimestamp;
    uint48 lastFreeAnalysisTimestamp;
    string encryptedSymmetricKey;
}

struct GamificationData {
    uint96 mediPoints;
    uint8 currentLevel;
}

struct Doctor {
    bool isVerified;
    uint96 consultationFee;
    string licenseNumber;
}

struct LabTechnician {
    bool isVerified;
    string licenseNumber;
}

struct Pharmacy {
    bool isRegistered;
    string licenseNumber;
}

// Enums
enum DataSharingStatus { Disabled, Enabled }

// Events
event PatientRegistered(address indexed patient);
event DoctorVerified(address indexed doctor);
event LabTechnicianVerified(address indexed labTech);
event PharmacyRegistered(address indexed pharmacy);
event DataMonetizationOptIn(address indexed patient, bool enabled);
event LevelUp(address indexed patient, uint8 newLevel);
event PointsDecayed(address indexed patient, uint256 decayedPoints);
event FreeAnalysisClaimed(address indexed patient);
event AIFundDeposited(address indexed sender, uint256 amount);
event ReserveFundDeposited(address indexed sender, uint256 amount);
event MinBalanceAlert(address indexed contractAddress, uint256 balance);
event AuditLog(uint256 indexed timestamp, address indexed actor, string action);

/// @custom:oz-upgrades-unsafe-allow constructor
constructor() {
    _disableInitializers();
}

function initialize(
    address[] memory _initialAdmins
) external initializer {
    require(_initialAdmins.length >= 2 && _initialAdmins.length <= MAX_ADMINS, "Invalid initial admin count");

    __UUPSUpgradeable_init();
    __AccessControl_init();
    __ReentrancyGuard_init();
    __Pausable_init();

    _setRoleAdmin(ADMIN_ROLE, ADMIN_ROLE);
    _setRoleAdmin(DOCTOR_ROLE, ADMIN_ROLE);
    _setRoleAdmin(PATIENT_ROLE, ADMIN_ROLE);
    _setRoleAdmin(LAB_TECH_ROLE, ADMIN_ROLE);
    _setRoleAdmin(PHARMACY_ROLE, ADMIN_ROLE);

    for (uint256 i = 0; i < _initialAdmins.length; i++) {
        require(_initialAdmins[i] != address(0), "Admin address cannot be zero");
        _grantRole(ADMIN_ROLE, _initialAdmins[i]);
        admins.push(_initialAdmins[i]);
    }

    minBookingBuffer = 15 minutes;
    minCancellationBuffer = 1 hours;
    verificationTimeout = 7 days;
    dataMonetizationReward = 10 * 10**18;
    aiAnalysisCost = 0.01 ether;
    pointsPerLevel = 100;
    maxLevel = 10;
    decayRate = 10;
    decayPeriod = 30 days;
    freeAnalysisPeriod = 30 days;
    minReserveBalance = RESERVE_FUND_THRESHOLD;
    versionNumber = 1;

    discountLevels[3] = 5;
    discountLevels[5] = 10;
    pointsForActions["appointment"] = 20;
    pointsForActions["aiAnalysis"] = 10;

    emit AuditLog(block.timestamp, msg.sender, "Contract Initialized");
}

function _authorizeUpgrade(address newImplementation) internal override onlyRole(ADMIN_ROLE) {
    versionNumber = versionNumber.add(1);
}

// Patient Functions
function registerPatient(string calldata _encryptedSymmetricKey) external whenNotPaused {
    require(!patients[msg.sender].isRegistered, "Patient already registered");
    patients[msg.sender] = Patient(
        true,
        bytes32(0),
        GamificationData(0, 1),
        DataSharingStatus.Disabled,
        uint48(block.timestamp),
        uint48(block.timestamp),
        0,
        _encryptedSymmetricKey
    );
    _grantRole(PATIENT_ROLE, msg.sender);
    emit PatientRegistered(msg.sender);
}

function toggleDataMonetization(bool _enable) external onlyRole(PATIENT_ROLE) whenNotPaused {
    Patient storage patient = patients[msg.sender];
    require(patient.isRegistered, "Patient not registered");
    patient.dataSharing = _enable ? DataSharingStatus.Enabled : DataSharingStatus.Disabled;
    emit DataMonetizationOptIn(msg.sender, _enable);
}

// Admin Functions
function verifyDoctor(address _doctor, string calldata _licenseNumber, uint256 _fee) external onlyRole(ADMIN_ROLE) {
    require(_doctor != address(0), "Doctor address cannot be zero");
    require(_fee <= type(uint96).max, "Fee exceeds uint96 maximum");
    doctors[_doctor] = Doctor(true, uint96(_fee), _licenseNumber);
    _grantRole(DOCTOR_ROLE, _doctor);
    emit DoctorVerified(_doctor);
}

function verifyLabTechnician(address _labTech, string calldata _licenseNumber) external onlyRole(ADMIN_ROLE) {
    require(_labTech != address(0), "Lab tech address cannot be zero");
    labTechnicians[_labTech] = LabTechnician(true, _licenseNumber);
    _grantRole(LAB_TECH_ROLE, _labTech);
    emit LabTechnicianVerified(_labTech);
}

function registerPharmacy(address _pharmacy, string calldata _licenseNumber) external onlyRole(ADMIN_ROLE) {
    require(_pharmacy != address(0), "Pharmacy address cannot be zero");
    pharmacies[_pharmacy] = Pharmacy(true, _licenseNumber);
    _grantRole(PHARMACY_ROLE, _pharmacy);
    emit PharmacyRegistered(_pharmacy);
}

function depositAIFund() external payable onlyRole(ADMIN_ROLE) {
    aiAnalysisFund = aiAnalysisFund.add(msg.value);
    emit AIFundDeposited(msg.sender, msg.value);
}

function depositReserveFund() external payable onlyRole(ADMIN_ROLE) {
    reserveFund = reserveFund.add(msg.value);
    emit ReserveFundDeposited(msg.sender, msg.value);
    _checkMinBalance();
}

// Internal Functions
function _applyFeeDiscount(address _patient, uint256 _baseFee) internal view returns (uint256) {
    uint8 level = patients[_patient].gamification.currentLevel;
    uint256 discountPercentage = discountLevels[level];
    if (discountPercentage == 0) return _baseFee;
    uint256 discount = _baseFee.mul(discountPercentage).div(100);
    return _baseFee.sub(discount);
}

function _isPriorityBooking(address _patient) internal view returns (bool) {
    return patients[_patient].gamification.currentLevel >= 5;
}

function _levelUp(address _patient) internal {
    Patient storage patient = patients[_patient];
    GamificationData storage gamification = patient.gamification;
    uint256 pointsNeeded = uint256(gamification.currentLevel + 1).mul(pointsPerLevel);
    if (gamification.mediPoints >= pointsNeeded && gamification.currentLevel < maxLevel) {
        gamification.currentLevel = gamification.currentLevel + 1;
        emit LevelUp(_patient, gamification.currentLevel);
    }
}

function decayPoints(address _patient) internal {
    Patient storage patient = patients[_patient];
    if (!patient.isRegistered) return;

    uint256 timeElapsed = block.timestamp.sub(patient.lastActivityTimestamp);
    if (timeElapsed >= decayPeriod && patient.gamification.mediPoints > 0) {
        uint256 periods = timeElapsed.div(decayPeriod);
        uint256 decayedPoints = patient.gamification.mediPoints.mul(decayRate).mul(periods).div(100);
        patient.gamification.mediPoints = uint96(patient.gamification.mediPoints.sub(decayedPoints > patient.gamification.mediPoints ? patient.gamification.mediPoints : decayedPoints));
        emit PointsDecayed(_patient, decayedPoints);
        patient.lastActivityTimestamp = uint48(block.timestamp);
    }
}

function _checkMinBalance() internal {
    if (address(this).balance < minReserveBalance) {
        emit MinBalanceAlert(address(this), address(this).balance);
    }
}

// Getters
function getPatientLevel(address _patient) external view returns (uint8) {
    return patients[_patient].gamification.currentLevel;
}

function getPatientPoints(address _patient) external view returns (uint256) {
    return patients[_patient].gamification.mediPoints;
}

function getDoctorFee(address _doctor) external view returns (uint256) {
    return doctors[_doctor].consultationFee;
}

function getContractBalance() external view returns (uint256) {
    return address(this).balance;
}

function getAIFundBalance() external view returns (uint256) {
    return aiAnalysisFund;
}

function getReserveFundBalance() external view returns (uint256) {
    return reserveFund;
}

receive() external payable {
    emit ReserveFundDeposited(msg.sender, msg.value);
    reserveFund = reserveFund.add(msg.value);
    _checkMinBalance();
}

}

