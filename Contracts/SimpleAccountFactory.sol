// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
import {Initializable} from "@openzeppelin
/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin
/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {SafeMathUpgradeable} from "@openzeppelin
/contracts-upgradeable/utils/math/SafeMathUpgradeable.sol";
import {ERC1967Proxy} from "@openzeppelin
/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {SimpleAccount} from "@account
-abstraction/contracts/samples/SimpleAccount.sol";
import {IEntryPoint} from "@account
-abstraction/contracts/interfaces/IEntryPoint.sol";
import {TelemedicineCore} from "./TelemedicineCore.sol";
contract SimpleAccountFactory is Initializable, ReentrancyGuardUpgradeable {
    using SafeMathUpgradeable for uint256;

SimpleAccount public immutable accountImplementation;
TelemedicineCore public core;
IEntryPoint public entryPoint;

event AccountCreated(address indexed owner, address indexed account, uint256 salt);

/// @custom:oz-upgrades-unsafe-allow constructor
constructor() {
    _disableInitializers();
    accountImplementation = new SimpleAccount(IEntryPoint(address(0))); // Temporary instantiation, updated in initialize
}

function initialize(address _core, address _entryPoint) external initializer {
    __ReentrancyGuard_init();
    core = TelemedicineCore(_core);
    entryPoint = IEntryPoint(_entryPoint);
}

// Create a new SimpleAccount for a patient
function createAccount(address owner, uint256 salt) public nonReentrant returns (SimpleAccount ret) {
    require(owner != address(0), "Invalid owner address");
    require(core.hasRole(core.PATIENT_ROLE(), owner), "Owner must be a patient");

    address addr = getAddress(owner, salt);
    uint256 codeSize = addr.code.length;
    if (codeSize > 0) {
        return SimpleAccount(payable(addr));
    }

    ret = SimpleAccount(payable(
        address(new ERC1967Proxy{salt: bytes32(salt)}(
            address(accountImplementation),
            abi.encodeCall(SimpleAccount.initialize, (owner))
        ))
    ));

    emit AccountCreated(owner, address(ret), salt);
}

// Compute the counterfactual address of a SimpleAccount
function getAddress(address owner, uint256 salt) public view returns (address) {
    return address(uint160(uint(keccak256(abi.encodePacked(
        bytes1(0xff),
        address(this),
        salt,
        keccak256(abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(address(accountImplementation), abi.encodeCall(SimpleAccount.initialize, (owner)))
        ))
    )))));
}

// Role-based access modifier (not used here but included for consistency)
modifier onlyRole(bytes32 role) {
    require(core.hasRole(role, msg.sender), "Unauthorized");
    _;
}

}

