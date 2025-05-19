// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {SimpleAccount} from "@account-abstraction/contracts/samples/SimpleAccount.sol";
import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {TelemedicineCore} from "./TelemedicineCore.sol";

/// @title SimpleAccountFactory
/// @notice A factory contract for creating SimpleAccount instances for patients using ERC-4337 account abstraction on Sonic Blockchain
/// @dev Designed for deployment on Sonic Blockchain, ensure ERC-4337 EntryPoint and TelemedicineCore are deployed
contract SimpleAccountFactory is Initializable {
    /// @notice The SimpleAccount implementation contract used for proxies
    SimpleAccount public accountImplementation;
    /// @notice Reference to the TelemedicineCore contract for role management
    TelemedicineCore public core;
    /// @notice Reference to the ERC-4337 EntryPoint contract
    IEntryPoint public entryPoint;

    /// @notice Emitted when a new SimpleAccount is created
    /// @param owner The owner of the new account
    /// @param account The address of the created account
    /// @param salt The salt used for deterministic address generation
    event AccountCreated(address indexed owner, address indexed account, uint256 salt);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the factory with core and entry point addresses
    /// @param _core The address of the TelemedicineCore contract
    /// @param _entryPoint The address of the ERC-4337 EntryPoint contract
    /// @dev Verifies addresses are non-zero and compatible with Sonic Blockchain
    function initialize(address _core, address _entryPoint) external initializer {
        if (_core == address(0)) revert SimpleAccountFactory__InvalidCoreAddress();
        if (_entryPoint == address(0)) revert SimpleAccountFactory__InvalidEntryPointAddress();

        core = TelemedicineCore(_core);
        entryPoint = IEntryPoint(_entryPoint);
        accountImplementation = new SimpleAccount(entryPoint);
    }

    /// @notice Creates a new SimpleAccount for a patient
    /// @param owner The owner of the new account
    /// @param salt The salt for deterministic address generation
    /// @return ret The created SimpleAccount instance
    /// @dev Uses CREATE2 for deterministic addresses, ensure Sonic supports ERC1967Proxy
    function createAccount(address owner, uint256 salt) external returns (SimpleAccount ret) {
        if (owner == address(0)) revert SimpleAccountFactory__InvalidOwnerAddress();
        if (!core.hasRole(core.PATIENT_ROLE(), owner)) revert SimpleAccountFactory__OwnerNotPatient();

        address addr = getAddress(owner, salt);
        if (addr.code.length > 0) {
            return SimpleAccount(payable(addr));
        }

        ret = SimpleAccount(payable(
            new ERC1967Proxy{salt: bytes32(salt)}(
                address(accountImplementation),
                abi.encodeCall(SimpleAccount.initialize, (owner))
            )
        ));

        emit AccountCreated(owner, address(ret), salt);
    }

    /// @notice Computes the counterfactual address of a SimpleAccount
    /// @param owner The owner of the account
    /// @param salt The salt for deterministic address generation
    /// @return The computed address
    /// @dev Uses CREATE2, verify Sonic Blockchain supports this opcode
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
}

/// @notice Custom errors for the SimpleAccountFactory contract
error SimpleAccountFactory__InvalidCoreAddress();
error SimpleAccountFactory__InvalidEntryPointAddress();
error SimpleAccountFactory__InvalidOwnerAddress();
error SimpleAccountFactory__OwnerNotPatient();
