//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.26;

/**
  @title A contract for deploying contracts EIP-3171 style.
  @author Darkerego <xelectron@protonmail.com>
  @notice adapted from library originally written by Agustin Aguilar <aa@horizon.io>
*/

contract Create3Deployer {
    address admin;
    /*
     @notice The bytecode for a contract that proxies the creation of another contract
     @dev If this code is deployed using CREATE2 it can be used to decouple `creationCode` from the child contract address \ 
      https://github.com/0xsequence/create3/blob/acc4703a21ec1d71dc2a99db088c4b1f467530fd/contracts/Create3.sol#L14C4-L15C122
    */
    bytes internal creationCode = hex"67_36_3d_3d_37_36_3d_34_f0_3d_52_60_08_60_18_f3";
    bytes32 internal constant creationCodeHash = 0x21c35dbe1b344a2488cf3321d6ce542f8e9f305544ff09e4993a62319a497c1f;

    
    /*
    @dev custom error functions are cheaper than `require` statements
    */
    error ErrorCreatingProxy();
    error ErrorCreatingContract();
    error TargetAlreadyExists();
    error AuthenticationError();
    error TransactionFailed();
    error NoEtherToRecover(address target);
    // emit an event whenever a contract is deployed
    event ContractDeployed(address indexed contractAddress, bytes32 indexed salt);
    // @dev accept deposits to this contract
    receive() external payable {}
    fallback() external payable {}
    
    /*
    @dev store the `msg.sender` as the contract's admin
    */
    constructor() {
        assembly {
            sstore(admin.slot, caller())
        }
    }

    /*
    @notice called by modifier `protected`
    */
    
    function auth() internal view {
      assembly {
            if iszero(eq(caller(), sload(0x0))) {
                 //  keccak256("AuthenticationError()")
                let ptr := mload(0x40)
                mstore(ptr, 0xd14518c6a85a3aaf5db8fc3348addbf40353edd39765014e8c5a87b656dbceb5)
                revert(ptr, 0x20)
            }
        }
    }

    /*
    @dev this modifier restricts function calls to the admin
    */

    modifier protected {
        auth();
        _;
    }
    

    /*
    @notice transfer ownership of the factory to a new account
    @param _admin the new admin account's address
    */
    function updateAdmin(address _admin) external protected {
        assembly {
            sstore(admin.slot, _admin)
        }
    }

    /*
    @notice a helper function that generates a random salt for convience 
    */

     function generateRandomSalt() external view returns (bytes32 salt) {
        
        assembly {
            let ptr := mload(0x40)    // Get free memory pointer

            // Store block.timestamp, block.difficulty, and msg.sender in memory
            mstore(ptr, timestamp())  // random bytes
            mstore(add(ptr, 0x20), prevrandao())
            // Block difficulty
            mstore(add(ptr, 0x40), caller())  // msg.sender

            // Compute keccak256 hash over the 96 bytes (32 * 3) of data and store it in salt
            salt := keccak256(ptr, 0x60)
        }
       
    }
     

     /*
     @notice: Jack of all trades emergency function
     */
     function arbitraryCall(address r, uint256 v, bytes memory d) external protected payable returns (uint8 success) {
        assembly {
            // Perform the call: r.call{value: v}(d)
            success := call(gas(), r, v, add(d, 0x20), mload(d), 0, 0)
            // Check if the call was successful or not
            
            if iszero(success) {
                //  keccak256("TransactionFailed()")
                let ptr := mload(0x40)
                mstore(ptr, 0xbf961a286ff1ab1274d051f23436195e7b459e522375f96695f8ded00e092183)
                revert(ptr, 0x20)
            }
            
            }
        }

  /**
    @notice Returns the size of the code on a given address
    @param _addr Address that may or may not contain code
    @return size of the code on the given `_addr`
  */
  function codeSize(address _addr) internal view returns (uint256 size) {
    assembly { size := extcodesize(_addr) }
  }


  /*
  @dev This is intended to recover Ether previously sent to an address that is recoverable by this contract \ 
  make sure you do not ever forget the salt that generates the address if you use this feature, otherwise \
  your funds will be lost forever!
  @notice Creates a contract that immediately selfdestruct's and forwards any Ether stored there to the `tx.origin`, \
  because create3 uses a proxy for deterministic deployment, we need to forward back to origin instead of sender.
  @param _salt Salt of the contract creation, resulting address will be derivated from this
  */
  function recoverHiddenEther(bytes32 _salt) external protected returns (address) {
    address addr = computeAddress(_salt);
    if (codeSize(addr) != 0) revert TargetAlreadyExists(); //@dev if addr is not empty then it means this contract already exists
    if (addr.balance == 0) revert NoEtherToRecover(addr); //@dev no point if there's no Ether stored here
    return create3(_salt, hex"32ff", 0); //@dev 0x32ff - The bytecode for ORIGIN + SELFDESTRUCT
    

  }

  /**
    @notice Creates a new contract with given `_creationCode` and `_salt`, forward msg.value (if any) to the deployed contract
    @param _salt Salt of the contract creation, resulting address will be derivated from this value only
    @param _creationCode Creation code (constructor) of the contract to be deployed, this value doesn't affect the resulting address
    @return addr of the deployed contract, reverts on error
  */
  function deploy(bytes32 _salt, bytes memory _creationCode) external protected payable returns (address addr) {
    return create3(_salt, _creationCode, msg.value);
  }

  /**
    @notice Creates a new contract with given `_creationCode` and `_salt`
    @param _salt Salt of the contract creation, resulting address will be derivated from this value only
    @param _creationCode Creation code (constructor) of the contract to be deployed, this value doesn't affect the resulting address
    @param _value In WEI of ETH to be forwarded to child contract
    @return addr of the deployed contract, reverts on error
  */
  function create3(bytes32 _salt, bytes memory _creationCode, uint256 _value) internal returns (address addr) {
    

    // Get target final address
    addr = computeAddress(_salt);
    if (codeSize(addr) != 0) revert TargetAlreadyExists();

    // Create CREATE2 proxy
    address proxy; 
    assembly { proxy := create2(0, add(creationCode.slot, 32), mload(creationCode.slot), _salt)}
    if (proxy == address(0)) revert ErrorCreatingProxy();

    // Call proxy with final init code
    (bool success,) = proxy.call{ value: _value }(_creationCode);
    if (!success) revert ErrorCreatingContract();
    assembly {
            // Log the event: Topics and Data
            log3(
                0x00,               // No data (non-indexed parameters) in the log
                0x00,               // No length of data (since no non-indexed parameters)
                0xb085ff794f342ed78acc7791d067e28a931e614b52476c0305795e1ff0a154bc,           // Topic 0: event signature
                addr,    // Topic 1: indexed contractAddress
                _salt                // Topic 2: indexed salt
            )
        }
     }
  

  /**
    @notice Computes the resulting address of a contract deployed using address(this) and the given `_salt`
    @param _salt Salt of the contract creation, resulting address will be derivated from this value only
    @return addr of the deployed contract, reverts on error

    @dev The address creation formula is: keccak256(rlp([keccak256(0xff ++ address(this) ++ _salt ++ keccak256(childBytecode))[12:], 0x01]))
  */
  function computeAddress(bytes32 _salt) public  view returns (address) {
    address proxy = address(
      uint160(
        uint256(
          keccak256(
            abi.encodePacked(
              hex'ff',
              address(this),
              _salt,
              creationCodeHash
            )
          )
        )
      )
    );

    return address(
      uint160(
        uint256(
          keccak256(
            abi.encodePacked(
              hex"d6_94",
              proxy,
              hex"01"
            )
          )
        )
      )
    );
  } 
}
