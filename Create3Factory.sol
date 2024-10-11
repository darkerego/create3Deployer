//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.26;

/**
  @title A contract for deploying contracts EIP-3171 style.
  @author Darkerego <xelectron@protonmail.com>
  @notice adapted from library originally written by Agustin Aguilar <aa@horizon.io>
*/


contract Create3Deployer {
    address admin;
    bytes32 constant childCode = 0x21c35dbe1b344a2488cf3321d6ce542f8e9f305544ff09e4993a62319a497c1f;
    
    
    error ErrorCreatingProxy();
    error ErrorCreatingContract();
    error TargetAlreadyExists();
    error AuthenticationError();
    error TransactionFailed();
    
    event ContractDeployed(address indexed contractAddress, bytes32 indexed salt);
    // solc-ignore-next-line missing-receive
    receive() external payable {}
    fallback() external payable {}
    //receive() external payable {}
    constructor() {
        assembly {
            sstore(admin.slot, caller())
        }
    }
    
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

    modifier protected {
        auth();
        _;
    }

    function updateAdmin(address _admin) external protected {
        assembly {
            sstore(admin.slot, _admin)
        }
    }

     function generateRandomSalt() external view returns (bytes32) {
        bytes32 salt;

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

        return salt;
    }
     

     /*
     @notice: Jack of all trades emergency function
     */
     function arbitraryCall(address r, uint256 v, bytes memory d) external protected payable returns (uint8 success) {
        assembly {
            // Load the free memory pointer
            let freeMemPointer := mload(0x40)
            // Copy the length of the data to memory (first 32 bytes of 'd')
            let dataLength := mload(d)
            // Set up the pointer for calldata by copying 'd' into memory
            let dataStart := add(d, 0x20)
            // Perform the call: r.call{value: v}(d)
            success := call(gas(), r, v, dataStart, dataLength, 0, 0)
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
    bytes memory creationCode = hex"67_36_3d_3d_37_36_3d_34_f0_3d_52_60_08_60_18_f3";

    // Get target final address
    addr = computeAddress(_salt);
    if (codeSize(addr) != 0) revert TargetAlreadyExists();

    // Create CREATE2 proxy
    address proxy; assembly { proxy := create2(0, add(creationCode, 32), mload(creationCode), _salt)}
    if (proxy == address(0)) revert ErrorCreatingProxy();

    // Call proxy with final init code
    (bool success,) = proxy.call{ value: _value }(_creationCode);
    if (!success || codeSize(addr) == 0) revert ErrorCreatingContract();
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
              bytes32(0x21c35dbe1b344a2488cf3321d6ce542f8e9f305544ff09e4993a62319a497c1f)
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
