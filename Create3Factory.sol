//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.26;


/**
  @title Authentication Manager
  @author Darkerego <xelectron@protonmail.com>
*/

abstract contract Auth {
    error AccessDenied();

    event AccessGranted(address indexed account);
    event AccessRevoked(address indexed account);

    mapping(address => uint8) private authorizedCallers;

    bytes32 private constant ACCESS_GRANTED_SIG = keccak256("AccessGranted(address)");
    bytes32 private constant ACCESS_REVOKED_SIG = keccak256("AccessRevoked(address)");

    modifier protected() {
        authenticate();
        _;
    }

    constructor() {
        authorizedCallers[msg.sender] = 1;
    }

    function authGetter(address account) private pure returns (uint256 key) {
        assembly {
            // Compute the correct mapping key: keccak256(account . storage_slot)
            mstore(0x0, account)
            mstore(0x20, authorizedCallers.slot)
            key := keccak256(0x0, 0x40)
        }
    }

    function authSetter(address account, bool status) public protected {
        uint key = authGetter(account);
        bytes32 topic = status ? ACCESS_GRANTED_SIG : ACCESS_REVOKED_SIG;

        assembly {
            let newStatus := iszero(iszero(status)) // Convert bool to 1 or 0
            sstore(key, newStatus)

            // Store the indexed parameter (account) at memory position 0x0
            mstore(0x0, account)
            log1(0x0, 0x20, topic) // Emit event with 1 indexed parameter
        }
    }

    function authenticate() internal view returns (uint8 isAuthorized) {
        uint key = authGetter(msg.sender);
        assembly {
            isAuthorized := sload(key)
            if iszero(isAuthorized) {
                let ptr := mload(0x40)
                mstore(ptr, 0x4ca88867)
                revert(ptr, 0x4)
            }
        }
    }
}

/**
  @title A contract for deploying contracts EIP-3171 style.
  @author Darkerego <xelectron@protonmail.com>
  @notice adapted from library originally written by Agustin Aguilar <aa@horizon.io>
*/

contract Create3Deployer is Auth {
   
    /*
     @notice The bytecode for a contract that proxies the creation of another contract
     @dev If this code is deployed using CREATE2 it can be used to decouple `creationCode` from the child contract address \ 
      https://github.com/0xsequence/create3/blob/acc4703a21ec1d71dc2a99db088c4b1f467530fd/contracts/Create3.sol#L14C4-L15C122
    */
    bytes32 internal constant creationCodeHash = 0x21c35dbe1b344a2488cf3321d6ce542f8e9f305544ff09e4993a62319a497c1f;
    

    
    /*
    @dev custom error functions are cheaper than `require` statements
    */
    error ErrorCreatingProxy();
    error ErrorCreatingContract();
    error TargetAlreadyExists();
    error TransactionFailed();
    error NoEtherToRecover(address target);
    // emit an event whenever a contract is deployed
    event ContractDeployed(address indexed contractAddress, bytes32 indexed salt);
    // @dev accept deposits to this contract
    receive() external payable {}
    fallback() external payable {}
    mapping (address caller => uint8 isAuthorized) public authorizedCallers;
    mapping (address contractAddress => bytes32 salt) public deployments;
    
    /*
    @dev store the `msg.sender` as the contract's admin
    */
     constructor() {
        //authorizedCallers[msg.sender] = 1; // Set deployer as authorized
        authSetter(msg.sender, true);
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
     function arbitraryCall(address r, uint256 v, bytes memory d) public protected payable returns (uint8 success) {
        assembly {
            // Perform the call: r.call{value: v}(d)
            success := call(gas(), r, v, add(d, 0x20), mload(d), 0, 0)
            // Check if the call was successful or not
            
            if iszero(success) {
                //  keccak256("TransactionFailed()")
                let ptr := mload(0x40)
                mstore(ptr, 0xb7ca6ae8)
                revert(ptr, 0x20)
            }
            
            }
        }

  /**
    @notice Returns the size of the code on a given address
    @param _addr Address that may or may not contain code
    @return size of the code on the given `_addr`
  */
  function codeSize(address _addr) public view returns (uint256 size) {
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
  function recoverHiddenEther(bytes32 _salt) external protected returns (bool) {
    address addr = computeAddress(_salt);
    if (codeSize(addr) != 0) revert TargetAlreadyExists(); //@dev if addr is not empty then it means this contract already exists
    if (addr.balance == 0) revert NoEtherToRecover(addr); //@dev no point if there's no Ether stored here
    //bytes calldata data = 0x32ff;
    create3(_salt, hex"32ff", 0); //@dev 0x32ff - The bytecode for ORIGIN + SELFDESTRUCT
    return true;
    
    

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
    @param _creationCode Creation code (constructor) of the contract to be deployed + constructor args \
    @dev this value doesn't affect the resulting address, only the hash does.
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
            

          // Compute the storage key: keccak256(addr . slot)
          
     }
     deployments[addr] = _salt;
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
