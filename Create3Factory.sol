// SPDX-License-Identifier: MIT
pragma solidity ^ 0.8.26;

// File: src/utils/AsmCall.sol




abstract contract AsmCalls {

  
  function assemblyCall(
    
    address target, 
    uint256 etherValue,
    bytes memory callData,
    bool isStatic,
    bool revertOnFailure
  ) internal returns (bool success, bytes memory retData) {
  
  assembly {
    //let noFail := revertOnFailure
    // tstore(noFail, 0x40)
    function checkCallStatus(_success, data) {
      
      if and(iszero(_success), tload(0x40)) {
                revert(data, mload(data))}
            }
    
      function parseRetData(_success, _revertonFail)  -> data {
        let retSize := returndatasize() // Get return data size
        // Update memory pointer after copying return data
        data := mload(0x40)
        mstore(0x40, add(data, add(retSize, 0x20))) // Adjust free memory pointer
        mstore(data, retSize) // Store the return size
        returndatacopy(add(data, 0x20), 0, retSize) // Copy return data
        checkCallStatus(_success, data)
      }
      
      function performStaticCall(_target, _callData, _etherValue, _noFail) -> _success, _retData {
        let size := mload(_callData) // Get input data size
        let ptr := add(_callData, 0x20) // Get input data pointer
        // Allocate memory for return data
        let output := mload(0x40) // Free memory pointer
        _success := staticcall(
            gas(),       // Forward all gas
            _target,      // Target contract
            ptr,         // Input data pointer
            size,        // Input data size
            output,      // Output data pointer
            0x00         // Initially, no known return size
        )
        let _data:= parseRetData(_success, _noFail)
      }

      function execCall(_target, _callData, _etherValue, _noFail) -> _success, _retData {
        _success := eq(call(gas(), _target, _etherValue, add(_callData, 0x20), mload(_callData), 0x00, 0x00), 0x1)
        let retSize := returndatasize()
        _retData := mload(0x40)
        mstore(0x40, add(_retData, add(retSize, 0x20))) // Adjust free memory pointer
        mstore(_retData, retSize) // Store the return size
        returndatacopy(add(_retData, 0x20), 0, retSize) // Copy return data
        let _data:= parseRetData(_success, _noFail)
        }

    switch gt(isStatic, 0) 
      case 1 {
      success, retData := performStaticCall(target, callData, etherValue, revertOnFailure)
      }
      case 0 {
        success, retData := execCall(target, callData, etherValue, revertOnFailure)
      }
      default {
        revert(0,0)
      }
          
        

}}}

  /*
 abstract contract AsmCallUtils {

     function staticCall(
        address target,
        bytes memory callData,
        bool requireSuccess
    ) internal view returns (bool success, bytes memory data) {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            let size := mload(callData) // Get input data size
            let ptr := add(callData, 0x20) // Get input data pointer
            // Allocate memory for return data
            let output := mload(0x40) // Free memory pointer
            success := staticcall(
                gas(),       // Forward all gas
                target,      // Target contract
                ptr,         // Input data pointer
                size,        // Input data size
                output,      // Output data pointer
                0x00         // Initially, no known return size
            )

            let retSize := returndatasize() // Get return data size
            // Update memory pointer after copying return data
            data := mload(0x40)
            mstore(0x40, add(data, add(retSize, 0x20))) // Adjust free memory pointer
            mstore(data, retSize) // Store the return size
            returndatacopy(add(data, 0x20), 0, retSize) // Copy return data
            
        }
        checkCall(revertOnFail, success, data);
        }

     function executeCall(
    
        address recipient,
        uint256 _value,
        bytes memory data,
        bool requireSucces
        ) internal returns(bool success, bytes memory retData) {
       assembly {
            success := eq(call(gas(), recipient, _value, add(data, 0x20), mload(data), 0x00, 0x00), 0x1)
            let retSize := returndatasize()
            retData := mload(0x40)
            mstore(0x40, add(retData, add(retSize, 0x20))) // Adjust free memory pointer
            mstore(retData, retSize) // Store the return size
            returndatacopy(add(retData, 0x20), 0, retSize) // Copy return data
            

        }
        checkCall(revertOnFail, success, data);
        }

        function checkCall(bool revertOnFail, bool success, bytes memory data) internal pure {
        assembly {
          if and(iszero(success), revertOnFail) {
                revert(data, mload(data))}
            }
        }}


  */
     
// File: src/utils/Create3.sol




  abstract contract Create3Factory is AsmCalls {
    bytes32 internal constant creationCodeHash = 0x21c35dbe1b344a2488cf3321d6ce542f8e9f305544ff09e4993a62319a497c1f;
    error ErrorCreatingProxy(); 
    error ErrorCreatingContract();
    error TargetAlreadyExists();
    error TransactionFailed();
    event ContractDeployed(address indexed contractAddress, bytes32 indexed salt);
   
    function codeSize(address target) view internal returns(uint256 size) {
        assembly {
            size := extcodesize(target)
        }
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
    assemblyCall(proxy, _value, _creationCode, false, true);
    //(bool success,) = proxy.call{ value: _value }(_creationCode);
    if (codeSize(addr) == 0) revert ErrorCreatingContract();
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
     emit ContractDeployed(addr, _salt);
    }


    /*
    @notice a helper function that generates a random salt for convience 
    */

     function generateSalt() public view returns (bytes32 salt) {
        assembly {
            let data := mload(0x40) // Get the free memory pointer

            // Load various sources of entropy into memory
            mstore(data, xor(timestamp(),prevrandao())) // Block timestamp
            mstore(add(data, 0x20), caller()) // Caller address
            mstore(add(data, 0x40), gaslimit()) // Gas limit

            // Compute keccak256 hash to obtain a random bytes32 salt
            salt := keccak256(data, 0x80)
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
// File: Factory3.sol




abstract contract Auth is Create3Factory {
    error AccessDenied();
    event AccessGranted(address indexed account);
    event AccessRevoked(address indexed account);
    mapping(address => uint8) public authorizedCallers;
    bytes32 internal constant ACCESS_GRANTED_SIG = 0xdeb5c31899474fe8c086c95ff9344480d19365676a6a1d22d37bb8e3e7c0ef18;
    bytes32 internal constant ACCESS_REVOKED_SIG = 0x1b9b72fde9da721e70e6aca3b0cf4cbe73e82765ef1f280157740376531bfdd8;

    modifier onlyAuthorized() {
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

    function authSetter(address account, bool status) public onlyAuthorized {
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
    /*
    @dev custom error functions are cheaper than `require` statements
    */
    mapping (address contractAddress => bytes32 deploymentSalt) public deployments;
  
    error NoEtherToRecover(address target);
    // emit an event whenever a contract is deployed
    
    // @dev accept deposits to this contract
    receive() external payable {}
    fallback() external payable {}
    //mapping (address contractAddress => bytes32 salt) public deployments;

  /*
  @dev This is intended to recover Ether previously sent to an address that is recoverable by this contract \ 
  make sure you do not ever forget the salt that generates the address if you use this feature, otherwise \
  your funds will be lost forever!
  @notice Creates a contract that immediately selfdestruct's and forwards any Ether stored there to the `tx.origin`, \
  because create3 uses a proxy for deterministic deployment, we need to forward back to origin instead of sender.
  @param _salt Salt of the contract creation, resulting address will be derivated from this
  */
  function recoverHiddenEther(bytes32 _salt) external onlyAuthorized returns (bool) {
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
  function deploy(bytes32 _salt, bytes memory _creationCode, bytes memory constructorArgs) external onlyAuthorized payable returns (address addr) {
     deployments[addr] = _salt;
     if (uint256(_salt) == 0) _salt = generateSalt();
     addr = create3(_salt, bytes.concat(_creationCode,constructorArgs), msg.value);
    
  }
}
