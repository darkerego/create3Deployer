# create3Deployer
================================================

####  About
A factory contract capable of determinstic deploy that depends only on a bytes32 hash. This allows you to have contract's with the same address and different bytecode across multiple chains as 
the address is derived by the salt and the bytecode is irrelevant. 

#### Constructor args 

If you need to deploy a contract with construct args, you need to simply encode them and then append to the deployment code. I will upload python script to manage this 
as well as deploy contracts using this factory soon.

#### Store & Recover Hidden Ether

Additionally, this factory contract contains built in functionality for recovering hidden Ether that is stored at an address that can be generated with a pre-known salt by this contract. 
Do not loose the salt if you use this feature or your funds will be lost forever. 

#### Python Helper Cli Tool



Example usage:
<pre>
  $ python3 create3.py -n tenderly deploy  contracts/minimalERC20.sol 0 0 MinimalistToken  -ct string string uint256 uint8 -ca Test T 1000000 18
</pre>
