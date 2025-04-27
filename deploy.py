#!/usr/bin/env python3
import argparse
import json
import os
import pprint
import re
from math import ceil
from typing import NamedTuple

import dotenv
import solcx
import web3
from eth_abi import encode
from eth_account.signers.local import LocalAccount
from eth_typing import HexStr
from eth_utils.curried import from_wei
from solcx import compile_source, install_solc, compile_standard

from utils.encode_constructor_args import main as encode_constructor_args

abi = json.loads(
    """[
	{
		"inputs": [],
		"name": "AccessDenied",
		"type": "error"
	},
	{
		"inputs": [],
		"name": "ErrorCreatingContract",
		"type": "error"
	},
	{
		"inputs": [],
		"name": "ErrorCreatingProxy",
		"type": "error"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "target",
				"type": "address"
			}
		],
		"name": "NoEtherToRecover",
		"type": "error"
	},
	{
		"inputs": [],
		"name": "TargetAlreadyExists",
		"type": "error"
	},
	{
		"inputs": [],
		"name": "TransactionFailed",
		"type": "error"
	},
	{
		"anonymous": false,
		"inputs": [
			{
				"indexed": true,
				"internalType": "address",
				"name": "account",
				"type": "address"
			}
		],
		"name": "AccessGranted",
		"type": "event"
	},
	{
		"anonymous": false,
		"inputs": [
			{
				"indexed": true,
				"internalType": "address",
				"name": "account",
				"type": "address"
			}
		],
		"name": "AccessRevoked",
		"type": "event"
	},
	{
		"anonymous": false,
		"inputs": [
			{
				"indexed": true,
				"internalType": "address",
				"name": "contractAddress",
				"type": "address"
			},
			{
				"indexed": true,
				"internalType": "bytes32",
				"name": "salt",
				"type": "bytes32"
			}
		],
		"name": "ContractDeployed",
		"type": "event"
	},
	{
		"stateMutability": "payable",
		"type": "fallback"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "account",
				"type": "address"
			},
			{
				"internalType": "bool",
				"name": "status",
				"type": "bool"
			}
		],
		"name": "authSetter",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "",
				"type": "address"
			}
		],
		"name": "authorizedCallers",
		"outputs": [
			{
				"internalType": "uint8",
				"name": "",
				"type": "uint8"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "bytes32",
				"name": "_salt",
				"type": "bytes32"
			}
		],
		"name": "computeAddress",
		"outputs": [
			{
				"internalType": "address",
				"name": "",
				"type": "address"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "bytes32",
				"name": "_salt",
				"type": "bytes32"
			},
			{
				"internalType": "bytes",
				"name": "_creationCode",
				"type": "bytes"
			},
			{
				"internalType": "bytes",
				"name": "constructorArgs",
				"type": "bytes"
			}
		],
		"name": "deploy",
		"outputs": [
			{
				"internalType": "address",
				"name": "addr",
				"type": "address"
			}
		],
		"stateMutability": "payable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "contractAddress",
				"type": "address"
			}
		],
		"name": "deployments",
		"outputs": [
			{
				"internalType": "bytes32",
				"name": "deploymentSalt",
				"type": "bytes32"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "generateSalt",
		"outputs": [
			{
				"internalType": "bytes32",
				"name": "salt",
				"type": "bytes32"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "bytes32",
				"name": "_salt",
				"type": "bytes32"
			}
		],
		"name": "recoverHiddenEther",
		"outputs": [
			{
				"internalType": "bool",
				"name": "",
				"type": "bool"
			}
		],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"stateMutability": "payable",
		"type": "receive"
	}
]""")

class Configuration(NamedTuple):
    private_key: str
    network: str
    net_rpc: str
    contract_addr: str




class Create3Deployer:

    def __init__(self, _network: str, _contract_address=None, admin_key=None, _rpc: str = None):
        dotenv.load_dotenv()
        if not _contract_address:
            self.contract_address = os.environ.get(f'{_network.upper()}_CREATE3_CONTRACT_ADDRESS')
        else:
            self.contract_address = _contract_address
        if not admin_key:
            self.account: LocalAccount = web3.Account.from_key(os.environ.get("ADMIN_KEY"))
        else:
            self.account: LocalAccount = web3.Account.from_key(admin_key)
        if _rpc:
            rpc_ = _rpc
        else:
            rpc_ = os.environ.get(f'{_network.upper()}_HTTP_ENDPOINT')
        self.w3 = web3.Web3(web3.HTTPProvider(rpc_))
        self.contract = self.w3.eth.contract(self.contract_address, abi=abi)

    def extract_solidity_version(self, pragma_statement: str):
        # Updated regex to handle all the cases
        pattern = r'pragma\s+solidity\s*(?:[\^=]\s*)?([0-9]+\.[0-9]+\.[0-9]+);'
        match = re.search(pattern, pragma_statement)

        if match:
            return match.group(1)  # Return the captured version number
        else:
            return None

    def random_salt(self):
        return '0x' + self.w3.eth.account.create().key.hex()



    def compile_and_encode_constructor(self, sol_file_path: str, _contract_name: str, _args=None):
        """
        Compiles a Solidity contract and encodes constructor parameters.

        :param sol_file_path: Path to the .sol file (e.g., './Calculator.sol')
        :param _contract_name: Contract name (e.g., 'Calculator')
        :param _args: Constructor arguments, either as list or dict
        :return: Tuple (abi, final_bytecode_hex)
        """
        try:
            install_solc("0.8.0")

            with open(sol_file_path, 'r') as file:
                source = file.read()

            compiled = compile_standard({
                "language": "Solidity",
                "sources": {
                    os.path.basename(sol_file_path): {
                        "content": source
                    }
                },
                "settings": {
                    "outputSelection": {
                        "*": {
                            "*": ["abi", "evm.bytecode.object"]
                        }
                    }
                }
            }, solc_version="0.8.0")

            contract_data = compiled['contracts'][os.path.basename(sol_file_path)][_contract_name]
            _abi = contract_data['abi']
            bytecode = contract_data['evm']['bytecode']['object']

            # If no constructor or args, just return
            constructor_inputs = []
            for item in _abi:
                if item.get("type") == "constructor":
                    constructor_inputs = item.get("inputs", [])
                    break

            if not constructor_inputs or not _args:
                print("No constructor args needed.")
                return _abi, bytecode

            # Prepare types and values
            types = [i['type'] for i in constructor_inputs]

            if isinstance(_args, dict):
                values = [_args[i['name']] for i in constructor_inputs]
            elif isinstance(_args, list):
                values = _args
            else:
                raise ValueError("Constructor args must be a list or dict.")

            encoded = encode(types, values)  # raw bytes
            final_bytecode = bytes.fromhex(bytecode) + encoded
            return _abi, final_bytecode.hex()

        except Exception as e:
            print(f"[Error] {e}")
            raise

    def compile_solidity(self, file_path, runs: int = 200):
        solidity_version = None
        # Read the Solidity file
        with open(file_path, 'r') as file:
            source_code = file.read()
        with open(file_path, 'r') as file:
            source_lines = file.readlines()
        # print(len(source_lines))
        for line in source_lines:
            solidity_version = self.extract_solidity_version(line.strip('\r\n'))
            if solidity_version:
                print('[~] Extracted solc version: ', solidity_version, 'from source')
                break

        if not solidity_version:
            raise Exception('[!] Could not find sol version')

        # Compile the source code
        print('[+] Solc binary: ' + solcx.wrapper.install.get_default_solc_binary().__str__())
        solcx.install_solc(solidity_version)
        compiled_sol = compile_source(source_code, solc_version=solidity_version, optimize=True, optimize_runs=runs,
                                      output_values=["abi", "bin"])

        # Extract contract data
        # contract_id, contract_interface = next(iter(compiled_sol.items())))
        # print(compiled_sol.keys().mapping.values())
        # Extract the bytecode for each contract in the file
        _bytecodes = {}
        for _contract_name, contract_info in compiled_sol.items():
            _bytecodes[_contract_name] = contract_info['bin']

        return _bytecodes

    def deploy(self, _contract_name: str, ether_val: int, salt: HexStr, _bytecode: HexStr, constructor_args: HexStr,
               dry_run: bool = False):
        print(f'[*] Deploying: dry run: %s' % dry_run)
        print('[*] Parameter types: ', args.constructor_types, 'args', args.constructor_args)
        gas = self.contract.functions.deploy(salt, _bytecode, constructor_args).estimate_gas({
            'chainId': self.w3.eth.chain_id,
            # 'gas': 5000000,  # Modify as needed or estimate dynamically
            # 'gasPrice': self.w3.to_wei(self.w3.eth.gas_price * 1.1, 'gwei'),
            'nonce': self.w3.eth.get_transaction_count(self.account.address),
            'from': self.account.address,
            'value': ether_val,
            # 'data': _tx_data
        })
        # gas = self.w3.eth.estimate_gas(tx_data)
        print('[+] Gas estimate: %s' % gas)
        # print('data', tx_data)
        tx = {'to': self.contract_address,
              'value': hex(ether_val),
              'gas': hex(gas),
              'gasPrice': ceil(self.w3.eth.gas_price * 1.1),
              'from': self.account.address,
              'chainId': hex(self.w3.eth.chain_id),
              'nonce': self.w3.eth.get_transaction_count(self.account.address),
              'data': self.contract.encode_abi('deploy', args=[salt, _bytecode, constructor_args])}

        gas = self.w3.eth.estimate_gas(tx)
        tx.update({'gas': gas})
        if dry_run:
            pprint.pprint(tx)
            return tx
        signed_tx = self.account.sign_transaction(tx)
        if hasattr(signed_tx, 'raw_transaction'):
            raw_tx = getattr(signed_tx, 'raw_transaction')
        else:
            raw_tx = getattr(signed_tx, 'rawTransaction')

        tx_id = self.w3.eth.send_raw_transaction(raw_tx)
        print('[+] TXID: ', self.w3.to_hex(tx_id))
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_id)
        return receipt

    def calculate(self, salt: HexStr):
        return self.contract.functions.computeAddress(HexStr(salt)).call({'from': self.account.address})


    @staticmethod
    def parse_config_file(file_path: str = None):
        if file_path:
            print(f'[+] Loading config from {args.config}')
            with open(file_path, 'r') as f:
                conf = json.load(f)
                network = conf.get('name')
                net_rpc = conf.get('evm_rpc')
                contract_addr = conf.get('deploy_contract')
                private_key = conf.get('private_key')
        else:
            private_key = os.environ.get('ADMIN_KEY')
            network = args.network.upper()
            net_rpc = os.environ.get(network + '_HTTP_ENDPOINT')
            contract_addr = os.environ.get(f'{network}_CREATE3_CONTRACT_ADDRESS')
        return Configuration(private_key, network, net_rpc, contract_addr)




if __name__ == '__main__':
    args = argparse.ArgumentParser()
    args.add_argument('-c', '--config', type=str, default=None)
    args.add_argument('-n', '--network', type=str, default='ethereum')

    subparsers = args.add_subparsers(dest='command')
    gen_salt = subparsers.add_parser('gen_salt')
    deploy = subparsers.add_parser('deploy')
    deploy.add_argument('contract_file', type=str)
    deploy.add_argument('ether_value', type=float)
    deploy.add_argument('salt', type=str, default='0')
    deploy.add_argument('-ct', '--constructor-types', dest='constructor_types', nargs='+', default=[])
    deploy.add_argument('-ca', '--constructor-args', dest='constructor_args', nargs='+', default=[])
    deploy.add_argument('contract_name', default=None)
    deploy.add_argument('-d', '--dry-run', dest='dry_run', action='store_true',
                        help='Do not broadcast')
    deploy.add_argument('--runs', type=int, default=200)
    calculate = subparsers.add_parser('calculate')
    calculate.add_argument('salt', type=str)
    args = args.parse_args()
    c = Create3Deployer.parse_config_file(args.config)
    deployer = Create3Deployer(c.network, c.contract_addr, c.private_key, c.net_rpc)
    dotenv.load_dotenv()
    contract_name = None
    contract_bytecode = None
    if args.command == 'gen_salt':
        print(deployer.random_salt())

    elif args.command == 'deploy':
        bytecode_dict = deployer.compile_solidity(args.contract_file, args.runs)
        if str(args.salt) in ['0x', '0x0', '0']:
            args.salt = deployer.random_salt()
            print(f'[+] Generated random salt: {args.salt}')
        found = False
        computed_address = deployer.calculate(HexStr(args.salt))
        print(f'[+] Salt computes to {computed_address}')
        for name, __bytecode in bytecode_dict.items():
            print('[*] ', name, __bytecode)
            contract_name = name.split(':')[1]
            # print(contract_name)
            contract_bytecode = __bytecode
            if isinstance(contract_bytecode, str):
                hex_string = bytes.fromhex(contract_bytecode)
            if len(args.constructor_types) > 0:
                assert args.constructor_types.__len__() == args.constructor_args.__len__()
                constructor_args_bytecode = encode_constructor_args(args.constructor_args, args.constructor_types)
            else:
                constructor_args_bytecode = "0x"
            if contract_name == args.contract_name:
                # print(name, bytecode_dict)
                if contract_name and contract_bytecode:
                    found = True
                    print(f'[+] Will deploy contract: {contract_name} to address {computed_address}')
                    input('>>  press enter to continue ')

                    ret = deployer.deploy(contract_name, from_wei(args.ether_value, 'ether'), HexStr(args.salt),
                                          HexStr('0x'+contract_bytecode),
                                          HexStr(constructor_args_bytecode), args.dry_run)
                    pprint.pprint(ret)
                    print('[+] Contract deployed to %s' % computed_address)
                    break
        if not found:
            print('[!] Could not find contract %s' % contract_name)
            exit(1)

    elif args.command == 'calculate':
        ret = deployer.calculate(HexStr(args.salt))
        print(f'[+] Address: {ret}')
    else:
        raise Exception('[!] Invalid command %s ' % args.command)
