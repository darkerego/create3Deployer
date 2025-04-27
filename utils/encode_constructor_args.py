#!/usr/bin/env python3
import argparse
import eth_abi


def encode_arg_to_type(_arg) -> str | int:
    try:
        return int(_arg)
    except ValueError:
        return _arg


def encode_constructor_args(argument_types: list[str], function_args: list[str]):
    encoded_args = eth_abi.abi.encode(argument_types, [encode_arg_to_type(a) for a in function_args])
    return encoded_args


def get_args():
    parser = argparse.ArgumentParser(description="Encode constructor arguments into bytecode.")
    parser.add_argument(
        "--values", nargs="+", required=True, help="Constructor arguments, space-separated"
    )
    parser.add_argument(
        "--types", type=str, nargs="+", help="Data types of constructor arguments, space-separated")

    # Parse the arguments
    return parser.parse_args()


def create_abi_bytecode(values: list, types: list):
    # types = [_type for _type in types]
    values = [encode_arg_to_type(x) for x in values]
    # Encode the constructor arguments using the given types
    try:
        return encode_constructor_args(types, values)
        # print(f"0x{encoded_args.hex()}")
    except Exception as e:
        print(f"[!] Error encoding arguments: {e}")


def cli_main():
    # Set up the argument parser
    args = get_args()
    print(vars(args))
    # with open(args.abi_json_file, 'r') as f:
    #    abi_dict = json.load(f)

    # Initialize Web3 codec
    # w3 = Web3()
    return create_abi_bytecode(args.values, args.types)


def main(values: list, types: list):
    return create_abi_bytecode(values, types)


if __name__ == "__main__":
    cli_main()
