// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract ModExp {
    address public constant modExpAddress = 0x0000000000000000000000000000000000000005;

    bytes constant modulus = hex"afb5ab279cc0df046f2910c763bd999f123297f96c17e1eb80337e96fcdd18b69212204dd8b9bdbf471e2e1e1bf13b404c63d35002037fb1609e6b91d4c0c8f52f42b66ebf24c2f75d4d5ad0f758ce9bdd1caf7a7dcf78942b744702a82fc97cd240e2f563397dd15f9754481eabf0fa0742f04f4dbc69e3d2522207af1ed271c6d77440582846fc773b17b1f44654435d99b4a811b394d78c2d2520c2adbffd0372fcbc9904a36b85148798c4ad8309c511a2ddf10b58c6ae2c03e50712391114b7d1e7d085b336061545570f55111a5bbc9ecc16b31b339f33ad48c338e8e429b7cd6f835f960dd3d01265705b8b9ba6751b0f2a53ee63d2677c95d03f58e7";
    bytes constant exp = hex"010001";

    function verify_signature(bytes calldata base, bytes calldata expected_result) public returns (bool) {
        uint256 base_length = 256;
        uint256 exp_length = 3;
        uint256 modulus_length = 256;

        (bool _success, bytes memory _result) = modExpAddress.call(abi.encodePacked(base_length, exp_length, modulus_length, base, exp, modulus));
        require(_success, "Modular exponentiation failed");

        return keccak256(_result) == keccak256(expected_result);
    }
}
