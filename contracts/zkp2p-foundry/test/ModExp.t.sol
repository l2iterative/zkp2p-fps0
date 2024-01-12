// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2} from "forge-std/Test.sol";
import {ModExp} from "../src/ModExp.sol";
import "forge-std/console.sol";

contract ModExpTest is Test {
    ModExp public modexp;

    function setUp() public {
        modexp = new ModExp();
    }

    function test_Increment() public {
        bytes memory base = hex"542b9702213b9ab78364ee361c04babca732df4af154dcb788572749fa8f7505ef96644f53f1f9f84bafa08c7503e9e79478978015cb0ea394a85cccbc36c1706b0c5c444c0518b8ad2a04d90d1f8a49ecd443d1674c889654aabb3a6e50cc6d5668a7687891326b6a0a058a49d4a0e6e07bf9dc9391c62d501cbe366a9149d8cd7482e8d614f4fec5f299c4a94ddc70d13a3b9f6d58d57c0556db35b7ea5bc9e18c4cad1e80a6ada8b0fe9377401f83095846c110ccbf8e9d18ec0d84d02eef31185c187af063cf4b60a5cf5ef7279543a91fce2c5db9252a415f6eda59e2f5b5c1967c1524fb84ec0c8fd57e87c410dfb20c972c0fb179f849d337bae203fe";
        bytes memory expected = hex"0001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff003031300d06096086480165030402010500042090f25972d8b7b0e1f14dbbef33c2e01ea567bbb53ec0a367f399c54a24be6f78";
        assert(modexp.verify_signature(base, expected));
    }
}
