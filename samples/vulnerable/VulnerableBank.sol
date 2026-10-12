// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Deliberately vulnerable: sends ether BEFORE zeroing the balance.
contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "nothing to withdraw");
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "send failed");
        balances[msg.sender] = 0;   // state updated after the external call
    }
}
