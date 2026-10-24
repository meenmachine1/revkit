# EVM test contracts

Compiled bytecode of two well-known open-source contracts, for the EVM
processor's tests (docs/evm.md):

| File | What |
| --- | --- |
| `erc20.creation.hex`, `erc20.runtime.hex` | OpenZeppelin `ERC20` (`contracts/token/ERC20/ERC20.sol`): creation code (constructor) and runtime code |
| `erc721.creation.hex`, `erc721.runtime.hex` | OpenZeppelin `ERC721` (`contracts/token/ERC721/ERC721.sol`) |

Source: the `bytecode` and `deployedBytecode` fields of
`build/contracts/ERC20.json` and `ERC721.json` in the npm package
`@openzeppelin/contracts` 4.9.6 (OpenZeppelin's release build), copied
unchanged as hex text. OpenZeppelin Contracts is MIT-licensed, Copyright (c)
2016-2023 zOS Global Limited and contributors (THIRD_PARTY_NOTICES.md).
