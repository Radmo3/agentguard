// Minimal embedded ABIs used for calldata decoding. Kept small on purpose.

export const ERC20_ABI = [
  {
    type: "function", name: "transfer", stateMutability: "nonpayable",
    inputs: [{ name: "to", type: "address" }, { name: "amount", type: "uint256" }],
    outputs: [{ type: "bool" }],
  },
  {
    type: "function", name: "approve", stateMutability: "nonpayable",
    inputs: [{ name: "spender", type: "address" }, { name: "amount", type: "uint256" }],
    outputs: [{ type: "bool" }],
  },
  {
    type: "function", name: "transferFrom", stateMutability: "nonpayable",
    inputs: [
      { name: "from", type: "address" }, { name: "to", type: "address" }, { name: "amount", type: "uint256" },
    ],
    outputs: [{ type: "bool" }],
  },
  {
    type: "function", name: "permit", stateMutability: "nonpayable",
    inputs: [
      { name: "owner", type: "address" }, { name: "spender", type: "address" }, { name: "value", type: "uint256" },
      { name: "deadline", type: "uint256" }, { name: "v", type: "uint8" }, { name: "r", type: "bytes32" }, { name: "s", type: "bytes32" },
    ],
    outputs: [],
  },
  {
    type: "function", name: "allowance", stateMutability: "view",
    inputs: [{ name: "owner", type: "address" }, { name: "spender", type: "address" }],
    outputs: [{ type: "uint256" }],
  },
  {
    type: "function", name: "decimals", stateMutability: "view", inputs: [], outputs: [{ type: "uint8" }],
  },
  {
    type: "function", name: "symbol", stateMutability: "view", inputs: [], outputs: [{ type: "string" }],
  },
  {
    type: "event", name: "Transfer",
    inputs: [
      { name: "from", type: "address", indexed: true },
      { name: "to", type: "address", indexed: true },
      { name: "value", type: "uint256", indexed: false },
    ],
  },
  {
    type: "event", name: "Approval",
    inputs: [
      { name: "owner", type: "address", indexed: true },
      { name: "spender", type: "address", indexed: true },
      { name: "value", type: "uint256", indexed: false },
    ],
  },
] as const;

export const ERC721_ABI = [
  {
    type: "function", name: "setApprovalForAll", stateMutability: "nonpayable",
    inputs: [{ name: "operator", type: "address" }, { name: "approved", type: "bool" }],
    outputs: [],
  },
] as const;

// Uniswap V2 router + V3 SwapRouter selectors.
export const SWAP_ABI = [
  {
    type: "function", name: "swapExactTokensForTokens", stateMutability: "nonpayable",
    inputs: [
      { name: "amountIn", type: "uint256" }, { name: "amountOutMin", type: "uint256" },
      { name: "path", type: "address[]" }, { name: "to", type: "address" }, { name: "deadline", type: "uint256" },
    ],
    outputs: [{ type: "uint256[]" }],
  },
  {
    type: "function", name: "swapTokensForExactTokens", stateMutability: "nonpayable",
    inputs: [
      { name: "amountOut", type: "uint256" }, { name: "amountInMax", type: "uint256" },
      { name: "path", type: "address[]" }, { name: "to", type: "address" }, { name: "deadline", type: "uint256" },
    ],
    outputs: [{ type: "uint256[]" }],
  },
  {
    type: "function", name: "swapExactETHForTokens", stateMutability: "payable",
    inputs: [
      { name: "amountOutMin", type: "uint256" }, { name: "path", type: "address[]" },
      { name: "to", type: "address" }, { name: "deadline", type: "uint256" },
    ],
    outputs: [{ type: "uint256[]" }],
  },
  {
    type: "function", name: "swapExactTokensForETH", stateMutability: "nonpayable",
    inputs: [
      { name: "amountIn", type: "uint256" }, { name: "amountOutMin", type: "uint256" },
      { name: "path", type: "address[]" }, { name: "to", type: "address" }, { name: "deadline", type: "uint256" },
    ],
    outputs: [{ type: "uint256[]" }],
  },
  {
    type: "function", name: "exactInputSingle", stateMutability: "payable",
    inputs: [{
      name: "params", type: "tuple",
      components: [
        { name: "tokenIn", type: "address" }, { name: "tokenOut", type: "address" }, { name: "fee", type: "uint24" },
        { name: "recipient", type: "address" }, { name: "deadline", type: "uint256" }, { name: "amountIn", type: "uint256" },
        { name: "amountOutMinimum", type: "uint256" }, { name: "sqrtPriceLimitX96", type: "uint160" },
      ],
    }],
    outputs: [{ type: "uint256" }],
  },
  {
    type: "function", name: "exactInput", stateMutability: "payable",
    inputs: [{
      name: "params", type: "tuple",
      components: [
        { name: "path", type: "bytes" }, { name: "recipient", type: "address" }, { name: "deadline", type: "uint256" },
        { name: "amountIn", type: "uint256" }, { name: "amountOutMinimum", type: "uint256" },
      ],
    }],
    outputs: [{ type: "uint256" }],
  },
  {
    type: "function", name: "exactOutputSingle", stateMutability: "payable",
    inputs: [{
      name: "params", type: "tuple",
      components: [
        { name: "tokenIn", type: "address" }, { name: "tokenOut", type: "address" }, { name: "fee", type: "uint24" },
        { name: "recipient", type: "address" }, { name: "deadline", type: "uint256" }, { name: "amountOut", type: "uint256" },
        { name: "amountInMaximum", type: "uint256" }, { name: "sqrtPriceLimitX96", type: "uint160" },
      ],
    }],
    outputs: [{ type: "uint256" }],
  },
] as const;

export const ALL_ABI = [...ERC20_ABI, ...ERC721_ABI, ...SWAP_ABI] as const;
