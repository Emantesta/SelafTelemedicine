require("@nomiclabs/hardhat-waffle");
require("hardhat-deploy");
require("dotenv").config();
const SONIC_RPC_URL = process.env.SONIC_RPC_URL || "https://rpc.sonic.example.com";
const PRIVATE_KEY = process.env.PRIVATE_KEY || "your-private-key-here";
module.exports = {
  solidity: {
    version: "0.8.20",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
    },
  },
  networks: {
    hardhat: {
      chainId: 1337,
      accounts: { mnemonic: "test test test test test test test test test test test junk" },
    },
    sonic: {
      url: SONIC_RPC_URL,
      accounts: [PRIVATE_KEY],
      chainId: 641, // Replace with actual Sonic chain ID
    },
  },
  namedAccounts: {
    deployer: {
      default: 0,
    },
    admin: {
      default: 1,
    },
  },
  paths: {
    sources: "./contracts",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts",
    deployments: "./deployments",
  },
  mocha: {
    timeout: 40000,
  },
};
