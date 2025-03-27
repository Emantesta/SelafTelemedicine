const { ethers } = require("hardhat");
module.exports = async ({ getNamedAccounts, deployments }) => {
  const { deploy } = deployments;
  const { deployer } = await getNamedAccounts();
  // Deploy EntryPoint (if not already deployed)
  const entryPointAddress = process.env.ENTRYPOINT_ADDRESS;
  // Deploy TelemedicineCore
  const core = await deploy("TelemedicineCore", {
    from: deployer,
    args: [],
    log: true,
    proxy: {
      proxyContract: "OpenZeppelinTransparentProxy",
      execute: {
        init: {
          methodName: "initialize",
          args: [deployer],
        },
      },
    },
  });
  // Deploy TelemedicinePayments
  const payments = await deploy("TelemedicinePayments", {
    from: deployer,
    args: [],
    log: true,
    proxy: {
      proxyContract: "OpenZeppelinTransparentProxy",
      execute: {
        init: {
          methodName: "initialize",
          args: [core.address],
        },
      },
    },
  });
  // Deploy TelemedicineMedical
  const medical = await deploy("TelemedicineMedical", {
    from: deployer,
    args: [],
    log: true,
    proxy: {
      proxyContract: "OpenZeppelinTransparentProxy",
      execute: {
        init: {
          methodName: "initialize",
          args: [core.address, payments.address],
        },
      },
    },
  });
  // Deploy SimpleAccountFactory
  const accountFactory = await deploy("SimpleAccountFactory", {
    from: deployer,
    args: [entryPointAddress],
    log: true,
  });
  // Deploy SimplePaymaster
  const paymaster = await deploy("SimplePaymaster", {
    from: deployer,
    args: [],
    log: true,
    proxy: {
      proxyContract: "OpenZeppelinTransparentProxy",
      execute: {
        init: {
          methodName: "initialize",
          args: [core.address, payments.address, medical.address],
        },
      },
    },
  });
  // Deploy TelemedicineGovernanceCore
  const governance = await deploy("TelemedicineGovernanceCore", {
    from: deployer,
    args: [],
    log: true,
    proxy: {
      proxyContract: "OpenZeppelinTransparentProxy",
      execute: {
        init: {
          methodName: "initialize",
          args: [core.address],
        },
      },
    },
  });
  // Deploy TelemedicineEmergency
  const emergency = await deploy("TelemedicineEmergency", {
    from: deployer,
    args: [],
    log: true,
    proxy: {
      proxyContract: "OpenZeppelinTransparentProxy",
      execute: {
        init: {
          methodName: "initialize",
          args: [core.address],
        },
      },
    },
  });
  // Deploy TelemedicineSubscription
  const subscription = await deploy("TelemedicineSubscription", {
    from: deployer,
    args: [],
    log: true,
    proxy: {
      proxyContract: "OpenZeppelinTransparentProxy",
      execute: {
        init: {
          methodName: "initialize",
          args: [core.address, payments.address],
        },
      },
    },
  });
  console.log("Deployed Contracts:");
  console.log("TelemedicineCore:", core.address);
  console.log("TelemedicinePayments:", payments.address);
  console.log("TelemedicineMedical:", medical.address);
  console.log("SimpleAccountFactory:", accountFactory.address);
  console.log("SimplePaymaster:", paymaster.address);
  console.log("TelemedicineGovernanceCore:", governance.address);
  console.log("TelemedicineEmergency:", emergency.address);
  console.log("TelemedicineSubscription:", subscription.address);
};
module.exports.tags = ["all"];

