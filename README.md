# SelafTelemedicine
A decentralized telemedicine system built on Ethereum with Solidity smart contracts, Node.js backend, and React frontend.

Development Instructions For Backend
Prerequisites
Node.js (v16+)

MongoDB (running locally or via a service)

Hardhat (installed via npm)

SSL certificates (cert.pem, key.pem) for HTTPS (self-signed for development)

Steps to Run Locally
Install Dependencies:
bash

npm install

Start Hardhat Node (for local blockchain):
bash

npx hardhat node

Compile Contracts:
bash

npx hardhat compile

Deploy Contracts Locally:
bash

npx hardhat deploy --network hardhat

Update .env with deployed contract addresses from the output.

Start MongoDB (if not running):
bash

mongod

Run Backend in Development Mode:
bash

npm run dev

Uses nodemon to auto-restart on changes.

Backend runs on https://localhost:8080.

Deploy to Sonic Network
Update .env:
Set SONIC_RPC_URL, PRIVATE_KEY, and contract addresses after deployment.

Deploy Contracts:
bash

npx hardhat deploy --network sonic

Start Backend:
bash

npm start


Running Tests
Ensure Dependencies:
bash

npm install

Start Hardhat Node:
bash

npx hardhat node

Deploy Contracts:
bash

npx hardhat deploy --network hardhat

Run Tests:
bash

npm test

Directory Structure

telemedicine-blockchain/
├── backend.js              # Backend API
├── contracts/
│   ├── TelemedicineCore.sol
│   ├── TelemedicinePayments.sol
│   ├── TelemedicineMedical.sol
│   ├── SimplePaymaster.sol
│   ├── SimpleAccountFactory.sol
│   ├── TelemedicineGovernanceCore.sol
│   ├── TelemedicineEmergency.sol
│   ├── TelemedicineSubscription.sol
├── deploy/
│   ├── 00_deploy_all.js
├── test/
│   ├── backend.test.js     # Backend API tests
│   ├── TelemedicineSystem.test.js  # Contract tests
├── .env
├── hardhat.config.js
├── package.json
