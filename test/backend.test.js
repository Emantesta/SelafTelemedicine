const request = require("supertest");
const { expect } = require("chai");
const { ethers } = require("ethers");
const app = require("../backend");
describe("Telemedicine Backend API", function () {
  let patientToken, adminToken;
  let patientAddress = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"; // Hardhat default account 0
  let adminAddress = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";   // Hardhat default account 1
  before(async function () {
    // Generate JWT tokens for testing
    const jwt = require("jsonwebtoken");
    patientToken = jwt.sign({ address: patientAddress, role: "patient" }, process.env.JWT_SECRET, { expiresIn: "1h" });
    adminToken = jwt.sign({ address: adminAddress, role: "admin" }, process.env.JWT_SECRET, { expiresIn: "1h" });

// Ensure MongoDB is connected
const mongoose = require("mongoose");
await mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });

  });
  after(async function () {
    await mongoose.connection.close();
  });
  it("should login a patient", async function () {
    const message = "Login to Telemedicine";
    const signature = await (new ethers.Wallet("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")).signMessage(message); // Hardhat private key 0
    const res = await request(app)
      .post("/login")
      .send({ address: patientAddress, signature, message })
      .expect(200);
    expect(res.body).to.have.property("token");
    expect(res.body.role).to.equal("patient");
  });
  it("should register a patient", async function () {
    const message = "Register to Telemedicine";
    const signature = await (new ethers.Wallet("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d")).signMessage(message); // Hardhat private key 2
    const newPatient = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";
    const res = await request(app)
      .post("/register")
      .send({ address: newPatient, role: "patient", signature, message })
      .expect(200);
    expect(res.body).to.have.property("token");
    expect(res.body.role).to.equal("patient");
  });
  it("should book an appointment", async function () {
    const res = await request(app)
      .post("/book-appointment")
      .set("Authorization", Bearer ${patientToken})
      .send({
        doctorAddress: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        timestamp: Math.floor(Date.now() / 1000) + 3600,
        paymentType: 0,
        isVideoCall: true,
        videoCallLink: "zoom.link",
        amount: "0.1",
      })
      .expect(200);
    expect(res.body).to.have.property("txHash");
  });
  it("should toggle data monetization", async function () {
    const res = await request(app)
      .post("/toggle-data-monetization")
      .set("Authorization", Bearer ${patientToken})
      .send({ enable: true })
      .expect(200);
    expect(res.body).to.have.property("txHash");
  });
  it("should claim data reward", async function () {
    const res = await request(app)
      .post("/claim-data-reward")
      .set("Authorization", Bearer ${patientToken})
      .expect(200);
    expect(res.body).to.have.property("txHash");
  });
  it("should queue withdraw funds (admin only)", async function () {
    const res = await request(app)
      .post("/queue-withdraw-funds")
      .set("Authorization", Bearer ${adminToken})
      .send({ to: adminAddress, amount: "0.5" })
      .expect(200);
    expect(res.body).to.have.property("txHash");
    expect(res.body).to.have.property("timeLockId");
  });
  it("should fail unauthorized admin action", async function () {
    await request(app)
      .post("/queue-withdraw-funds")
      .set("Authorization", Bearer ${patientToken})
      .send({ to: adminAddress, amount: "0.5" })
      .expect(403);
  });
});
