const { expect } = require("chai");
const { ethers } = require("hardhat");
describe("Telemedicine Blockchain System", function () {
  let deployer, patient, doctor, admin;
  let core, payments, medical, paymaster, accountFactory, governance, emergency, subscription;
  beforeEach(async function () {
    [deployer, patient, doctor, admin] = await ethers.getSigners();

const Core = await ethers.getContractFactory("TelemedicineCore");
core = await upgrades.deployProxy(Core, [deployer.address], { initializer: "initialize" });

const Payments = await ethers.getContractFactory("TelemedicinePayments");
payments = await upgrades.deployProxy(Payments, [core.address], { initializer: "initialize" });

const Medical = await ethers.getContractFactory("TelemedicineMedical");
medical = await upgrades.deployProxy(Medical, [core.address, payments.address], { initializer: "initialize" });

const Paymaster = await ethers.getContractFactory("SimplePaymaster");
paymaster = await upgrades.deployProxy(Paymaster, [core.address, payments.address, medical.address], { initializer: "initialize" });

const AccountFactory = await ethers.getContractFactory("SimpleAccountFactory");
accountFactory = await AccountFactory.deploy("0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789");

const Governance = await ethers.getContractFactory("TelemedicineGovernanceCore");
governance = await upgrades.deployProxy(Governance, [core.address], { initializer: "initialize" });

const Emergency = await ethers.getContractFactory("TelemedicineEmergency");
emergency = await upgrades.deployProxy(Emergency, [core.address], { initializer: "initialize" });

const Subscription = await ethers.getContractFactory("TelemedicineSubscription");
subscription = await upgrades.deployProxy(Subscription, [core.address, payments.address], { initializer: "initialize" });

  });
  it("should register a patient and create an account", async function () {
    await core.connect(patient).registerPatient("encryptedKey");
    const accountAddr = await accountFactory.getAddress(patient.address, 0);
    expect(await core.hasRole(await core.PATIENT_ROLE(), patient.address)).to.be.true;
    expect(accountAddr).to.not.equal(ethers.constants.AddressZero);
  });
  it("should book and confirm an appointment", async function () {
    await core.connect(patient).registerPatient("encryptedKey");
    await core.connect(admin).verifyDoctor(doctor.address, "DOC123", ethers.utils.parseEther("0.1"));
    await medical.connect(patient).bookAppointment(doctor.address, Math.floor(Date.now() / 1000), 0, true, "zoom.link", { value: ethers.utils.parseEther("0.1") });
    const appointmentId = 1;
    await medical.connect(doctor).confirmAppointment(appointmentId, false);
    const appointment = await medical.appointments(appointmentId);
    expect(appointment.isConfirmed).to.be.true;
  });
  it("should deposit to paymaster and use it", async function () {
    await paymaster.connect(deployer).deposit(0, ethers.utils.parseEther("1"), { value: ethers.utils.parseEther("1") });
    const balance = await paymaster.getBalance(0);
    expect(balance).to.equal(ethers.utils.parseEther("1"));
  });
  it("should queue and execute a governance action", async function () {
    await governance.connect(admin).queueWithdrawFunds(deployer.address, ethers.utils.parseEther("0.5"));
    await governance.connect(admin).approveTimeLock(1);
    await ethers.provider.send("evm_increaseTime", [3600]); // Fast forward 1 hour
    await governance.connect(admin).executeTimeLock(1);
    const timeLock = await governance.timeLocks(1);
    expect(timeLock.executed).to.be.true;
  });
  it("should subscribe and check status", async function () {
    await core.connect(patient).registerPatient("encryptedKey");
    await subscription.connect(patient).subscribe(0, { value: ethers.utils.parseEther("0.01") });
    const [isActive] = await subscription.getSubscriptionStatus(patient.address);
    expect(isActive).to.be.true;
  });
});
