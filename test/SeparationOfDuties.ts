import { expect } from "chai";
import { ethers } from "hardhat";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { HRABACPropertyRegistry } from "../typechain-types";

describe("HRABACPropertyRegistry - Separation of Duties (Access Control)", function () {
  let registry: HRABACPropertyRegistry;
  let admin: SignerWithAddress;
  let inspector: SignerWithAddress;
  let maliciousUser: SignerWithAddress;
  let newInspector: SignerWithAddress;

  // Mock test data accurately typed for EVM input parsing
  const dummyEpoch = ethers.keccak256(ethers.toUtf8Bytes("EPOCH_1"));
  
  // Array parameters for batch execution (emitEpochState)
  const dummyPropertyHashes = [ethers.keccak256(ethers.toUtf8Bytes("BG.SOFIA.001"))];
  const dummyCitizenHashes = [ethers.keccak256(ethers.toUtf8Bytes("CITIZEN_PID_SALT"))];
  const dummyOwnerCounts = [1]; // Explicitly an array of uint32 values
  const dummyShares = [ethers.parseUnits("100", 0)]; // Array of uint256 values

  // Single parameters extracted for specific targeted contract endpoints
  const targetProperty = dummyPropertyHashes[0];
  const targetCitizen = dummyCitizenHashes[0];
  const expectedShare = dummyShares[0];

  beforeEach(async function () {
    // Retrieve testing accounts
    [admin, inspector, maliciousUser, newInspector] = await ethers.getSigners();

    // Deploy the contract (admin automatically becomes the initial deploymentAdmin and government inspector)
    const HRABACPropertyRegistryFactory = await ethers.getContractFactory("HRABACPropertyRegistry");
    registry = await HRABACPropertyRegistryFactory.deploy();
    await registry.waitForDeployment();

    // Provision an official inspector account by the administrator
    await registry.connect(admin).registerInspector(inspector.address);
  });

  // --- 1. DEPLOYMENT ADMIN ROLES & PRIVILEGES (R_admin) ---
  describe("Role: Deployment Admin", function () {
    it("Should allow the admin to register a new inspector", async function () {
      await expect(registry.connect(admin).registerInspector(newInspector.address))
        .to.not.be.reverted;
      
      expect(await registry.governmentInspectors(newInspector.address)).to.be.true;
    });

    it("Should allow the admin to revoke an existing inspector", async function () {
      await expect(registry.connect(admin).revokeInspector(inspector.address))
        .to.not.be.reverted;

      expect(await registry.governmentInspectors(inspector.address)).to.be.false;
    });

    it("Should NOT allow the admin to emit data (emitEpochState) if inspector privileges are revoked", async function () {
      // Stripping inspector rights from the admin to isolate roles completely
      await registry.connect(admin).revokeInspector(admin.address);

      await expect(
        registry.connect(admin).emitEpochState(
          dummyEpoch,
          dummyPropertyHashes,
          dummyCitizenHashes,
          dummyOwnerCounts,
          dummyShares
        )
      ).to.be.revertedWithCustomError(registry, "UnauthorizedSender");
    });
  });

  // --- 2. GOVERNMENT INSPECTOR ROLES & PRIVILEGES (R_inspector) ---
  describe("Role: Government Inspector", function () {
    it("Should allow an authorized inspector to batch emit property records", async function () {
      await expect(
        registry.connect(inspector).emitEpochState(
          dummyEpoch,
          dummyPropertyHashes,
          dummyCitizenHashes,
          dummyOwnerCounts,
          dummyShares
        )
      ).to.emit(registry, "EpochStateEmitted");
    });

    it("Should allow an inspector to deactivate a property record", async function () {
      // Seed the state using arrays
      await registry.connect(inspector).emitEpochState(
        dummyEpoch, 
        dummyPropertyHashes, 
        dummyCitizenHashes, 
        dummyOwnerCounts, 
        dummyShares
      );

      // Execute targeted action using a single bytes32 parameter
      await expect(registry.connect(inspector).deactivateProperty(targetProperty))
        .to.emit(registry, "PropertyDeactivated");
    });

    it("Should allow an inspector to shred a single co-owner anchor for GDPR Article 17 compliance", async function () {
      await registry.connect(inspector).emitEpochState(
        dummyEpoch, 
        dummyPropertyHashes, 
        dummyCitizenHashes, 
        dummyOwnerCounts, 
        dummyShares
      );

      // Execute targeted action using single parameters
      await expect(registry.connect(inspector).revokeSingleOwnerAnchor(targetProperty, targetCitizen))
        .to.emit(registry, "OwnershipAnchorRevoked");
    });

    it("Should NOT allow an inspector to manage roles or provision other inspectors", async function () {
      await expect(
        registry.connect(inspector).registerInspector(newInspector.address)
      ).to.be.revertedWithCustomError(registry, "UnauthorizedSender");
    });
  });

  // --- 3. UNAUTHORIZED / MALICIOUS USER PROTECTION TESTS ---
  describe("Protection Against Unauthorized Access (Separation of Duties Validation)", function () {
    it("Should NOT allow an unprivileged user to register inspectors", async function () {
      await expect(
        registry.connect(maliciousUser).registerInspector(newInspector.address)
      ).to.be.revertedWithCustomError(registry, "UnauthorizedSender");
    });

    it("Should NOT allow an unprivileged user to execute batch data emissions", async function () {
      await expect(
        registry.connect(maliciousUser).emitEpochState(
          dummyEpoch,
          dummyPropertyHashes,
          dummyCitizenHashes,
          dummyOwnerCounts,
          dummyShares
        )
      ).to.be.revertedWithCustomError(registry, "UnauthorizedSender");
    });

    it("Should NOT allow an unprivileged user to deactivate property records", async function () {
      await registry.connect(inspector).emitEpochState(
        dummyEpoch, 
        dummyPropertyHashes, 
        dummyCitizenHashes, 
        dummyOwnerCounts, 
        dummyShares
      );

      await expect(
        registry.connect(maliciousUser).deactivateProperty(targetProperty)
      ).to.be.revertedWithCustomError(registry, "UnauthorizedSender");
    });

    it("Should NOT allow an unprivileged user to shred ownership tokens (GDPR bypass restriction)", async function () {
      await registry.connect(inspector).emitEpochState(
        dummyEpoch, 
        dummyPropertyHashes, 
        dummyCitizenHashes, 
        dummyOwnerCounts, 
        dummyShares
      );

      await expect(
        registry.connect(maliciousUser).revokeSingleOwnerAnchor(targetProperty, targetCitizen)
      ).to.be.revertedWithCustomError(registry, "UnauthorizedSender");
    });
  });

  // --- 4. ROLE-FREE PUBLIC VERIFICATION GATEWAY TESTS ---
  describe("Public Access (Role-Free Gateway Checking)", function () {
    it("Should allow any stateless external entity to successfully verify property ownership in O(1) time", async function () {
      // Publish the block using arrays
      await registry.connect(inspector).emitEpochState(
        dummyEpoch, 
        dummyPropertyHashes, 
        dummyCitizenHashes, 
        dummyOwnerCounts, 
        dummyShares
      );

      // Untrusted entity queries the view function using single identifiers
      const [isValidOwner, registeredShare] = await registry.connect(maliciousUser).verifyPropertyOwnership(
        targetProperty,
        targetCitizen
      );

      expect(isValidOwner).to.be.true;
      expect(registeredShare).to.equal(expectedShare);
    });
  });
});
