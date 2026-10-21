# HRABAC Property Registry (ZTA-Reg-HRABAC) 🏠⛓️

A post-quantum resilient, structurally decoupled **Zero-Trust Architecture (ZTA)** designed for secure, constant-time real estate registry computations over cryptographically blinded asset parameters. 

This project implements the core blockchain layer of the **ZTA-Reg-HRABAC** framework proposed by Maria Penelova (Sofia University "St. Kliment Ohridski"). It addresses the computational trilemma dividing storage granularity, gas fee predictability, and strict compliance with European regulatory mandates such as the **NIS 2 Directive**, **eIDAS 2.0**, and **GDPR Article 17**.

---

## 🔬 Scientific & Architectural Context

Traditional Attribute-Based Access Control (ABAC) evaluations inside the Ethereum Virtual Machine (EVM) suffer from linear \(\mathcal{O}(N)\) or polynomial computational degradation due to runtime array traversals, exposing registries to block-gas-limit Denial-of-Service (DoS) exploits at scale. 

**ZTA-Reg-HRABAC** neutralizes this by compressing variable-length co-ownership configurations and shared equity matrices off-chain into uniform, fixed-length **32-byte cryptographic tokens** (`c_anchor`) via non-invertible Keccak-256 accumulation. 

As verified through extensive state-space modeling using the **TLA+ specification language and the TLC model checker**, this repository ensures:
* **Constant-Time \(\mathcal{O}(1)\) Persistence:** Bypasses sequential search paths using stateless nested memory lookups (`SLOAD` optimization).
* **Flat Gas Ceiling:** Evaluates complex ownership permissions at a completely predictable execution floor of exactly **32,365 gas units**, regardless of database saturation or co-owner density.
* **Zero-PII Storage:** Plaintext Personally Identifiable Information (PII) is isolated off-chain, satisfying GDPR "Right to Be Forgotten" compliance through edge-level cryptographic pre-image shredding.


---

## 🚀 Quick Start

Follow these steps to set up and run the project on your local machine:

### 1. Clone the Repository
```bash
git clone https://github.com/MGP-Ucict/HRABAC-Property-Registry
cd HRABAC-Property-Registry
```

### 2. Install Dependencies
The project relies on Node.js. Install the required packages by running:
```bash
npm install
```

### 3. Compile the Smart Contracts
Compile the Solidity contracts to bytecode:
```bash
npx hardhat compile
```

---

## 🧪 Testing & Development

The project comes with automated tests to verify the functionality and security of the smart contracts.

* **Run tests:**
  ```bash
  npx hardhat test
  ```
* **Run tests with a gas consumption report:**
  ```bash
  REPORT_GAS=true npx hardhat test
  ```
* **Start a local Ethereum node (Hardhat Network):**
  ```bash
  npx hardhat node
  ```

## 📁 Project Structure

* `contracts/` — Smart contracts written in Solidity.
* `ignition/modules/` — Deployment modules using Hardhat Ignition.
* `test/` — Automated scripts to test the contract logic.
* `hardhat.config.ts` — Main Hardhat configuration file (networks, compilers, plugins).
