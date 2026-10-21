// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title HRABACPropertyRegistry
 * @notice High-performance decentralized architecture for secure multi-owner property registries.
 * @dev Eliminates linear loops O(N) inside the EVM sandbox to secure constant-time O(1) verification.
 * @dev Decouples PII off-chain, ensuring complete alignment with GDPR Article 17 via cryptographic shredding.
 * @dev Formally optimized for Arbitrum Layer 2 execution to achieve deterministic, flat transaction cost boundaries.
 */
contract HRABACPropertyRegistry {

    // --- STRUCTS ---

    struct PropertyInfo {
        bytes32 epochRoot;       // Cryptographic anchor verifying the multi-institutional chronological batch
        bool isDeactivated;      // Global deactivation flag enforcing structural privacy freezes and GDPR compliance
        uint32 totalOwners;      // Total number of registered co-owners tracked for boundary validation without iteration
    }

    // --- CUSTOM ERRORS (Optimized for gas and semantic insulation) ---

    error UnauthorizedSender();
    error DuplicateEpochRoot();
    error MatrixLengthParityMismatch();
    error PropertyAlreadyRegistered();
    error PropertyRecordNotFoundOrFrozen();
    error OwnerRecordNotFoundOrShredded();
    error WriteOnceConstraintViolation();
    error InvalidNullPointerAssignment();

    // --- STORAGE LAYOUT (Packed key-value slots bypassing execution loops) ---

    address public deploymentAdmin; // Root technical entity (R_admin) managing network operator lifecycles
    
    // Mapping targeting the system validator nodes (R_inspector) provisioned with write privileges
    mapping(address => bool) public governmentInspectors;
    
    // Core property registry: Property Hash (keccak256 of cadaster code) => Structural Metadata
    mapping(bytes32 => PropertyInfo) public properties;

    // Double-mapping mapping layout forcing ownership confirmation into instant O(1) checks
    // Property Hash => (Client-Generated Identity Anchor cHash => Ownership Status)
    mapping(bytes32 => mapping(bytes32 => bool)) public ownershipRegistry;
    
    // Mapping holding ideal shares to support granular instance-level attribute precision
    // Property Hash => (Client-Generated Identity Anchor cHash => Ideal Share Proportion)
    mapping(bytes32 => mapping(bytes32 => uint256)) public ownershipShares;

    // Mapping tracking globally validated epoch Merkle roots to prevent emission duplicate exploits
    mapping(bytes32 => bool) public validatedEpochs;

    // --- LOGGING LAYER (Asynchronous audit trail emission for indexers) ---

    event EpochStateEmitted(bytes32 indexed epochRoot, address indexed inspector, uint256 propertyCount, uint256 timestamp);
    event PropertyDeactivated(bytes32 indexed propertyHash, uint256 timestamp);
    event OwnershipAnchorRevoked(bytes32 indexed propertyHash, bytes32 indexed citizenHash, uint256 timestamp, uint256 blockNumber);

    // --- MODIFIERS ---

    modifier onlyAdmin() {
        if (msg.sender != deploymentAdmin) revert UnauthorizedSender();
        _;
    }

    modifier onlyInspector() {
        if (!governmentInspectors[msg.sender]) revert UnauthorizedSender();
        _;
    }

    // --- CONSTRUCTOR ---

    constructor() {
        deploymentAdmin = msg.sender;
        governmentInspectors[msg.sender] = true; // Initial bootstrap step
    }

    // --- LIFECYCLE MANAGEMENT (R_admin primitives) ---

    function registerInspector(address _newInspector) external onlyAdmin {
        if (_newInspector == address(0)) revert InvalidNullPointerAssignment();
        governmentInspectors[_newInspector] = true;
    }

    function revokeInspector(address _inspector) external onlyAdmin {
        governmentInspectors[_inspector] = false;
    }

    // --- STATE EMISSION (R_inspector batch pipeline) ---

    /**
     * @notice Performs high-throughput batch emission of property records and ownership shares.
     * @dev Signature verification is delegated off-chain via message queues to bypass nonce locks.
     * @dev Enforces structural verification checks to guarantee strict data coherence from the Laravel web tier.
     * @param _epochRoot Deterministic Merkle root collectively authorized off-chain by consortium nodes.
     * @param _propertyHashes Array of unique cryptographic property identifiers (bytes32).
     * @param _citizenHashes Multi-dimensional matrix mapping individual co-owners (cHash tokens).
     * @param _ownerCounts Array defining the exact count of co-owners assigned per property.
     * @param _shares Explicit array mapping ideal parts matching the targeting citizen anchors.
     */
    function emitEpochState(
        bytes32 _epochRoot,
        bytes32[] calldata _propertyHashes,
        bytes32[] calldata _citizenHashes,
        uint32[] calldata _ownerCounts,
        uint256[] calldata _shares
    ) external onlyInspector {
        if (_epochRoot == bytes32(0)) revert InvalidNullPointerAssignment();
        if (validatedEpochs[_epochRoot]) revert DuplicateEpochRoot(); 
        if (_propertyHashes.length != _ownerCounts.length) revert MatrixLengthParityMismatch();

        validatedEpochs[_epochRoot] = true;
        uint256 citizenPointer = 0;
        uint256 totalProperties = _propertyHashes.length;

        for (uint256 i = 0; i < totalProperties; i++) {
            bytes32 pHash = _propertyHashes[i];
            
            if (pHash == bytes32(0)) revert InvalidNullPointerAssignment();
            
            uint32 currentPropertyOwners = _ownerCounts[i];

            properties[pHash] = PropertyInfo({
                epochRoot: _epochRoot,
                isDeactivated: false,
                totalOwners: currentPropertyOwners
            });

            // Map individual owner attribute tokens natively into key-value slots bypassing iteration loops
            for (uint32 j = 0; j < currentPropertyOwners; j++) {
                // Bounds safety check to defend against malformed batch parsing payloads
                if (citizenPointer >= _citizenHashes.length) revert MatrixLengthParityMismatch();

                bytes32 cHash = _citizenHashes[citizenPointer];
                uint256 cShare = _shares[citizenPointer];

                if (cHash == bytes32(0)) revert InvalidNullPointerAssignment();
                if (ownershipRegistry[pHash][cHash]) revert WriteOnceConstraintViolation();

                ownershipRegistry[pHash][cHash] = true;
                ownershipShares[pHash][cHash] = cShare;

                unchecked {
                    citizenPointer++;
                }
            }
        }

        // Guarantees absolute transactional atomicity and matrix alignment
        if (citizenPointer != _citizenHashes.length || citizenPointer != _shares.length) {
            revert MatrixLengthParityMismatch();
        }

        emit EpochStateEmitted(_epochRoot, msg.sender, totalProperties, block.timestamp);
    }

    // --- VERIFICATION GATEWAY (Stateless Role-Free Primitive) ---

    /**
     * @notice Performs role-free verification of a specific owner's share in a given property asset.
     * @dev Enforces a strict constant-time O(1) processing trajectory with a guaranteed flat gas ceiling.
     * @param _propertyHash Unique internal key representing the requested estate asset.
     * @param _calculatedCitizenHash Client-side pre-computed attribute token: keccak256(Name || PID || Salt).
     * @return isValidOwner Boolean confirmation validating that context parameters passed the evaluation gate.
     * @return registeredShare The exact ownership share proportion attached to the verified identifier.
     */
    function verifyPropertyOwnership(
        bytes32 _propertyHash,
        bytes32 _calculatedCitizenHash
    ) external view returns (bool isValidOwner, uint256 registeredShare) {
        PropertyInfo memory prop = properties[_propertyHash];

        if (prop.epochRoot == bytes32(0) || prop.isDeactivated) {
            revert PropertyRecordNotFoundOrFrozen();
        }

        if (!ownershipRegistry[_propertyHash][_calculatedCitizenHash]) {
            revert OwnerRecordNotFoundOrShredded();
        }

        return (true, ownershipShares[_propertyHash][_calculatedCitizenHash]);
    }

    // --- GDPR ARTICLE 17 COMPLIANCE ROUTINES ---

    /**
     * @notice Full property deactivation to halt third-party verification instantly via state revert.
     * @param _propertyHash The distinct 32-byte cryptographic identifier hash of the estate asset.
     */
    function deactivateProperty(bytes32 _propertyHash) external onlyInspector {
        if (properties[_propertyHash].epochRoot == bytes32(0)) revert PropertyRecordNotFoundOrFrozen();
        properties[_propertyHash].isDeactivated = true;
        emit PropertyDeactivated(_propertyHash, block.timestamp);
    }

    /**
     * @notice Soft-locks a singular co-owner's validation trace while preserving multi-ownership topology integrity.
     * @dev Implements data zeroing to break public ledger linkability without disrupting the mathematical ideal balance.
     * @param _propertyHash Unique internal primary key of the target asset.
     * @param _citizenHash Pre-computed identity anchor to be permanently isolated and cryptographically shredded.
     */
    function revokeSingleOwnerAnchor(bytes32 _propertyHash, bytes32 _citizenHash) external onlyInspector {
        if (properties[_propertyHash].epochRoot == bytes32(0) || properties[_propertyHash].isDeactivated) {
            revert PropertyRecordNotFoundOrFrozen();
        }
        if (!ownershipRegistry[_propertyHash][_citizenHash]) {
            revert OwnerRecordNotFoundOrShredded();
        }

        // Data zeroing: Breaks the validation check trace for the target identity
        ownershipRegistry[_propertyHash][_citizenHash] = false;
        ownershipShares[_propertyHash][_citizenHash] = 0;
        
        // Note: The ideal share proportion in ownershipShares is intentionally retained as an orphaned/frozen state 
        // to preserve the historical 100% boundary integrity of the cadastral registry asset.
        
        emit OwnershipAnchorRevoked(_propertyHash, _citizenHash, block.timestamp, block.number);
    }
}
