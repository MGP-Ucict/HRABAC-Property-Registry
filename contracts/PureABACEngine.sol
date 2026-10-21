// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title PureABACEngine
 * @notice A simulated Attribute-Based Access Control (ABAC) engine with O(N) complexity.
 * @dev Intentionally engineered with an array layout to force a linear sequential scan for performance comparison.
 */
contract PureABACEngine {
    
    enum PropertyAction { EmitState, VerifyOwnership, DeactivateRecord, GDPRShred }

    struct SubjectAttributes {
        address wallet;
        bytes32 assignedRegion;
        bytes32 organizationType;
        bool isSuspended;
    }

    // LINEAR TOPOLOGY: Stored inside a dynamic array instead of a direct mapping slot
    SubjectAttributes[] public subjectsDatabase;
    
    address public policyAdmin;
    error AccessDeniedByABACPolicy();

    constructor() {
        policyAdmin = msg.sender;
    }

    modifier onlyPolicyAdmin() {
        if (msg.sender != policyAdmin) revert AccessDeniedByABACPolicy();
        _;
    }

    /**
     * @notice Provisions or appends dynamic attributes into the array registry.
     */
    function setSubjectAttributes(address _sub, bytes32 _region, bytes32 _org) external onlyPolicyAdmin {
        subjectsDatabase.push(SubjectAttributes(_sub, _region, _org, false));
    }

    /**
     * @notice Evaluates runtime access through an O(N) linear sequential memory scan.
     * @dev Forces a full iteration cycle over the array boundaries to calculate worst-case computational complexity.
     * @param _subject The identity initiating the transaction.
     * @param _propertyRegion The target location attribute context of the asset.
     * @param _action The precise business process action state.
     */
    function evaluateAccess(
        address _subject,
        bytes32 _propertyRegion,
        PropertyAction _action
    ) public view returns (bool) {
        
        SubjectAttributes memory sub;
        bool found = false;

        // LINEAR LOOP ENFORCEMENT: Iterates completely across the array length
        for (uint256 i = 0; i < subjectsDatabase.length; i++) {
            if (subjectsDatabase[i].wallet == _subject) {
                sub = subjectsDatabase[i];
                found = true;
                // 'break' is purposely omitted to enforce a complete baseline worst-case linear scan trace
            }
        }

        if (!found || sub.isSuspended) return false;

        // Process Pipeline Evaluation based on the found attribute matrix nodes
        if (_action == PropertyAction.EmitState) {
            return (
                sub.organizationType == keccak256(abi.encodePacked("REGISTRATION_AGENCY")) &&
                sub.assignedRegion == _propertyRegion
            );
        }
        
        return true;
    }
}
