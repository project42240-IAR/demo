// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title  EvidenceLog
/// @notice Immutable on-chain proof-of-evidence registry for the
///         Fake Social Media Account Detection & Reporting platform
///         (PS-SW-003 compliance).
///
/// @dev    Design principles:
///           • No owner, no admin key, no upgradability proxy.
///           • No selfdestruct — entries are permanent by construction.
///           • Anyone with a funded account on the network can call
///             logEvidence(); restrict at the application layer (private key
///             management) rather than on-chain so the contract stays simple
///             and auditable.
///           • Gas cost per entry ≈ 80k–120k gas (dominated by string
///             storage); acceptable on a private/L2 testnet.
contract EvidenceLog {

    // ------------------------------------------------------------------ //
    // Data structures
    // ------------------------------------------------------------------ //

    struct EvidenceEntry {
        /// SHA-256 hash of the deterministically serialised case payload.
        /// Stored as bytes32 (256 bits); matches Python hashlib.sha256 output.
        bytes32 payloadHash;

        /// Human-readable case reference from the MongoDB cases collection.
        string  caseId;

        /// Social-media platform name, e.g. "Instagram", "X".
        string  platform;

        /// Detection engine verdict: "Likely Fake" | "Suspicious".
        string  verdict;

        /// The status value that triggered this log entry.
        /// Only "Escalated to Platform" and "Account Suspended" are ever sent.
        string  newStatus;

        /// Reviewer identity (name / email) from the X-Reviewer HTTP header.
        string  reviewer;

        /// Unix epoch timestamp set by the EVM at mining time (block.timestamp).
        /// Independent of the application server clock — cannot be backdated.
        uint256 timestamp;
    }

    /// @dev  Append-only array; indices are stable and never re-used.
    EvidenceEntry[] private _entries;

    // ------------------------------------------------------------------ //
    // Events
    // ------------------------------------------------------------------ //

    /// @notice Emitted for every successful logEvidence() call.
    /// @param  entryIndex   Position of the new entry in the _entries array.
    /// @param  payloadHash  SHA-256 of the case payload (indexed for fast filter).
    /// @param  caseId       Application-layer case reference.
    /// @param  newStatus    Status value that triggered this record.
    /// @param  timestamp    block.timestamp at the time of mining.
    event EvidenceLogged(
        uint256 indexed entryIndex,
        bytes32 indexed payloadHash,
        string          caseId,
        string          newStatus,
        uint256         timestamp
    );

    // ------------------------------------------------------------------ //
    // Write functions
    // ------------------------------------------------------------------ //

    /// @notice Append a new immutable evidence entry to the ledger.
    /// @param  payloadHash  SHA-256(deterministic JSON of sanitised case fields).
    /// @param  caseId       Case identifier from the detection platform.
    /// @param  platform     Social-media platform name.
    /// @param  verdict      Detection engine verdict string.
    /// @param  newStatus    New workflow status being committed.
    /// @param  reviewer     Identity of the reviewer authorising the action.
    /// @return entryIndex   Array index of the newly created entry.
    function logEvidence(
        bytes32        payloadHash,
        string calldata caseId,
        string calldata platform,
        string calldata verdict,
        string calldata newStatus,
        string calldata reviewer
    ) external returns (uint256 entryIndex) {
        entryIndex = _entries.length;
        _entries.push(
            EvidenceEntry({
                payloadHash : payloadHash,
                caseId      : caseId,
                platform    : platform,
                verdict     : verdict,
                newStatus   : newStatus,
                reviewer    : reviewer,
                timestamp   : block.timestamp
            })
        );
        emit EvidenceLogged(
            entryIndex,
            payloadHash,
            caseId,
            newStatus,
            block.timestamp
        );
    }

    // ------------------------------------------------------------------ //
    // Read functions (view — no gas cost when called off-chain)
    // ------------------------------------------------------------------ //

    /// @notice Retrieve a single evidence entry by its array index.
    /// @param  index  Zero-based index returned by logEvidence().
    function getEntry(uint256 index)
        external
        view
        returns (EvidenceEntry memory)
    {
        require(index < _entries.length, "EvidenceLog: index out of bounds");
        return _entries[index];
    }

    /// @notice Total number of evidence entries logged so far.
    function getCount() external view returns (uint256) {
        return _entries.length;
    }
}
