// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Insurance Data Registry with Consent & Access Control
/// @notice 僅存證加密資料的雜湊與URI；不儲存明文個資
contract InsuranceDataRegistry {
    // ===== 基本型別 =====
    enum DataType { Driving, Health, Other }

    struct Consent {
        bool active;            // 是否已取得用戶同意
        uint64 expiresAt;       // 同意到期時間(0 表示不設到期)
        string termsURI;        // 同意條款的對外連結(例如PDF/IPFS)
        bytes32 termsHash;      // 同意條款文件雜湊(防竄改)
    }

    struct DataRecord {
        DataType kind;          // 資料類型：行車/健康/其他
        bytes32 dataHash;       // 加密檔/原始資料的雜湊(例如Keccak-256/SHA-256)
        string uri;             // 外部加密資料位置(如 IPFS CID / S3), 不存明文
        bytes32 encKeyHint;     // 加密金鑰指示(如保險公司公鑰指紋/版本號)
        uint64 collectedAt;     // 資料蒐集時間(用戶/裝置端提供)
        uint64 storedAt;        // 上鏈時間(自動寫入)
        bool redacted;          // 是否已被用戶標示為「刪除/遮蔽」(鏈上不可移除，僅標記)
    }

    // ===== 權限與身分管理 =====
    address public owner;
    modifier onlyOwner() { require(msg.sender == owner, "Not owner"); _; }

    // 由平台/協會/監理機關等審核過的保險公司清單
    mapping(address => bool) public isInsurerVerified;

    // 用戶 -> (保險公司 -> 是否授權)
    mapping(address => mapping(address => bool)) public insurerApproval;

    // 用戶 -> (代理者 -> 是否被授權代為上傳，例如手機App/IoT閘道器)
    mapping(address => mapping(address => bool)) public agentApproval;

    // 用戶 -> (資料類型 -> 同意資訊)
    mapping(address => mapping(DataType => Consent)) public consents;

    // 用戶 -> 資料列表
    mapping(address => DataRecord[]) private userData;

    // ===== 事件(供稽核與追溯) =====
    event InsurerVerified(address indexed insurer, bool verified);
    event InsurerApprovalChanged(address indexed user, address indexed insurer, bool approved);
    event AgentApprovalChanged(address indexed user, address indexed agent, bool approved);

    event ConsentUpdated(
        address indexed user,
        DataType indexed kind,
        bool active,
        uint64 expiresAt,
        string termsURI,
        bytes32 termsHash
    );

    event DataRecorded(
        address indexed user,
        uint256 indexed index,
        DataType indexed kind,
        bytes32 dataHash,
        string uri,
        bytes32 encKeyHint,
        uint64 collectedAt
    );

    event DataRedacted(address indexed user, uint256 indexed index);

    constructor() {
        owner = msg.sender;
    }

    // ===== 平台層：設定通過審核之保險公司 =====
    function setInsurerVerified(address insurer, bool verified) external onlyOwner {
        isInsurerVerified[insurer] = verified;
        emit InsurerVerified(insurer, verified);
    }

    // ===== 用戶層：授權/撤銷 指定保險公司 可查閱我的資料 =====
    function setInsurerApproval(address insurer, bool approved) external {
        insurerApproval[msg.sender][insurer] = approved;
        emit InsurerApprovalChanged(msg.sender, insurer, approved);
    }

    // ===== 用戶層：授權/撤銷 代理者(裝置/APP) 代為上傳 =====
    function setAgentApproval(address agent, bool approved) external {
        agentApproval[msg.sender][agent] = approved;
        emit AgentApprovalChanged(msg.sender, agent, approved);
    }

    // ===== 用戶層：設定/更新 同意條款（依資料類型分流）=====
    function setConsent(
        DataType kind,
        bool active,
        uint64 expiresAt,
        string calldata termsURI,
        bytes32 termsHash
    ) external {
        consents[msg.sender][kind] = Consent({
            active: active,
            expiresAt: expiresAt,
            termsURI: termsURI,
            termsHash: termsHash
        });
        emit ConsentUpdated(msg.sender, kind, active, expiresAt, termsURI, termsHash);
    }

    // 查詢：同意是否仍有效
    function isConsentActive(address user, DataType kind) public view returns (bool) {
        Consent memory c = consents[user][kind];
        if (!c.active) return false;
        if (c.expiresAt != 0 && block.timestamp > c.expiresAt) return false;
        return true;
    }

    // ===== 上傳存證：由用戶本人或其代理者提交 =====
    function addDataRecord(
        address user,
        DataType kind,
        bytes32 dataHash,
        string calldata uri,
        bytes32 encKeyHint,
        uint64 collectedAt
    ) external {
        require(
            msg.sender == user || agentApproval[user][msg.sender],
            "Not user or authorized agent"
        );
        require(isConsentActive(user, kind), "Consent not active/expired");

        userData[user].push(
            DataRecord({
                kind: kind,
                dataHash: dataHash,
                uri: uri,
                encKeyHint: encKeyHint,
                collectedAt: collectedAt,
                storedAt: uint64(block.timestamp),
                redacted: false
            })
        );

        emit DataRecorded(
            user,
            userData[user].length - 1,
            kind,
            dataHash,
            uri,
            encKeyHint,
            collectedAt
        );
    }

    // 用戶可標示某筆資料為「遮蔽/刪除請求」(鏈上不可移除，只能標記+事件供鏈下遵循)
    function redactData(uint256 index) external {
        require(index < userData[msg.sender].length, "Index out of bounds");
        userData[msg.sender][index].redacted = true;
        emit DataRedacted(msg.sender, index);
    }

    // ===== 存取控制：保險公司在經用戶授權且通過平台審核後可查閱 =====
    function canAccess(address user, address caller) public view returns (bool) {
        if (caller == user) return true; // 本人永遠可查
        // 必須同時：用戶授權 + 保險公司通過平台審核
        return insurerApproval[user][caller] && isInsurerVerified[caller];
    }

    // 查詢：某用戶的資料數量（需具備存取權）
    function getUserDataCount(address user) external view returns (uint256) {
        require(canAccess(user, msg.sender), "No access");
        return userData[user].length;
    }

    // 查詢：某用戶第 index 筆資料（需具備存取權）
    function getUserDataAt(address user, uint256 index)
        external
        view
        returns (DataRecord memory)
    {
        require(canAccess(user, msg.sender), "No access");
        require(index < userData[user].length, "Index out of bounds");
        return userData[user][index];
    }

    // 方便查核：回傳用戶對某資料類型的 Consent 概要（需具備存取權或本人）
    function getConsent(address user, DataType kind)
        external
        view
        returns (Consent memory)
    {
        require(user == msg.sender || canAccess(user, msg.sender), "No access");
        return consents[user][kind];
    }
}
