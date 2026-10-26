# AWS S3 Forensic Evidence Storage & WORM Architecture Guide

This guide documents the enterprise cloud storage architecture, security controls, IAM policies, and Write-Once-Read-Many (WORM) Object Lock configuration for the **Automated Ransomware Containment & Incident Response Orchestrator**.

> [!IMPORTANT]
> In accordance with SOC least-privilege standards, **no live AWS resources are automatically provisioned by the application code**. All production infrastructure must be provisioned by authorized cloud administrators following the verified configuration steps below.

---

## 1. AWS S3 Evidence Bucket Creation (AWS Console Step-by-Step)

Follow these steps in the AWS Management Console to create a forensically sound, isolated evidence vault:

### Step 1: Bucket Naming & Region
1. Open the **Amazon S3 Console** at `https://console.aws.amazon.com/s3/`.
2. Click **Create bucket**.
3. **Bucket name**: Use a standardized, dedicated vault name such as:
   `secops-forensic-evidence-vault-<ACCOUNT_ID>-<REGION>`
   *(Bucket names must be globally unique across AWS)*.
4. **AWS Region**: Select your organization's primary SOC region (e.g., `us-east-1` or `eu-west-1`).

### Step 2: Object Ownership
1. Under **Object Ownership**, choose **ACLs disabled (recommended)**.
2. All objects in this bucket will be owned by the bucket owner account.

### Step 3: Block Public Access Settings (CRITICAL)
1. Check **Block all public access**.
2. Verify all four sub-options are enabled:
   * [x] Block public access to buckets and objects granted through new access control lists (ACLs)
   * [x] Block public access to buckets and objects granted through any access control lists (ACLs)
   * [x] Block public access to buckets and objects granted through new public bucket or access point policies
   * [x] Block public and cross-account access to buckets and objects through any public bucket or access point policies

### Step 4: Bucket Versioning
1. Under **Bucket Versioning**, select **Enable**.
2. *Note: Bucket versioning is mandatory to enable S3 Object Lock.*

### Step 5: S3 Object Lock (WORM Protection)
1. Under **Default encryption / Advanced settings**, expand **Object Lock**.
2. Choose **Enable**.
3. Acknowledge that Object Lock permanently prevents objects from being deleted or overwritten for a fixed retention period.

### Step 6: Server-Side Encryption
1. Under **Default encryption**:
   * **Encryption type**: Choose **Server-side encryption with Amazon S3 managed keys (SSE-S3)** (default, zero extra cost) OR **Server-side encryption with AWS Key Management Service keys (SSE-KMS)** for audit-logged cryptographic keys.
   * If using SSE-KMS, select a dedicated Customer Managed Key (CMK) configured with restricted key administrator policies.
   * **Bucket Key**: Choose **Enable** (reduces KMS request volume and latency).

2. Click **Create bucket**.

---

## 2. WORM Storage Guidance & S3 Object Lock Configuration

Write-Once-Read-Many (WORM) storage is required by legal standards (Federal Rules of Evidence Rule 902(14), ISO/IEC 27037) to guarantee that digital evidence cannot be tampered with or deleted by compromised credentials, rogue administrators, or ransomware threats.

### Retention Modes: COMPLIANCE vs GOVERNANCE

| Feature | GOVERNANCE Mode | COMPLIANCE Mode |
| :--- | :--- | :--- |
| **Tamper Resistance** | Protected against normal users; users with `s3:BypassGovernanceRetention` can delete or overwrite. | **Absolute protection**. No user—not even the AWS root account—can overwrite or delete the object during the retention period. |
| **Overriding Retention** | Allowed for authorized break-glass IAM roles. | **Forbidden**. AWS Support cannot delete or shorten retention. |
| **Recommended Usage** | Staging, dev, or operational logging. | **Production Forensic Evidence Vaults**. |

### Recommended Default Retention Setting
* **Default Retention Mode**: `COMPLIANCE`
* **Default Retention Period**: `365 Days` (1 Year) or `2555 Days` (7 Years) according to corporate incident response policy.

### Console Configuration for Default Object Lock:
1. In the S3 Console, select your evidence bucket.
2. Navigate to the **Properties** tab.
3. Scroll down to **Object Lock** and click **Edit**.
4. Enable **Default retention**.
5. Select **Compliance** mode.
6. Specify retention period: `365 Days`.
7. Click **Save changes**.

### Legal Hold
In addition to time-based retention, S3 Object Lock supports **Legal Hold**:
* An indefinite hold that prevents object modification until explicitly removed by legal counsel.
* Does not require a fixed expiration date.

---

## 3. Least-Privilege IAM Policies

The Orchestrator requires minimal IAM permissions to upload artifacts, compute checksums, and attach metadata. It must **never** possess administrative or deletion permissions.

### IAM Policy: Orchestrator Ingestion Role
Create an IAM Policy named `ForensicEvidenceUploaderPolicy`:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowEvidenceBucketLocation",
            "Effect": "Allow",
            "Action": [
                "s3:GetBucketLocation",
                "s3:ListBucket"
            ],
            "Resource": "arn:aws:s3:::secops-forensic-evidence-vault-*"
        },
        {
            "Sid": "AllowEvidenceUploadWithIntegrity",
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:GetObject",
                "s3:GetObjectAttributes"
            ],
            "Resource": "arn:aws:s3:::secops-forensic-evidence-vault-*/incidents/*"
        },
        {
            "Sid": "ExplicitDenyEvidenceDeletionAndRetentionBypass",
            "Effect": "Deny",
            "Action": [
                "s3:DeleteObject",
                "s3:DeleteObjectVersion",
                "s3:BypassGovernanceRetention",
                "s3:PutObjectRetention",
                "s3:PutBucketObjectLockConfiguration"
            ],
            "Resource": [
                "arn:aws:s3:::secops-forensic-evidence-vault-*",
                "arn:aws:s3:::secops-forensic-evidence-vault-*/*"
            ]
        }
    ]
}
```

### KMS Key Policy (If using SSE-KMS)
If encrypting with a customer managed KMS key:

```json
{
    "Effect": "Allow",
    "Action": [
        "kms:Encrypt",
        "kms:GenerateDataKey*"
    ],
    "Resource": "arn:aws:kms:us-east-1:123456789012:key/forensic-evidence-cmk"
}
```

---

## 4. Object Hierarchy & S3 Key Conventions

All evidence is organized by Incident ID and Collection Job ID:

```text
s3://<BUCKET_NAME>/incidents/<INCIDENT_ID>/evidence/<COLLECTION_JOB_ID>/<FILENAME>
```

### Example S3 Layout:
```text
s3://secops-forensic-evidence-vault/
└── incidents/
    ├── 1001/
    │   └── evidence/
    │       └── kape-a1b2c3d4/
    │           ├── kape_FINANCE-SRV-01_20261026.zip     # Forensic disk triage archive
    │           └── metadata.json                        # SHA-256 verified manifest
    └── 1002/
        └── evidence/
            └── ram-e5f6g7h8/
                ├── ram_ISOLATED-HOST_20261026.raw       # Memory image
                └── metadata.json                        # Companion manifest
```

---

## 5. Cryptographic Verification & Audit Trail

1. **Pre-Upload Hashing**:
   * The local evidence file is hashed via streaming chunks to produce a 64-character hexadecimal SHA-256 digest.
2. **Native S3 Checksum Algorithm**:
   * The upload request includes `ChecksumAlgorithm='SHA256'` and `ChecksumSHA256` Base64 header.
   * Amazon S3 computes the SHA-256 hash upon ingestion and rejects the payload if any bit flipped during transit.
3. **Post-Upload Verification**:
   * The orchestrator issues a `HeadObject` request with `ChecksumMode='ENABLED'`, decodes `ChecksumSHA256`, and compares it directly with the local pre-upload SHA-256 hash.
   * **Do not use ETag for SHA-256**: In Amazon S3, ETag represents MD5 for single-part uploads and a proprietary chunk-hash formula for multipart uploads. It is not cryptographic SHA-256.
4. **Manifest Audit Link**:
   * The companion `metadata.json` records:
     * `s3_bucket`: S3 bucket name.
     * `s3_object_key`: Exact object key.
     * `s3_checksum_sha256`: Verified SHA-256 hex digest.
     * `s3_checksum_verified`: `True` / `False`.
     * `s3_version_id`: S3 object version ID.
     * `s3_uploaded_at`: ISO 8601 UTC timestamp.
