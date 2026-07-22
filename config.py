SYSTEM_PERMISSIONS = {
    
    "Admin": [
        "Global_Infrastructure_Root",
        "Production_Cloud_Cluster",
        "Customer_Financial_Profiles",
        "Local_Sandbox_Testing",
        "Alpha_Mock_DB",
        "SIEM_Security_Logs",
        "Compliance_Audit_Vault",
        "Staging_Environment_Root",
        "Analytics_Data_Warehouse",
        "Customer_Metrics_S3",
        "HR_Records_Vault",
        "Finance_Reporting_Warehouse",
        "ML_Model_Registry",
        "Backup_Storage_Vault",
        "Network_Backbone_Root",
        "VPN_Gateway_Configs",
    ],

    # Cloud Admins: root infrastructure only.
    "Cloud_Admin": [
        "Global_Infrastructure_Root"
    ],

    # Cyber Security Analysts: security logs and compliance vaults.
    "Security_Analyst": [
        "SIEM_Security_Logs",
        "Compliance_Audit_Vault"
    ],

    # DevOps Engineers: deployment environments (Staging and Production).
    "DevOps_Engineer": [
        "Staging_Environment_Root",
        "Production_Cloud_Cluster"
    ],

    # Data Scientists: data warehouses, not raw infrastructure.
    "Data_Scientist": [
        "Analytics_Data_Warehouse",
        "Customer_Metrics_S3"
    ],

    # Support Interns: heavily restricted to temporary testing environments.
    "Support_Intern": [
        "Local_Sandbox_Testing"
    ],

    # Network Engineers: backbone and VPN configuration only.
    "Network_Engineer": [
        "Network_Backbone_Root",
        "VPN_Gateway_Configs"
    ],

    # Database Administrators: production data stores.
    "Database_Administrator": [
        "Production_Cloud_Cluster",
        "Customer_Financial_Profiles"
    ],

    # HR Managers: personnel records only.
    "HR_Manager": [
        "HR_Records_Vault"
    ],

    # Finance Analysts: financial reporting data only.
    "Finance_Analyst": [
        "Finance_Reporting_Warehouse"
    ],

    # QA Testers: staging environment only, no production access.
    "QA_Tester": [
        "Staging_Environment_Root"
    ],

    # Product Managers: read-only-style access to analytics.
    "Product_Manager": [
        "Analytics_Data_Warehouse"
    ],

    # ML Engineers: model registry plus the analytics warehouse it trains from.
    "ML_Engineer": [
        "Analytics_Data_Warehouse",
        "ML_Model_Registry"
    ],

    # Backup Operators: backup storage only, nothing live.
    "Backup_Operator": [
        "Backup_Storage_Vault"
    ],
}
