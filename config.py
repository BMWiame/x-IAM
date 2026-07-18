SYSTEM_PERMISSIONS = {
    # 1. Cloud Admins: Can access the absolute root infrastructure
    "Cloud_Admin": [
        "Global_Infrastructure_Root"
    ],
    
    # 2. Cyber Security Analysts: Need access to security logs and compliance vaults
    "Security_Analyst": [
        "SIEM_Security_Logs", 
        "Compliance_Audit_Vault"
    ],
    
    # 3. DevOps Engineers: Need access to deployment environments (Staging and Production)
    "DevOps_Engineer": [
        "Staging_Environment_Root", 
        "Production_Cloud_Cluster"
    ],
    
    # 4. Data Scientists: Need access to data warehouses, but NOT raw infrastructure
    "Data_Scientist": [
        "Analytics_Data_Warehouse", 
        "Customer_Metrics_S3"
    ],
    
    # 5. Support Interns: Heavily restricted to temporary testing environments
    "Support_Intern": [
        "Local_Sandbox_Testing"
    ]
}