import hashlib
import os
from config import SYSTEM_PERMISSIONS

class User:
    #initiating variables, giving none to password_hash and salt to be able to make new usures and load existing ones fro json files
    def __init__(self,username,role,password_hash=None,salt=None):
        self.username=username
        self.password_hash=password_hash
        self.salt=salt
        self.role=role
    #Takes a plain password, hashes it with a salt, and stores it
    def set_password(self,plain_password):
       # Generate a 16 byte random salt
       salt_bytes=os.urandom(16)
       # convert it to a hex string so we can save it to JSON later
       self.salt = salt_bytes.hex()
       #Hash the password using PBKDF2
       hashed_bytes=hashlib.pbkdf2_hmac(
           hash_name='sha256',
           password=plain_password.encode('utf-8'),
           salt=salt_bytes,               
           iterations=100_000,     
           dklen=32
       )
       #Convert the hash to a hex string and store it
       self.password_hash = hashed_bytes.hex()
    #Verifies if a typed password matches the stored hash.
    def check_password(self,password_guess):
        #Convert our stored hex salt back into raw bytes
        salt_bytes = bytes.fromhex(self.salt)
        #Hash the GUESS using the EXACT SAME salt
        guess_hash_bytes = hashlib.pbkdf2_hmac(
            hash_name='sha256',
            password=password_guess.encode('utf-8'),
            salt=salt_bytes,               
            iterations=100_000,     
            dklen=32
        )
        #Compare the guess hash with our saved hash string
        return self.password_hash == guess_hash_bytes.hex()
    
'''# --- TESTING BLOCK ---
if __name__ == "__main__":
    print("--- Testing Day 1: User Security Core ---")
    
    # 1. Simulate a user signing up
    print("Creating user 'alice_dev' with role 'DevOps'...")
    alice = User(username="alice_dev", role="DevOps")
    
    # 2. Set her password
    raw_password = "SuperSecretBankPassword123"
    alice.set_password(raw_password)
    
    # inside the function
    print(f"Stored Salt (Hex): {alice.salt}")
    print(f"Stored Hash (Hex): {alice.password_hash}")
    print("-" * 40)
    
    # 3. Test a WRONG password
    wrong_guess = "password123"
    print(f"Testing wrong password '{wrong_guess}':")
    is_valid = alice.check_password(wrong_guess)
    print(f"Access Granted? {is_valid} (Expected: False)")
    print("-" * 40)
    
    # 4. Test the RIGHT password
    right_guess = "SuperSecretBankPassword123"
    print(f"Testing correct password '{right_guess}':")
    is_valid = alice.check_password(right_guess)
    print(f"Access Granted? {is_valid} (Expected: True)") '''

class Resource:
    def __init__(self,name,parent_resource=None):
        self.name=name
        self.parent_resource=parent_resource

#check_hierarchy_permission function to be moved later 

def check_hierarchy_permission(role,resource,permission_map):
    if resource is None:
        return False
    else:
        exact_role = permission_map.get(role, [])
        if resource.name in exact_role:
            return True
        else:
            return check_hierarchy_permission(role,resource.parent_resource,permission_map)
        
'''# --- TESTING BLOCK ---
if __name__ == "__main__":
    from config import SYSTEM_PERMISSIONS
    print("===Resource Hierarchies ===")
    
    # 1. Create a deep hierarchy for the Intern's Sandbox
    sandbox_root = Resource("Local_Sandbox_Testing", parent_resource=None)
    project_folder = Resource("Alpha_Project_Files", parent_resource=sandbox_root)
    secret_mock_data = Resource("Alpha_Mock_DB", parent_resource=project_folder)
    
    # 2. Create a deep hierarchy for production data
    prod_root = Resource("Production_Cloud_Cluster", parent_resource=None)
    customer_db = Resource("Customer_Financial_Profiles", parent_resource=prod_root)
    
    # 3. Create our users matching the roles in config.py
    intern = User(username="intern_sam", role="Support_Intern")
    devops = User(username="devops_dan", role="DevOps_Engineer")
    
    print("\n--- Test Scenario 1: Intern accessing a deep subfolder in Sandbox ---")
    has_access = check_hierarchy_permission(intern.role, secret_mock_data, SYSTEM_PERMISSIONS)
    print(f"Can Intern access Alpha_Mock_DB? {has_access} (Expected: True)")
    
    print("\n--- Test Scenario 2: Intern trying to sneak into Production ---")
    has_access = check_hierarchy_permission(intern.role, customer_db, SYSTEM_PERMISSIONS)
    print(f"Can Intern access Customer_Financial_Profiles? {has_access} (Expected: False)")
    
    print("\n--- Test Scenario 3: DevOps accessing Production ---")
    has_access = check_hierarchy_permission(devops.role, customer_db, SYSTEM_PERMISSIONS)
    print(f"Can DevOps access Customer_Financial_Profiles? {has_access} (Expected: True)")'''

class StorageManager:
    def save_to_json(data,filename):
        pass
    def load_from_json(filename):
        pass