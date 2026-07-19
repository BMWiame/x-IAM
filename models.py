import hashlib
import os
from config import SYSTEM_PERMISSIONS
import json
from datetime import datetime

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
    
    #translator function
    def to_dict(self):
        dict_to_json = {
            "username": self.username,
            "role": self.role,
            "password_hash": self.password_hash,
            "salt": self.salt  
        }
        return dict_to_json

    
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

    @staticmethod
    def save_to_json(data,filename):
        converted_dictionaries=[]
        for user in data:
            converted_dictionaries.append(user.to_dict())
        
        with open(filename, "w") as file:
            json.dump(converted_dictionaries,file, indent=4, ensure_ascii=False)
        
        print(f"[Success] Saved data to {filename}")


    @staticmethod
    def load_from_json(filename):
        try:
            with open(filename,"r") as file:
                data=json.load(file)
        except FileNotFoundError:
            print(f"[Warning] {filename} not found. Starting with an empty list.")
            return []

        reconstituted_users = []

        for user_dict in data:

            user = User(
                username=user_dict["username"],
                role=user_dict["role"],
                password_hash=user_dict["password_hash"],
                salt=user_dict["salt"]
            )

            reconstituted_users.append(user)
        return reconstituted_users
    
'''# --- VERIFICATION TESTING ---*

if __name__ == "__main__":
    print("=== Day 3: Testing Storage Manager ===")
    
    # 1. Create fresh users
    user1 = User("alice_admin", "Admin")
    user1.set_password("AdminPass123!")
    
    user2 = User("bob_dev", "DevOps")
    user2.set_password("DevPass456!")
    
    runtime_users = [user1, user2]
    
    # 2. Save them to the hard drive
    print("\nSaving users to disk...")
    StorageManager.save_to_json(runtime_users, "users.json")
    
    # 3. Clear our active memory to simulate closing the app
    runtime_users = []
    print(f"Active memory cleared. Current users in memory: {runtime_users}")
    
    # 4. Load them back from the file
    print("\nLoading users back from disk...")
    loaded_users = StorageManager.load_from_json("users.json")
    
    # 5. Verify they are real Python objects with working methods again
    print(f"Loaded {len(loaded_users)} users successfully!")
    for u in loaded_users:
        print(f"-> User: {u.username} | Role: {u.role} | Has Hash: {bool(u.password_hash)}")
        
    # Check if the passwords still verify correctly
    print("\nVerifying Alice's restored security credentials...")
    is_valid = loaded_users[0].check_password("AdminPass123!")
    print(f"Password Check: {is_valid} (Expected: True)")'''
class AccessEngine:

    @staticmethod
    def authenticate(username, password):
        for user in StorageManager.load_from_json("users.json"):
            if username == user.username:
                return user.check_password(password)
        return False
    
    @staticmethod
    def request_access(username, resource_object):
        for user in StorageManager.load_from_json("users.json"):
            if username == user.username:
                success_status=check_hierarchy_permission(user.role,resource_object,SYSTEM_PERMISSIONS)

                AccessEngine.log_attempt(username, resource_object.name, success_status)

                return success_status
        
        AccessEngine.log_attempt(username, resource_object.name, False)
        return False
    @staticmethod
    def log_attempt(username, resource_name, success_status):
        now=datetime.now()
        timestamp_str = now.strftime("%Y-%m-%d %H:%M:%S")

        if success_status:
            status_text = "ALLOWED"
        else:
            status_text = "DENIED"
        status= f"[{timestamp_str}] USER: {username} | RESOURCE: {resource_name} | STATUS: {status_text}\n"
        with open("audit_log.txt","a") as f:
            f.write(status)

