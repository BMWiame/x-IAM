import hashlib
import os
import hmac
from config import SYSTEM_PERMISSIONS
import json
from datetime import datetime

class User:
    #initiating variables, giving none to password_hash and salt to be able to make new usures and load existing ones fro json files
    def __init__(self,username,role,password=None,password_hash=None,salt=None):
        self.username=username
        self.password_hash=password_hash
        self.salt=salt
        self.role=role
        if password is not None:
            self.set_password(password)

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
        return hmac.compare_digest(self.password_hash, guess_hash_bytes.hex())
    
    #translator function
    def to_dict(self):
        dict_to_json = {
            "username": self.username,
            "role": self.role,
            "password_hash": self.password_hash,
            "salt": self.salt  
        }
        return dict_to_json

    


class Resource:
    def __init__(self,name,parent_resource=None):
        self.name=name
        self.parent_resource=parent_resource
    def to_dict(self):
        if self.parent_resource is not None:
            parent_dict = self.parent_resource.to_dict()
        else:
            parent_dict = None
        return {
            "name": self.name,
            "parent_resource": parent_dict
        }

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
        


class StorageManager:

    @staticmethod
    def save_objects_to_json(data, filename):
        converted_dictionaries = [obj.to_dict() for obj in data]
        with open(filename, "w") as file:
            json.dump(converted_dictionaries, file, indent=4, ensure_ascii=False)
        print(f"[Success] Saved data to {filename}")

    @staticmethod
    def load_objects_from_json(filename, from_dict_fn):
        try:
            with open(filename, "r") as file:
                data = json.load(file)
        except FileNotFoundError:
            print(f"[Warning] {filename} not found. Starting with an empty list.")
            return []
        except json.JSONDecodeError:
            print(f"[Error] {filename} is corrupted or invalid JSON. Starting with an empty list.")
            return []

        reconstituted = []
        for item_dict in data:
            reconstituted.append(from_dict_fn(item_dict))
        return reconstituted
    @staticmethod
    def user_from_dict(d):
        return User(
            username=d["username"],
            role=d["role"],
            password_hash=d["password_hash"],
            salt=d["salt"]
        )
    @staticmethod
    def resource_from_dict(d):
        if d is None:
            return None
        parent = StorageManager.resource_from_dict(d["parent_resource"])
        return Resource(name=d["name"], parent_resource=parent)
    
    @staticmethod
    def _load_users_indexed(filename):
        users = StorageManager.load_objects_from_json(filename, StorageManager.user_from_dict)
        return {u.username: u for u in users}

    

class AccessEngine:

    @staticmethod
    def authenticate(username, password, users_file="users.json"):
        users = StorageManager._load_users_indexed(users_file)
        user = users.get(username, None)
        if user is None:
            return False
        return user.check_password(password)

    @staticmethod
    def request_access(username, resource_object, users_file="users.json", log_file="audit_log.txt"):
        users = StorageManager._load_users_indexed(users_file)
        user = users.get(username, None)
        if user is None:
            AccessEngine.log_attempt(username, resource_object.name, False, log_file=log_file)
            return False
        else:
            success_status = check_hierarchy_permission(user.role, resource_object, SYSTEM_PERMISSIONS)
            AccessEngine.log_attempt(username, resource_object.name, success_status, log_file=log_file)
            return success_status
            
    @staticmethod
    def log_attempt(username, resource_name, success_status, log_file="audit_log.txt"):
        now=datetime.now()
        timestamp_str = now.strftime("%Y-%m-%d %H:%M:%S")

        if success_status:
            status_text = "ALLOWED"
        else:
            status_text = "DENIED"

        safe_username = username.replace("\n", "").replace("\r", "")
        safe_resource = resource_name.replace("\n", "").replace("\r", "")
        status= f"[{timestamp_str}] USER: {safe_username} | RESOURCE: {safe_resource} | STATUS: {status_text}\n"
        with open(log_file,"a") as f:
            f.write(status)

