import hashlib
import os

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
    
# --- TESTING BLOCK ---
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
    print(f"Access Granted? {is_valid} (Expected: True)")