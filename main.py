from models import AccessEngine, StorageManager, Resource
from config import SYSTEM_PERMISSIONS 

prod_root = Resource("Production_Cloud_Cluster")
customer_db = Resource("Customer_Financial_Profiles", parent_resource=prod_root)

sandbox_root = Resource("Local_Sandbox_Testing")
mock_db = Resource("Alpha_Mock_DB", parent_resource=sandbox_root)


RESOURCES = {
    "Production_Cloud_Cluster": prod_root,
    "Customer_Financial_Profiles": customer_db,
    "Local_Sandbox_Testing": sandbox_root,
    "Alpha_Mock_DB": mock_db
}
current_user=None

while True:
    print("\n=== IAM ACCESS ENGINE ===")
    print(f"Active Session: {current_user if current_user else 'None (Logged Out)'}")
    print("1. Login")
    print("2. Request Resource Access")
    print("3. View Audit Log (Admin Only)")
    print("4. Exit")
    
    choice = input("\nSelect an option (1-4): ").strip()

    if choice=="1":
        username=input("enter your username: ")
        password=input("enter your password: ")

        if AccessEngine.authenticate(username,password):
            current_user = username
            print(f"\n[Success] Welcome back, {current_user}!")
        else:
            current_user = None
            print("\n[Error] Invalid username or password.")

    elif choice=="2":
        if not current_user:
            print("\n[Denied] You must log in first!")
            continue
            
        resource_name = input("Enter resource name: ").strip()
        resource_obj = RESOURCES.get(resource_name)

        if not resource_obj:
            print(f"\n[Error] Resource '{resource_name}' does not exist.")
            continue
            
        allowed = AccessEngine.request_access(current_user, resource_obj)
        if allowed:
            print(f"\n[ACCESS GRANTED] You have permission to view {resource_name}.")
        else:
            print(f"\n[ACCESS DENIED] Your role cannot access {resource_name}.")

    elif choice == "3":
        if not current_user:
            print("\n[Denied] You must log in first!")
            continue
            
        # Find active user object to check their role
        active_users = StorageManager.load_objects_from_json("users.json", StorageManager.user_from_dict)
        user_obj = next((u for u in active_users if u.username == current_user), None)
        
        #Role check for Admin privileges
        if not user_obj or user_obj.role != "Admin":
            print("\n[Denied] Admin privileges required to view audit logs.")
            continue
            
        #Handling missing log file
        try:
            with open("audit_log.txt", "r") as log_file:
                print("\n--- SYSTEM AUDIT LOG ---")
                print(log_file.read().strip())
                print("------------------------")
        except FileNotFoundError:
            print("\n[Warning] No audit log file exists yet.")


    elif choice == "4":
        print("\nShutting down IAM Engine. Goodbye!")
        break
        
    else:
        #Invalid menu option typed
        print("\n[Error] Invalid selection. Please enter a number from 1 to 4.")