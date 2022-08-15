#Cynthia Zhu
#Professor Krzyzanowski
#Computer Security (01:198:419:02)
#February 20, 2022

#Project 1

import pickle
from sys import argv
from collections import defaultdict

user_password = defaultdict(str)
domain_users = defaultdict(list)
type_objects = defaultdict(list)
operation_domain_type = defaultdict(list)

def print_success():
    print("Success")

def print_missing_command():
    print("Error: Missing command")

def print_invalid(x):
    print("Error: Invalid " + x)

def print_too_few_arguments():
    print("Error: Too few arguments")

def print_too_many_arguments():
    print("Error: Too many arguments")

def print_user_exists():
    print("Error: User already exists")

def print_not_found(x):
    print("Error: " + x + " not found")

def print_incorrect_password():
    print("Error: Incorrect password")

def print_access_denied():
    print("Error: Access denied")

#auth.py AddUser user password
def add_user():
    global user_password
    if len(argv) < 4:
        print_too_few_arguments()
        return
    if len(argv) > 4:
        print_too_many_arguments()
        return
    user = argv[2]
    if user == "":
        print_invalid("username")
        return
    password = argv[3]
    if user in user_password:
        print_user_exists()
        return
    user_password[user] = password
    print_success()

#auth.py Authenticate user password
def authenticate():
    global user_password
    if len(argv) < 4:
        print_too_few_arguments()
        return
    if len(argv) > 4:
        print_too_many_arguments()
        return
    user = argv[2]
    if user == "":
        print_invalid("username")
        return
    password = argv[3]
    if user not in user_password:
        print_not_found("User")
        return
    if user_password[user] == password:
        print_success()
    else:
        print_incorrect_password()

#auth.py SetDomain user domain
def set_domain():
    global user_password
    global domain_users
    if len(argv) < 4:
        print_too_few_arguments()
        return
    if len(argv) > 4:
        print_too_many_arguments()
        return
    user = argv[2]
    if user == "":
        print_invalid("username")
        return
    domain = argv[3]
    if domain == "":
        print_invalid("domain")
        return
    if user not in user_password:
        print_not_found("User")
        return
    if user not in domain_users[domain]:
        domain_users[domain].append(user)
    print_success()

#auth.py DomainInfo domain
def domain_info():
    global domain_users
    if len(argv) < 3:
        print_too_few_arguments()
        return
    if len(argv) > 3:
        print_too_many_arguments()
        return
    domain = argv[2]
    if domain == "":
        print_invalid("domain")
        return
    if domain in domain_users and len(domain_users[domain]) > 0:
        for user in domain_users[domain]:
            print(user)

#auth.py SetType object type
def set_type():
    global type_objects
    if len(argv) < 4:
        print_too_few_arguments()
        return
    if len(argv) > 4:
        print_too_many_arguments()
        return
    object = argv[2]
    if object == "":
        print_invalid("object")
        return
    type = argv[3]
    if type == "":
        print_invalid("type")
        return
    if object not in type_objects[type]:
        type_objects[type].append(object)
    print_success()

#auth.py TypeInfo type
def type_info():
    global type_objects
    if len(argv) < 3:
        print_too_few_arguments()
        return
    if len(argv) > 3:
        print_too_many_arguments()
        return
    type = argv[2]
    if type == "":
        print_invalid("type")
        return
    if type in type_objects and len(type_objects[type]) > 0:
        for object in type_objects[type]:
            print(object)

#auth.py AddAccess operation domain type
def add_access():
    global domain_users
    global type_objects
    global operation_domain_type
    if len(argv) < 5:
        print_too_few_arguments()
        return
    if len(argv) > 5:
        print_too_many_arguments()
        return
    operation = argv[2]
    if operation == "":
        print_invalid("operation")
        return
    domain = argv[3]
    if domain == "":
        print_invalid("domain")
        return
    type = argv[4]
    if type == "":
        print_invalid("type")
        return
    if domain not in domain_users:
        domain_users[domain]
    if type not in type_objects:
        type_objects[type]
    if (domain, type) not in operation_domain_type[operation]:
        operation_domain_type[operation].append((domain, type))
    print_success()

#auth.py CanAccess operation user object
def can_access():
    global user_password
    global domain_users
    global type_objects
    global operation_domain_type
    if len(argv) < 5:
        print_too_few_arguments()
        return
    if len(argv) > 5:
        print_too_many_arguments()
        return
    operation = argv[2]
    if operation == "":
        print_invalid("operation")
        return
    user = argv[3]
    if user == "":
        print_invalid("username")
        return
    object = argv[4]
    if object == "":
        print_invalid("object")
        return
    if operation not in operation_domain_type:
        print_not_found("Operation")
        return
    if user not in user_password:
        print_not_found("User")
        return
    if object not in set().union(*type_objects.values()):
        print_not_found("Object")
        return
    domains = []
    for d in domain_users:
        if user in domain_users[d]:
            domains.append(d)
    types = []
    for t in type_objects:
        if object in type_objects[t]:
            types.append(t)
    for d in domains:
        for t in types:
            if (d, t) in operation_domain_type[operation]:
                print_success()
                return
    print_access_denied()

def read_command():
    if len(argv) == 1:
        print_missing_command()
        return
    command = argv[1]
    if command == "AddUser":
        add_user()
    elif command == "Authenticate":
        authenticate()
    elif command == "SetDomain":
        set_domain()
    elif command == "DomainInfo":
        domain_info()
    elif command == "SetType":
        set_type()
    elif command == "TypeInfo":
        type_info()
    elif command == "AddAccess":
        add_access()
    elif command == "CanAccess":
        can_access()
    else:
        print_invalid("command")
    return

def import_data():
    global user_password
    global domain_users
    global type_objects
    global operation_domain_type
    try:
        with open("user_password.pickle", "rb") as user_password_input_file:
            user_password = pickle.load(user_password_input_file)
    except FileNotFoundError:
        pass
    try:
        with open("domain_users.pickle", "rb") as domain_users_input_file:
            domain_users = pickle.load(domain_users_input_file)
    except FileNotFoundError:
        pass
    try:
        with open("type_objects.pickle", "rb") as type_objects_input_file:
            type_objects = pickle.load(type_objects_input_file)
    except FileNotFoundError:
        pass
    try:
        with open("operation_domain_type.pickle", "rb") as operation_domain_type_input_file:
            operation_domain_type = pickle.load(operation_domain_type_input_file)
    except FileNotFoundError:
        pass
    return

def export_data():
    global user_password
    global domain_users
    global type_objects
    global operation_domain_type
    with open("user_password.pickle", "wb") as user_password_output_file:
        pickle.dump(user_password, user_password_output_file, pickle.HIGHEST_PROTOCOL)
    with open("domain_users.pickle", "wb") as domain_users_output_file:
        pickle.dump(domain_users, domain_users_output_file, pickle.HIGHEST_PROTOCOL)
    with open("type_objects.pickle", "wb") as type_objects_output_file:
        pickle.dump(type_objects, type_objects_output_file, pickle.HIGHEST_PROTOCOL)
    with open("operation_domain_type.pickle", "wb") as operation_domain_type_output_file:
        pickle.dump(operation_domain_type, operation_domain_type_output_file, pickle.HIGHEST_PROTOCOL)
    return

def main():
    import_data()
    read_command()
    export_data()

if __name__ == "__main__":
    main()
