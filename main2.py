from werkzeug.security import generate_password_hash, check_password_hash

# When registering:
hashed_pw = generate_password_hash("secret123")
print(hashed_pw)  # stored in DB

# When logging in:
print(check_password_hash(hashed_pw, "secret123"))  # True
print(check_password_hash(hashed_pw, "wrongpass"))  # False
