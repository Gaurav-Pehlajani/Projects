# Python program for checking password
import re
 
# Function that checks if a string 
# contains uppercase, lowercase 
# special character & numeric value 
def isAllPresent(password):
    regex = ("^(?=.*[a-z])(?=." +
             "*[A-Z])(?=.*\\d)" +
             "(?=.*[-+_!@#$%^&*., ?]).+$")
     
    # Compile the ReGex
    p = re.compile(regex)
 
    # If the string is empty 
    if (len(password)<8):
        print("Password must contain atleast 8 characters! ")
        return
 
    # Analyzing strength if the password
    # matches ReGex 
    if(re.search(p, password)):
        return True
    else:
        print("Paasowrd must conatain atleast 1 Lowercase, 1 Uppercase, 1 Digit, and 1 Special character!")
        return False


#Strength Checker
def check_strength(password):
    score=0
    if len(password)>8:
        score+=1
    if len(password)>=12:
        score+=1
    if not re.search(r'(.)\1{2,}', password):  # No three or more repeating characters
        score += 1
    if not re.search(r'012|123|234|345|456|567|678|789', password):  # No numeric sequence
        score += 1
    if not re.search(r'abc|bcd|cde|def|efg|fgh|ghi', password, re.I):  # No alphabetical sequence
        score +=1
        
    # Determine strength based on score
    if score <= 2:
        return "Weak"
    elif score == 3 or 4:
        return "Moderate"
    else:
        return "Strong"

#Time to Crack
def estimate_crack_time(password):
    char_set_size = (26 if re.search(r"[a-z]", password) else 0) + \
                    (26 if re.search(r"[A-Z]", password) else 0) + \
                    (10 if re.search(r"\d", password) else 0) + \
                    (32 if re.search(r"[-+_!@#$%^&*., ?]", password) else 0)
    
    total_combinations = char_set_size ** len(password)
    time_in_seconds = total_combinations / 1e7  # 10 million guesses per second
    time_in_hours = time_in_seconds / 3600
    
    return time_in_hours

# Looping until a valid password is entered
while True:
    password = input("Enter Password: ")

    if isAllPresent(password):
        strength = check_strength(password)
        crack_time_in_hours = estimate_crack_time(password)

        print(f"Password Strength: {strength}") 

        if crack_time_in_hours >= 24:
            crack_time_in_days = crack_time_in_hours / 24
            print(f"Estimated Time to Crack: {crack_time_in_days:.2f} days")
        else:
            print(f"Estimated Time to Crack: {crack_time_in_hours:.2f} hours")

        break