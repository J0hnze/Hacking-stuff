import os
import json
import requests
import unidecode
import pandas as pd
from faker import Faker
from PIL import Image
from io import BytesIO
import random

# Mapping region names to i18n locales
REGION_LOCALE_MAP = {
    "US": "en_US", "USA": "en_US",
    "UK": "en_GB", "United Kingdom": "en_GB",
    "France": "fr_FR",
    "Germany": "de_DE",
    "Spain": "es_ES",
    "Italy": "it_IT",
    "Canada": "en_CA",
    "Australia": "en_AU",
    "India": "en_IN"
}

# Get user input
region_input = input("Enter region (e.g., US, UK, Germany, France): ").strip()
num_profiles = int(input("How many profiles to generate? (Default: 1): ") or 1)

# Determine correct locale
region = REGION_LOCALE_MAP.get(region_input, "en_US")  # Default to en_US if unknown
print(f"Using locale: {region}")

# Initialize Faker with the detected region locale
fake = Faker(region)

# Function to remove non-ASCII characters
def clean_text(text):
    return unidecode.unidecode(text)

# Generate Fake Identity
def generate_fake_identity():
    gender = random.choice(["male", "female"]) if num_profiles > 1 else input("Enter gender (male/female): ").strip().lower()
    
    if gender == "male":
        name = clean_text(fake.name_male())
    else:
        name = clean_text(fake.name_female())

    age = fake.random_int(min=21, max=100)
    dob = fake.date_of_birth(minimum_age=21, maximum_age=100).strftime("%Y-%m-%d")

    profile = {
        "name": name,
        "gender": gender,
        "age": age,
        "dob": dob,
        "phone": fake.phone_number(),
        "address": clean_text(fake.address()),
        "occupation": clean_text(fake.job()),
        "job_history": generate_job_history(age)
    }
    return profile

# Generate Fake Job History (Last 5 Years)
def generate_job_history(age):
    job_history = []
    current_year = 2025  # Set current year manually

    # Ensure realistic start age for work
    start_year = max(current_year - 5, 18)
    
    for year in range(start_year, current_year):
        job_history.append({
            "year": year,
            "company": clean_text(fake.company()),
            "position": clean_text(fake.job()),
            "location": clean_text(fake.city())
        })
    
    return job_history

# Get AI Image by Gender and Region
def get_gendered_image(save_folder, gender):
    search_query = f"{gender} person from {region_input}"
    image_url = f"https://source.unsplash.com/featured/?{search_query}"  # Uses Unsplash API
    
    response = requests.get(image_url)
    
    if response.status_code == 200:
        image_path = os.path.join(save_folder, "profile.jpg")
        image = Image.open(BytesIO(response.content))
        image.save(image_path)
        print(f"Saved AI-generated image: {image_path}")
    else:
        print("Failed to retrieve AI image.")

# Save Profile Data
def save_profile(profile, save_folder):
    os.makedirs(save_folder, exist_ok=True)
    profile_path = os.path.join(save_folder, "profile.json")

    with open(profile_path, "w") as f:
        json.dump(profile, f, indent=4)
    
    print(f"Saved profile data: {profile_path}")

# Save Profiles to CSV
def save_to_csv(profiles):
    df = pd.DataFrame(profiles)
    df.to_csv("profiles.csv", index=False)
    print("All profiles saved to profiles.csv")

# Main Execution
def main():
    profiles_list = []

    for i in range(num_profiles):
        profile = generate_fake_identity()
        save_folder = f"./sock_puppets/{profile['name'].replace(' ', '_')}"
        
        save_profile(profile, save_folder)
        # get_gendered_image(save_folder, profile['gender'])
        profiles_list.append({
            "Name": profile["name"],
            "Gender": profile["gender"],
            "Age": profile["age"],
            "DOB": profile["dob"],
            "Email": profile["email"],
            "Phone": profile["phone"],
            "Address": profile["address"],
            "Occupation": profile["occupation"]
        })

    save_to_csv(profiles_list)

if __name__ == "__main__":
    main()
