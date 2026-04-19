from dotenv import load_dotenv
import os
from kaggle.api.kaggle_api_extended import KaggleApi

# load .env variables
load_dotenv()

# get credentials
username = os.getenv("KAGGLE_USERNAME")
key = os.getenv("KAGGLE_KEY")

# configure Kaggle
os.environ["KAGGLE_USERNAME"] = username
os.environ["KAGGLE_KEY"] = key

# authenticate
api = KaggleApi()
api.authenticate()

# download dataset
api.dataset_download_files(
    "wcukierski/enron-email-dataset",
    path="data/enron",
    unzip=True
)

print("Enron dataset downloaded.")