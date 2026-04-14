from dotenv import load_dotenv
import os
from pathlib import Path
from kaggle.api.kaggle_api_extended import KaggleApi

load_dotenv()

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data" / "enron"

username = os.getenv("KAGGLE_USERNAME")
key = os.getenv("KAGGLE_KEY")

os.environ["KAGGLE_USERNAME"] = username
os.environ["KAGGLE_KEY"] = key

api = KaggleApi()
api.authenticate()

api.dataset_download_files(
    "wcukierski/enron-email-dataset",
    path=str(DATA_DIR),
    unzip=True,
)

print("Enron dataset downloaded.")
