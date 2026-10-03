import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    backend_host: str = os.getenv("BACKEND_HOST", "0.0.0.0")
    backend_port: int = int(os.getenv("BACKEND_PORT", "8000"))
    debug: bool = os.getenv("DEBUG", "True").lower() == "true"

    qr_dataset_path: str = os.getenv("QR_DATASET_PATH", "data/qr")
    url_dataset_path: str = os.getenv("URL_DATASET_PATH", "data/url")

    ml_data_path: str = os.getenv("ML_DATA_PATH", "ml/data")
    ml_models_path: str = os.getenv("ML_MODELS_PATH", "ml/saved_models")


settings = Settings()
