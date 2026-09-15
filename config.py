import os
from dotenv import load_dotenv


# ==========================================
# LOAD ENVIRONMENT VARIABLES
# ==========================================

load_dotenv()


# ==========================================
# DATABASE SETTINGS
# ==========================================

DB_HOST = os.getenv(
    "MYSQLHOST",
    os.getenv(
        "DB_HOST",
        "localhost"
    )
)

DB_PORT = int(
    os.getenv(
        "MYSQLPORT",
        os.getenv(
            "DB_PORT",
            "3306"
        )
    )
)

DB_USER = os.getenv(
    "MYSQLUSER",
    os.getenv(
        "DB_USER",
        "root"
    )
)

DB_PASSWORD = os.getenv(
    "MYSQLPASSWORD",
    os.getenv(
        "DB_PASSWORD",
        ""
    )
)

DB_NAME = os.getenv(
    "MYSQLDATABASE",
    os.getenv(
        "DB_NAME",
        "student_portal"
    )
)


# ==========================================
# FLASK SECRET KEY
# ==========================================

SECRET_KEY = os.getenv(
    "SECRET_KEY",
    "development-secret-key"
)