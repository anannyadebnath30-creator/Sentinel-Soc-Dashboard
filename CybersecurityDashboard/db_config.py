
import os
import mysql.connector


def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", ""),
        database="sentinel_soc"
    )
