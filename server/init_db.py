
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
SCHEMA_FILE = BASE_DIR / "schema.sql"
DATABASE_FILE = BASE_DIR / "trustvault.db"


def initialize_database():
    if not SCHEMA_FILE.exists():
        raise FileNotFoundError(
            f"Schema file not found: {SCHEMA_FILE}"
        )

    connection = sqlite3.connect(DATABASE_FILE)

    try:
        connection.execute("PRAGMA foreign_keys = ON")

        schema = SCHEMA_FILE.read_text(encoding="utf-8")
        connection.executescript(schema)
        connection.commit()

        print("TrustVault database initialized successfully.")
        print(f"Database location: {DATABASE_FILE}")

        tables = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
            ORDER BY name
            """
        ).fetchall()

        print("\nTables created:")
        for (table_name,) in tables:
            print(f"- {table_name}")

    finally:
        connection.close()


if __name__ == "__main__":
    initialize_database()
