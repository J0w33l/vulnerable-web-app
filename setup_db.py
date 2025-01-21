import sqlite3

def setup_db():
    db_path = "example.db"
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Create users table if it doesn't exist
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT
        )
    """)

    # Insert default users
    cursor.execute("SELECT COUNT(*) FROM users")
    user_count = cursor.fetchone()[0]
    print(f"Number of users in the database before insertion: {user_count}")

    if user_count == 0:
        users = [
            ('admin', 'password123'),
            ('joel', 'joel123'),
            ('alice', 'alice123')
        ]
        cursor.executemany("INSERT INTO users (username, password) VALUES (?, ?)", users)
        print("Default users added to the database.")

    # Debug: Print all users in the database
    cursor.execute("SELECT * FROM users")
    all_users = cursor.fetchall()
    print("Current users in the database:", all_users)

    conn.commit()
    conn.close()

if __name__ == "__main__":
    setup_db()
