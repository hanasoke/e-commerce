require 'sqlite3'

DB = SQLite3::Database.new('e_commerce.db')
DB.results_as_hash = true

# Profiles Table 
DB.execute <<-SQL 
    CREATE TABLE IF NOT EXISTS users (
        user_id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE,
        username TEXT UNIQUE,
        email TEXT UNIQUE,
        password TEXT,
        birthdate TEXT,
        address TEXT,
        phone INT,
        photo TEXT,
        reset_token TEXT,
        access INTEGER
    );
SQL

# sellers Table
DB.execute <<-SQL 
    CREATE TABLE IF NOT EXISTS sellers (
        seller_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        identity_photo TEXT,
        FOREIGN KEY(user_id) REFERENCES users(user_id)
    );
SQL

# Store Table 
DB.execute <<-SQL 
    CREATE TABLE NOT EXISTS store (
        store_id INTEGER PRIMARY KEY AUTOINCREMENT,
        seller_id INTEGER,
        store_name TEXT,
        store_photo TEXT,
        store_address TEXT,
        cs_number TEXT,
        FOREIGN KEY(seller_id) REFERENCES sellers(seller_id)
    )
SQL