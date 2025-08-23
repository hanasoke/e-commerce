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
    CREATE TABLE IF NOT EXISTS stores (
        store_id INTEGER PRIMARY KEY AUTOINCREMENT,
        seller_id INTEGER,
        store_name TEXT,
        store_photo TEXT,
        store_banner TEXT,
        store_address TEXT,
        store_status TEXT,
        cs_number TEXT,
        FOREIGN KEY(seller_id) REFERENCES sellers(seller_id)
    );
SQL

DB.execute <<-SQL 
    CREATE TABLE IF NOT EXISTS items (
        item_id INTEGER PRIMARY KEY AUTOINCREMENT,
        store_id INTEGER,
        item_name TEXT, 
        item_photo TEXT,
        item_description TEXT,
        item_price TEXT,
        item_stock INTEGER,
        item_category TEXT,
        item_unit TEXT,
        item_status TEXT,
        FOREIGN KEY(store_id) REFERENCES stores(store_id)
    );
SQL;