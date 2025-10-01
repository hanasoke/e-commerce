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

# Sellers Table
DB.execute <<-SQL 
    CREATE TABLE IF NOT EXISTS sellers (
        seller_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        identity_photo TEXT,
        FOREIGN KEY(user_id) REFERENCES users(user_id)
    );
SQL

# Stores Table 
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

# Items Table
DB.execute <<-SQL 
    CREATE TABLE IF NOT EXISTS items (
        item_id INTEGER PRIMARY KEY AUTOINCREMENT,
        store_id INTEGER,
        item_name TEXT, 
        item_brand TEXT,
        item_photo TEXT,
        item_description TEXT,
        item_price TEXT,
        item_stock INTEGER,
        item_category TEXT,
        item_unit TEXT,
        item_status TEXT,
        FOREIGN KEY(store_id) REFERENCES stores(store_id)
    );
SQL

DB.execute <<-SQL 
    CREATE TABLE IF NOT EXISTS wishlists (
        wishlist_id INTEGER PRIMARY KEY AUTOINCREMENT,
        item_id INTEGER,
        store_id INTEGER,
        user_id INTEGER,
        seller_id INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(user_id)
        FOREIGN KEY(seller_id) REFERENCES sellers(seller_id)
        FOREIGN KEY(store_id) REFERENCES stores(store_id)
        FOREIGN KEY(item_id) REFERENCES items(item_id)
    );
SQL

DB.execute <<-SQL
    CREATE TABLE IF NOT EXISTS baskets (
        basket_id INTEGER PRIMARY KEY AUTOINCREMENT,
        wishlist_id INTEGER,
        item_id INTEGER,
        store_id INTEGER,
        user_id INTEGER,
        seller_id INTEGER,
        quantity INTEGER,
        total_price INTEGER,
        FOREIGN KEY(wishlist_id) REFERENCES wishlists(wishlist_id),
        FOREIGN KEY(user_id) REFERENCES users(user_id),
        FOREIGN KEY(seller_id) REFERENCES sellers(seller_id),
        FOREIGN KEY(store_id) REFERENCES stores(store_id),
        FOREIGN KEY(item_id) REFERENCES items(item_id)
    )
SQL

# Add the 'note' column in basket table if it doesn't exist 
# begin 
#     DB.execute("ALTER TABLE baskets ADD COLUMN note TEXT;")
# rescue SQLite3::SQLException => e 
#     puts "Column 'note' in basket table already exists or another error occured: #{e.message}"
# end 

DB.execute <<-SQL 
    CREATE TABLE IF NOT EXISTS services (
        service_id INTEGER PRIMARY KEY AUTOINCREMENT,
        service_name TEXT, 
        fee INTEGER
    )
SQL

DB.execute <<-SQL 
    CREATE TABLE IF NOT EXISTS transactions (
        transaction_id INTEGER PRIMARY KEY AUTOINCREMENT,
        store_id INTEGER,
        seller_id INTEGER, 
        item_id INTEGER, 
        user_id INTEGER,
        wishlist_id INTEGER,
        basket_id INTEGER,
        service_id INTEGER,
        quantity INTEGER,
        total_price INTEGER,
        payment_method TEXT,
        account_number TEXT,
        payment_photo TEXT,
        payment_status TEXT,
        transaction_date TEXT, 
        FOREIGN KEY(wishlist_id) REFERENCES wishlists(wishlist_id),
        FOREIGN KEY(user_id) REFERENCES users(user_id),
        FOREIGN KEY(seller_id) REFERENCES sellers(seller_id),
        FOREIGN KEY(store_id) REFERENCES stores(store_id),
        FOREIGN KEY(item_id) REFERENCES items(item_id),
        FOREIGN KEY(basket_id) REFERENCES items(basket_id),
        FOREIGN KEY(service_id) REFERENCES services(service_id)
    );
SQL

# Add the 'note' column in transactions table if it doesn't exist 
# begin 
#     DB.execute("ALTER TABLE transactions ADD COLUMN note TEXT;")
# rescue SQLite3::SQLException => e 
#     puts "Column 'note' in transactions table already exists or another error occured: #{e.message}"
# end 

DB.execute <<-SQL
    CREATE TABLE IF NOT EXISTS shipments (
        shipping_id INTEGER PRIMARY KEY AUTOINCREMENT,
        transaction_id INTEGER,
        shipping_status TEXT,
        shipping_date TEXT
    );
SQL