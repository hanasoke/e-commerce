require 'sinatra'
require 'sinatra/flash'
require 'bcrypt'
require_relative 'database/e-commerce'
require 'prawn'
require 'rubyXL'
require 'prawn/table'
require 'write_xlsx'
require 'date'

# This is also needed for generating files in memory
require 'stringio'

enable :sessions 
register Sinatra::Flash

# Allow access from any IP 
set :bind, '127.0.0.4'

# Different server port
set :port, 4002

# Helper methods 
def logged_in?
    session[:user_id] != nil 
end

def user_count 
    result = DB.get_first_value("SELECT COUNT(*) FROM users")
    result.to_i
end 

def seller_count 
    result = DB.get_first_value("SELECT COUNT(*) FROM sellers")
    result.to_i
end 

def store_count 
    result = DB.get_first_value("SELECT COUNT(*) FROM stores")
    result.to_i
end 

def seller_registered?(user_id)
    result = DB.get_first_value("SELECT COUNT(*) FROM sellers WHERE user_id = ?", [user_id])
    result.to_i > 0
end 

def current_user 
    @current_user ||= DB.execute("SELECT * FROM users WHERE user_id = ?", [session[:user_id]]).first if logged_in?
end 

def seller_item_count 
    result = DB.get_first_value(<<-SQL)
        SELECT COUNT(*)
        FROM items i 
        JOIN stores s ON i.store_id = s.store_id
        JOIN sellers se ON s.seller_id = se.seller_id
    SQL
    result.to_i
end 

def seller_item_count_for(user_id) 
    result = DB.get_first_value(<<-SQL, [user_id])
        SELECT COUNT(*)
        FROM items i 
        JOIN stores s ON i.store_id = s.store_id 
        JOIN sellers se ON s.seller_id = se.seller_id 
        WHERE se.user_id = ?
    SQL
    result.to_i
end 

def store_exists_for?(user_id)
    result = DB.get_first_value(<<-SQL, [user_id])
        SELECT COUNT(*)
        FROM stores s 
        JOIN sellers se ON s.seller_id = se.seller_id
        WHERE se.user_id = ?
    SQL
    result.to_i > 0
end 

def rupiah_currency(money)
    "Rp #{money.to_i.to_s.reverse.gsub(/(\d{3})(?=\d)/, '\\1.').reverse}"
end 

# Prevent sellers from ordering their own item
def owns_item?(user_id, item_id)
    result = DB.get_first_value(<<-SQL, [user_id, item_id])
        SELECT COUNT(*)
        FROM items i
        JOIN stores s ON i.store_id = s.store_id
        JOIN sellers se ON s.seller_id = se.seller_id 
        WHERE se.user_id = ? AND i.item_id = ?
    SQL
    result.to_i > 0
end 

# Count Helpers for Logged-in User

def wishlist_count(user_id)
    result = DB.get_first_value("SELECT COUNT(*) FROM wishlists WHERE user_id = ?", [user_id])
    result.to_i
end 

def basket_count(user_id)
    result = DB.get_first_value("SELECT COUNT(*) FROM baskets WHERE user_id = ?", [user_id])
    result.to_i
end 

def transaction_count(user_id)
    result = DB.get_first_value("SELECT COUNT(*) FROM transactions WHERE user_id = ?", [user_id])
    result.to_i
end 

# Format count for display (hide if zero, cap at 99+)
def format_count_badge(count)
    return "" if count == 0
    count > 99 ? "99+" : count.to_s
end 

# validate email 
def validate_email(email, user_id = nil)
    errors = []

    # Regular expression for email validation

    # all email
    # email_regex = /\A[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\z/

    # only yahoo & gmail 
    email_regex = /\A[a-zA-Z0-9._%+-]+@(gmail\.com|yahoo\.(com|co\.id))\z/i

    # check if email is blank
    if email.nil? || email.strip.empty?
        errors << "Email cannot be blank."
    elsif email !~ email_regex
        # check if email matches the regular expression
        errors << "Email format is invalid"
    else 
        # Check for Email fields 
        query = user_id ? "SELECT user_id FROM users WHERE LOWER (email) = ? AND user_id != ?" : "SELECT user_id FROM users WHERE LOWER(email) = ?"
        existing_email = DB.execute(query, user_id ? [email.downcase, user_id] : [email.downcase]).first

        errors << "Email already exists. Please choose a different name." if existing_email
    end 

    errors
end 

# validate user 
def validate_user(name, username, email, password, birthdate, address, phone, access, user_id = nil)
    errors = []

    # Name validation
    if name.nil? || name.strip.empty?
        errors << "Name cannot be blank."
    else 
        query = "SELECT user_id FROM users WHERE LOWER(name) = ?"
        query += " AND user_id != ?" if user_id
        name_exists = DB.get_first_row(query, user_id ? [name.downcase, user_id] : [name.downcase])
        errors << "Name is already taken." if name_exists
    end 

    # Username validation
    if username.nil? || username.strip.empty?
        errors << "Username cannot be blank."
    else 
        query = "SELECT user_id FROM users WHERE LOWER(username) = ?"
        query += " AND user_id != ?" if user_id 
        username_exists = DB.get_first_row(query, user_id ? [username.downcase, user_id] : [username.downcase])
        errors << "Username is already taken." if username_exists
    end 

    # Password validation 
    if password.nil? || password.strip.empty?
        errors << "Password cannot be blank." 
    else 
        # Prevent password from being the same as the name
        if name && password.strip.downcase == name.strip.downcase 
            errors << "Password cannot be the same as your name."
        end 
        # Avoid password that is same as others (by comparing hashes)
        existing_passwords = DB.execute("SELECT password FROM users")
        existing_passwords.each do |row| 
            existing_hash = row['password']
            begin 
                if BCrypt::Password.new(existing_hash) == password
                    errors << "Password is already used by another user"
                    break
                end 
            rescue BCrypt::Errors::InvalidHash 
                # Skip invalid hash formats
            end 
        end 
    end 

    # Birthdate validation 
    errors << "Birthdate cannot be blank." if birthdate.nil? || birthdate.strip.empty?

    # Address
    errors << "Address cannot be blank." if address.nil? || address.strip.empty?

    # Phone validation 
    if phone.nil? || phone.strip.empty? 
        errors << "Phone Cannot be Blank."
    elsif phone !~ /\A[0-9]{10,15}\z/
        errors << "Phone must be 10 to 15 digits and contain only numbers."
    else 
        query = "SELECT user_id FROM users WHERE phone = ?"
        query += " AND user_id != ?" if user_id 
        phone_exists = DB.get_first_row(query, user_id ? [phone.downcase, user_id] : [phone.downcase])
        errors << "Phone is already taken." if phone_exists
    end

    # Validate Email 
    email_errors = validate_email(email, user_id)
    errors.concat(email_errors)

    errors
end 

def validate_item(item_name, item_brand, item_description, item_price, item_stock, item_category, item_unit, item_status, item_id = nil) 
    errors = []

    # Item Name Validation
    errors << "Item Name Cannot be Blank."  if item_name.nil? || item_name.strip.empty?

    # Check for unique item_name (only if it's a new item or name is being changed)
    if item_name && !item_name.strip.empty?
        if item_id 
            # For updated: check if another item (with different ID) has the same name 
            existing_item = DB.execute(
                "SELECT item_id FROM items WHERE LOWER(item_name) = ? AND item_id != ?", 
                [item_name.downcase, item_id]
            ).first 
        else 
            # For new items: check if any item has the same name
            existing_item = DB.execute(
                "SELECT item_id FROM items WHERE LOWER(item_name) = ?",
                [item_name.downcase]
            ).first 
        end 
        errors << "Item Name Already exist. Please choose a different item name." if existing_item
    end 

    # Item Brand 
    errors << "Item Brand Cannot be Blank." if item_brand.nil? || item_brand.strip.empty?

    # Item Description 
    errors << "Item Description Cannot be Blank." if item_description.nil? || item_description.strip.empty?

    # Item Price 
    if item_price.nil? ||  item_price.to_s.strip.empty?
        errors << "Item Price Cannot be Blank."
    elsif item_price.to_s !~ /\A\d+(\.\d{1,2})?\z/
        errors << "Item Price must be a valid number."
    elsif item_price.to_f <= 0 
        errors << "Item Price must be a positive number."
    end 

    # Item Stock
    if item_stock.nil? ||  item_stock.to_s.strip.empty?
        errors << "Item Stock Cannot be Blank."
    elsif item_stock.to_s !~ /\A\d+(\.\d{1,2})?\z/
        errors << "Item Stock must be a valid number."
    elsif item_stock.to_f <= 0 
        errors << "Item Stock must be a positive number."
    end 

    # Item Category
    errors << "Item Category Cannot be blank." if item_category.nil? || item_category.to_s.strip.empty?
    
    # Item Unit 
    errors << "SKU Cannot be blank." if item_unit.nil? || item_unit.to_s.strip.empty?

    # Item Status 
    errors << "Item Status Cannot be blank." if item_status.nil? || item_status.to_s.strip.empty?

    errors
end 

def validate_store(store_name, store_address, store_status, cs_number, store_id = nil)

    errors = []

    # Store Name Validation 
    errors << "Store Name Cannot be Blank." if store_name.nil? || store_name.strip.empty?

    # Check for unique store_name (only if it's a new store or name is being changed)
    if store_name && !store_name.strip.empty?
        if store_id 
            # For updated: check if another store (with different ID) has the same name
            existing_store = DB.execute(
                "SELECT store_id FROM stores WHERE LOWER(store_name) = ? AND store_id != ?", 
                [store_name.downcase, store_id]
            ).first 
        else 
            # For new stores: check if any store has the same name 
            existing_store = DB.execute(
                "SELECT store_id FROM stores WHERE LOWER(store_name) = ?",
                [store_name.downcase]
            ).first 
        end 
        errors << "Store Name Already exist. Please choose a different store name." if existing_store
    end 

    # Store Address Validation 
    errors << "Store Address Cannot be Blank." if store_address.nil? || store_address.strip.empty?
    
    # Store Status Validation 
    errors << "Store Status Cannot be Blank." if store_status.nil? || store_status.strip.empty?
    
    # CS_Number Validation
    if cs_number.nil? || cs_number.to_s.strip.empty? 
        errors << "CS Number Cannot be Blank."
    elsif cs_number.to_s !~ /\A\d+(\.\d{1,2})?\z/
        errors << "CS Number must be a valid number."
    elsif cs_number.to_f <= 0 
        errors << "CS Number must be a positive number."
    end
    
    errors
end 

def editing_user(name, username, email, birthdate, address, phone, access, user_id = nil)

    errors = []

    errors << "Name cannot be blank." if name.nil? || name.strip.empty?

    errors << "Username cannot be blank." if username.nil? || username.strip.empty?
    
    errors << "Birthdate cannot be blank." if birthdate.nil? || birthdate.strip.empty?

    errors << "Address cannot be blank." if address.nil? || address.strip.empty?

    errors << "Phone cannot be blank."if phone.nil? || phone.strip.empty?

    errors << "Access cannot be blank." if access.nil? || access.strip.empty?

    # Validate duplicate name (excluding the current user)
    if name && !name.strip.empty? 
        query = user_id ? "SELECT user_id FROM users WHERE LOWER(name) = ? AND user_id != ?" : "SELECT user_id FROM users WHERE LOWER(name) = ?"
        existing_name = DB.execute(query, user_id ? [name.downcase, user_id] : [name.downcase]).first 
        errors << "Name already exists. Please choose a different name." if existing_name
    end 

    # Validate duplicate phone number (excluding the current user)
    if phone && !phone.strip.empty? 
        query = user_id ? "SELECT user_id FROM users WHERE phone = ? AND user_id != ?" : "SELECT user_id FROM users WHERE phone = ?"
        existing_phone = DB.execute(query, user_id ? [phone, user_id] : [phone]).first 
        errors << "Phone number already exists. Please use a different number." if existing_phone
    end 

    # Validate email 
    errors.concat(validate_email(email, user_id))
    errors
end 

def editing_profile_admin(name, username, email, birthdate, address, phone, access, user_id = nil)

    errors = []

    errors << "Name cannot be blank." if name.nil? || name.strip.empty?

    errors << "Username cannot be blank." if username.nil? || username.strip.empty?
    
    errors << "Birthdate cannot be blank." if birthdate.nil? || birthdate.strip.empty?

    errors << "Address cannot be blank." if address.nil? || address.strip.empty?

    errors << "Phone cannot be blank."if phone.nil? || phone.strip.empty?

    errors << "Access cannot be blank." if access.nil? || access.strip.empty?

    # Validate email 
    errors.concat(validate_email(email, user_id))
    errors
end

def editing_profile(name, username, email, birthdate, address, phone, user_id = nil)

    errors = []

    errors << "Name cannot be blank." if name.nil? || name.strip.empty?

    errors << "Username cannot be blank." if username.nil? || username.strip.empty?
    
    errors << "Birthdate cannot be blank." if birthdate.nil? || birthdate.strip.empty?

    errors << "Address cannot be blank." if address.nil? || address.strip.empty?

    errors << "Phone cannot be blank."if phone.nil? || phone.strip.empty?

    # Validate email 
    errors.concat(validate_email(email, user_id))
    errors
end

def validate_photo(photo)
    errors = []

    # Check if the photo parameter is valid and has expected structure
    if photo.nil? || !photo.is_a?(Hash) || photo[:tempfile].nil?
        errors << 'Photo is required.'
    else 
        # Check file type
        valid_types = ["image/jpeg", "image/png", "image/gif"]
        if !photo[:type] || !valid_types.include?(photo[:type])
            errors << "Photo must be a JPG, PNG, or GIF file."
        end 

        # Check file sizee (8MB max)
        max_size = 8 * 1024 * 1024 # 8MB in bytes
        file_size = photo[:tempfile].size if photo[:tempfile] && photo[:tempfile].respond_to?(:size)

        if file_size.nil? 
            errors << "Photo file size could not be determined."
        elsif file_size > max_size 
            errors << "Photo size must be less than 8MB."
        end 
    end 

    errors 
end 

def validate_item_photo(photo)
    errors = []

    # Check if the photo parameter is valid and has expected structure
    if photo.nil? || !photo.is_a?(Hash) || photo[:tempfile].nil?
        errors << 'Item Photo is required.'
    else 
        # Check file type
        valid_types = ["image/jpeg", "image/png", "image/gif"]
        if !photo[:type] || !valid_types.include?(photo[:type])
            errors << "Item Photo must be a JPG, PNG, or GIF file."
        end 

        # Check file sizee (8MB max)
        max_size = 8 * 1024 * 1024 # 8MB in bytes
        file_size = photo[:tempfile].size if photo[:tempfile] && photo[:tempfile].respond_to?(:size)

        if file_size.nil? 
            errors << "Item Photo file size could not be determined."
        elsif file_size > max_size 
            errors << "Item Photo size must be less than 8MB."
        end 
    end 

    errors 
end 

def validate_store_photo(photo)
    errors = []

    # Check if the photo parameter is valid and has expected structure
    if photo.nil? || !photo.is_a?(Hash) || photo[:tempfile].nil?
        errors << 'Store Photo is required.'
    else 
        # Check file type
        valid_types = ["image/jpeg", "image/png", "image/gif"]
        if !photo[:type] || !valid_types.include?(photo[:type])
            errors << "Store Photo must be a JPG, PNG, or GIF file."
        end 

        # Check file sizee (8MB max)
        max_size = 8 * 1024 * 1024 # 8MB in bytes
        file_size = photo[:tempfile].size if photo[:tempfile] && photo[:tempfile].respond_to?(:size)

        if file_size.nil? 
            errors << "Store Photo file size could not be determined."
        elsif file_size > max_size 
            errors << "Store Photo size must be less than 8MB."
        end 
    end 

    errors 
end 

def validate_store_banner(photo)
    errors = []

    # Check if the photo parameter is valid and has expected structure
    if photo.nil? || !photo.is_a?(Hash) || photo[:tempfile].nil?
        errors << 'Store Banner is required.'
    else 
        # Check file type
        valid_types = ["image/jpeg", "image/png", "image/gif"]
        if !photo[:type] || !valid_types.include?(photo[:type])
            errors << "Store Banner must be a JPG, PNG, or GIF file."
        end 

        # Check file sizee (8MB max)
        max_size = 8 * 1024 * 1024 # 8MB in bytes
        file_size = photo[:tempfile].size if photo[:tempfile] && photo[:tempfile].respond_to?(:size)

        if file_size.nil? 
            errors << "Store Banner file size could not be determined."
        elsif file_size > max_size 
            errors << "Store Banner size must be less than 8MB."
        end 
    end 

    errors 
end 

def validate_user_login(email, password)
    errors = []

    # Password check
    errors << "Password cannot be blank." if password.nil? || password.strip.empty?

    # Email format check
    email_regex = /\A[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\z/
    if email.nil? || email.strip.empty?
        errors << "Email cannot be blank."
    elsif email !~ email_regex
        errors << "Email format is invalid."
    end

    errors
end

def editing_payment(payment_name, payment_method, account_number, service_id = nil)
    errors = []

    # Bank/E-Wallet/VA Name
    if payment_name.nil? || payment_name.strip.empty? || payment_name == "Input Your Payment Name"
        errors << "Payment Name is required."
    end 

    # Payment Method 
    if payment_method.nil? || payment_method.strip.empty? || payment_method == "Input Your Payment Method"
        errors << "Payment Method is required."
    end 

    # Account Number validation
    if account_number.nil? || account_number.strip.empty?
        errors << "Account Number cannot be blank."
    elsif account_number.to_s !~ /^\d+$/
        errors << "Account Number must be a number."
    elsif account_number.to_f <= 0 
        errors << "Account Number must be a positive number."
    end 

    errors 
end

# Routes 

# Homepage 
get '/' do 
    @errors = []
    @title = 'HomePage'

    # fetch only active items 
    @items = DB.execute(<<-SQL)
        SELECT i.*, s.store_name
        FROM items i
        JOIN stores s ON i.store_id = s.store_id
        WHERE i.item_status = 'Active'
            AND s.store_status = 'Active'
    SQL
    
    erb :'user/no_account/index', layout: :'layouts/no_user/template'
end 

# Account 
get '/account' do 
    redirect '/login' unless logged_in?
    
    @errors = []
    @title = 'HomePage'

    # fetch only active items 
    @items = DB.execute(<<-SQL)
        SELECT i.*, s.store_name
        FROM items i
        JOIN stores s ON i.store_id = s.store_id
        WHERE i.item_status = 'Active'
            AND s.store_status = 'Active'
    SQL

    erb :'user/index', layout: :'layouts/user/template'
end 

# Login
get '/login' do 
    @errors = []
    @title = 'Login'
    erb :'sign/login', layout: :'layouts/sign/template'
end 

post '/login' do
    email = params[:email].to_s.strip
    password = params[:password]
    remember = params[:remember]

    @errors = validate_user_login(email, password)
  
    if @errors.empty? 
        # Find user by email
        user = DB.get_first_row("SELECT * FROM users WHERE LOWER(email) = ?", [email.downcase])

        if user && BCrypt::Password.new(user['password']) == password
            # Successful login
            session[:user_id] = user['user_id']
            session[:success] = "Login successful."

            # Check access level and redirect accordingly 
            if user['access'] == 1
                # Redirect to the user page for regular users
                redirect '/account'
            elsif user['access'] == 2 
                # Redirect to the viewer page for sellers
                redirect '/account'
            elsif user['access'] == 3
                # Redirect to the admin page for admins
                redirect '/admin'
            else 
                @errors << "Invalid access level"
            end 
        else
            @errors << "Invalid email or password."
        end
    end 

    @title = 'Login'
    erb :'sign/login', layout: :'layouts/sign/template'
end

# Register 
get '/register' do 
    @errors = []
    @title = "Register"
    erb :'sign/register', layout: :'layouts/sign/template'
end 

post '/register' do 
    name = params[:name]
    username = params[:username]
    email = params[:email]
    password = params[:password]
    birthdate = params[:birthdate]
    address = params[:address]
    phone = params[:phone]
    access = params[:access]
    photo = params[:photo]

    # Validate user input 
    @errors = validate_user(name, username, email, password, birthdate, address, phone, access)

    # Validate photo 
    @errors += validate_photo(photo)

    # If no errors, process registration 
    if @errors.empty?
        photo_filename = "#{Time.now.to_i}_#{photo[:filename]}"
        photo_path = "./public/uploads/users/#{photo_filename}"

        # Save photo to public/uploads/
        File.open(photo_path, 'wb') do |f|
            f.write(photo[:tempfile].read)
        end 

        begin 
            hashed_password = BCrypt::Password.create(password)

            DB.execute(
                "INSERT INTO users (name, username, email, password, birthdate, address, phone, photo, access) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [name, username, email, hashed_password, birthdate, address, phone, photo_filename, access]
            )

            session[:success] = "Account successfully created. Please login."
            redirect '/login'
        
        rescue SQLite3::ConstraintException => e 
            @errors << "Account creation failed: #{e.message}"
        end 
    end 

    @title = "Register"
    erb :'sign/register', layout: :'layouts/sign/template'
end 

get '/reset_password' do 
    @errors = []
    @title = "Reset Password"
    erb :'sign/reset_password', layout: :'layouts/sign/template'
end 

get '/admin' do 
    redirect '/login' unless logged_in?

    @errors = []
    @title = "Admin"

    erb :'admin/index', layout: :'layouts/admin/layout'
end

get '/user_lists' do 
    redirect '/login' unless logged_in?

    @errors = []
    @title = "User Lists"
    @users = DB.execute("SELECT * FROM users WHERE access IN (1, 2)")
    erb :'admin/user_dashboard/user_lists', layout: :'layouts/admin/layout'

end 

get '/edit_user/:user_id' do 
    redirect '/login' unless logged_in?

    @title = "Edit A User"
    @user = DB.execute("SELECT * FROM users WHERE user_id = ?", [params[:user_id]]).first
    @errors = []

    if @user.nil?
        session[:error] = 'A User is not founded!'
        redirect '/error_page'
    end 
    erb :'admin/user_dashboard/edit', layout: :'layouts/admin/layout'
end 

# Update a user
post '/edit_user/:user_id' do 
    @errors = editing_user(params[:name], params[:username], params[:email], params[:birthdate], params[:address], params[:phone], params[:access], params[:user_id])

    # error photo variable check
    photo = params['photo']

    # Validate only if a new photo is provided 
    @errors += validate_photo(photo) if photo && photo[:tempfile]

    photo_filename = nil 

    if @errors.empty?
        # Handle file image upload 
        if photo && photo[:tempfile]
            photo_filename = "#{Time.now.to_i}_#{photo[:filename]}"

            # Uploaded image to uploads folder 
            File.open("./public/uploads/users/#{photo_filename}", 'wb') do |f| 
                f.write(photo[:tempfile].read)
            end
        end 

        # Flash Message
        session[:success] = "A User has been successfully updated."

        # Update the user
        DB.execute("UPDATE users SET name = ?, username = ?, email = ?, birthdate = ?, address = ?, phone = ?, photo = COALESCE(?, photo), access = ? WHERE user_id = ?", 
        [params[:name], params[:username], params[:email], params[:birthdate], params[:address], params[:phone], photo_filename, params[:access], params[:user_id]])

        redirect '/user_lists'
    
    else 
        # Handle validation errors and re-render the edit form 
        original_user = DB.execute("SELECT * FROM users WHERE user_id = ?", [params[:user_id]]).first

        # Merge user input with original data to retain user edits
        @user = {
            'user_id' => params[:user_id], 
            'name' => params[:name] || original_user['name'],
            'username' => params[:username] || original_user['username'],
            'email' => params[:email] || original_user['email'],
            'birthdate' => params[:birthdate] || original_user['birthdate'],
            'address' => params[:address] || original_user['address'],
            'phone' => params[:phone] || original_user['phone'],
            'photo' => photo_filename || original_user['photo'],
            'access' => params[:access] || original_user['access']
        }
        erb :'admin/user_dashboard/edit',  layout: :'layouts/admin/layout'
    end 
end 

get '/error_page' do 
    redirect '/login' unless logged_in?
    @errors = []
    @title = "Error Page"

    erb :'errors/admin_error', layout: :'layouts/admin/layout'
end 

# Logout 
get '/logout' do 
    success_message = "You have been logged out successfully."
    session.clear 
    session[:success] = success_message
    redirect '/login'
end 

# DELETE a user
post '/delete_user/:user_id' do
    # Flash message
    session[:success] = "A user has been successfully deleted."

    DB.execute("DELETE FROM users WHERE user_id = ?", [params[:user_id]])
    redirect '/admin'
end 

# Detail a user
get '/detail_user/:user_id' do 
    redirect '/login' unless logged_in?

    @title = "View the user profile"
    @user = DB.execute("SELECT * FROM users WHERE user_id = ?", [params[:user_id]]).first
    @errors = []

    if @user && @user['birthdate']
        birthdate = Date.parse(@user['birthdate']) rescue nil 
        if birthdate 
            today = Date.today 
            age = today.year - birthdate.year 
            @user['age'] = age
        else 
            @user['age'] = 'Invalid birthdate'
        end 
    else 
        @profile['age'] = 'Not available'
    end

    erb :'admin/user_dashboard/view', layout: :'layouts/admin/layout'
end 

# Show Forgot Password Page
get '/forgot_password' do 
    @errors = []
    @title = "Forgot Password"
    erb :'sign/forgot_password', layout: :'layouts/sign/template'

end 

post '/forgot_password' do
    email = params[:email]
    @errors = []

    session[:success] = "Password reset link sent to your email."

    if email.strip.empty? 
        @errors << "Email cannot be blank."
    elsif !DB.execute("SELECT * FROM users WHERE email = ?", [email]).first 
        @errors << "Email not found in our records."
    else 
        # Generate reset token (basic implementation, use a secure library in production)
        reset_token = SecureRandom.hex(20)
        DB.execute("UPDATE users SET reset_token = ? WHERE email = ?", [reset_token, email])

        # Simulate sending an email (in production, send a real email)
        reset_url = "http://127.0.0.4:4002/reset_password/#{reset_token}"
        puts "Reset password link: #{reset_url}" # Replace with email sending logic
        redirect '/login'
    end 

    erb :'sign/forgot_password', layout: :'layouts/sign/template'
end 

# Show Reset Password Page
get '/reset_password/:token' do 
    @reset_token = params[:token]
    @user = DB.execute("SELECT * FROM users WHERE reset_token = ?", [@reset_token]).first
    @title = "Reset Password"

    if @user.nil?
        session[:error] = "Invalid or expired reset token."
        redirect '/login'
    end 

    erb :'sign/reset_password', layout: :'layouts/sign/template'
end 

# Handle Reset Password Submission
post '/reset_password' do 
    reset_token = params[:reset_token]
    password = params[:password]
    re_password = params[:re_password]
    @errors = []

    if password.strip.empty? || re_password.strip.empty?
        @errors << "Password fields cannot be blank."
    elsif password != re_password
        @errors << "Password do not match."
    else
        user = DB.execute("SELECT * FROM users WHERE reset_token = ?", [reset_token]).first

        if user.nil?
            @errors << "Invalid or expired reset token."
        else 
            hashed_password = BCrypt::Password.create(password)
            DB.execute("UPDATE users SET password = ?, reset_token = NULL WHERE user_id = ?", [hashed_password, user['user_id']])
            session[:success] = "Password reset successfully. Please log in."
            redirect '/login'
        end 
    end 

    @reset_token = reset_token 
    erb :'sign/reset_password', layout: :'layouts/sign/template'
end 

get '/admin_view_profile/:user_id' do 
    redirect '/login' unless logged_in?

    @title = "View Profile"
    @profile = current_user
    
    if @profile && @profile['birthdate']
        birthdate = Date.parse(@profile['birthdate']) rescue nil 
        if birthdate 
            today = Date.today 
            age = today.year - birthdate.year 
            @profile['age'] = age
        else 
            @profile['age'] = 'Invalid birthdate'
        end 
    else 
        @profile['age'] = 'Not available'
    end 

    @errors = []
    erb :'admin/view_profile', layout: :'layouts/admin/layout'
end 

get '/admin_edit_profile/:user_id' do 
    redirect '/login' unless logged_in?

    @title = "Edit Profile"
    @profile = current_user
    @errors = []
    erb :'admin/edit_profile', layout: :'layouts/admin/layout'
end 

post '/admin_edit_profile/:user_id' do 

    @errors = editing_profile_admin(params[:name], params[:username], params[:email], params[:birthdate], params[:address], params[:phone], params[:access], params[:user_id])

    # error photo variable check 
    photo = params['photo']
    @errors += validate_photo(photo) if photo && photo[:tempfile] # validate only if a new photo is provided

    photo_filename = nil 

    if @errors.empty? 
        # Handle file upload 
        if photo && photo[:tempfile]
            photo_filename = "#{Time.now.to_i}_#{photo[:filename]}"
            File.open("./public/uploads/users/#{photo_filename}", 'wb') do |f|
                f.write(photo[:tempfile].read)
            end 
        end 

        # Flash message
        session[:success] = "Your Profile has been successfully updated"

        # Update the profile in the database
        DB.execute("UPDATE users SET name = ?, username = ?, email = ?, birthdate = ?, address = ?, phone = ?, photo = COALESCE(?, photo), access = ? WHERE user_id = ?", [params[:name], params[:username], params[:email], params[:birthdate], params[:address], params[:phone], photo_filename, params[:access], params[:user_id]]) 

        profile = DB.execute("SELECT * FROM users WHERE email = ?", [params[:email]]).first 
        session[:user_id] = profile['user_id']

        # Redirect based on access level 
        case profile['access']
        when 1 
            # Flash message
            session[:success] = "You Are Customer Now"
            redirect '/login'
        when 2 
            # Flash message
            session[:success] = "You Are Seller Now"
            redirect '/login'
        when 3
            # Flash message
            session[:success] = "Your Profile has been successfully updated"
            redirect "/admin_view_profile/#{params[:user_id]}"
        else 
            @errors << "Invalid access level"
        end 
    else 
        # Handle validation errors and re-render the edit form 
        original_profile = DB.execute("SELECT * FROM users WHERE user_id = ?", [params[:user_id]]).first

        # Merge user input with original data to retain user edit 
        @profile = {
            'user_id' => params[:user_id],
            'name' => params[:name] || original_profile['name'],
            'username' => params[:username] || original_profile['username'],
            'email' => params[:email] || original_profile['email'],
            'birthdate' => params[:birthdate] || original_profile['birthdate'],
            'address' => params[:address] || original_profile['address'],
            'phone' => params[:phone] || original_profile['phone'],
            'photo' => photo_filename || original_profile['photo'],
            'access' => params[:access] || original_profile['access']
        }
        erb :'admin/edit_profile', layout: :'layouts/admin/layout'
    end 
end 

get '/seller_dashboard/:user_id' do 
    redirect '/login' unless logged_in?

    @title = "Seller Dashboard"
    @profile = current_user
    @errors = []
    erb :'seller/seller_panel/index', layout: :'layouts/admin/layout'
end 

get '/seller_register/:user_id' do 
    redirect '/login' unless logged_in?
    
    if seller_registered?(session[:user_id])
        flash[:warning] = "You have already registered as a seller"
        redirect '/seller'
    end 

    @title = "Seller Register"
    @profile = current_user
    @errors = []
    erb :'sign/seller/register', layout: :'layouts/sign/template'
end

post '/seller_register/:user_id' do
    redirect '/login' unless logged_in? 

    @errors = []

    # pastikan yang mendaftar adalah user yang sedang login (prevent spoofing)
    unless params[:user_id].to_i == session[:user_id].to_i 
        halt 403, "Forbidden"
    end 

    user_id = session[:user_id]
    photo = params['identity_photo']

    # Validasi foto jika ada 
    @errors += validate_photo(photo)

    if @errors.empty?
        
        # Cek apakah seller sudah terdaftar sebelumnya 
        existing = DB.get_first_row("SELECT * FROM sellers WHERE user_id = ?", [user_id])

        if existing
            @errors << "Seller profile already registered"
        else 
            photo_filename = nil 
            if photo && photo[:tempfile]
                photo_filename = "#{Time.now.to_i}_#{photo[:filename]}"
                File.open("./public/uploads/sellers/#{photo_filename}", 'wb') do |f|
                    f.write(photo[:tempfile].read)
                end 
            end 

            begin 
                DB.execute("INSERT INTO sellers (user_id, identity_photo) VALUES (?, ?)", [user_id, photo_filename])

                # Update access level after successful seller registration 
                DB.execute("UPDATE users SET access = 2 WHERE user_id = ?", [user_id])

                session[:success] = "Seller account registered."
                redirect '/seller' 
            rescue SQLite3::ConstraintException => e 
                @errors << "Registration failed: #{e.message}"
            end 
        end 
    end 

    # Jika ada error, render ulang form 
    @title = "Seller Register"
    @profile = current_user
    erb :'sign/seller/register', layout: :'layouts/sign/template'
end 

get '/user_profile/:user_id' do 
    redirect '/login' unless logged_in? 

    @title = "User Profile"
    @profile = current_user

    if @profile && @profile['birthdate']
        birthdate = Date.parse(@profile['birthdate']) rescue nil 
        if birthdate 
            today = Date.today 
            age = today.year - birthdate.year 
            @profile['age'] = age
        else 
            @profile['age'] = 'Invalid birthdate'
        end 
    else 
        @profile['age'] = 'Not available'
    end

    @errors = []
    erb :'user/profile/view', layout: :'layouts/user/template'
end 

get '/user_profile_edit/:user_id' do 
    redirect '/login' unless logged_in? 

    @title = "User Profile Edit"
    @profile = current_user

    @errors = []
    erb :'user/profile/edit', layout: :'layouts/user/template'
end 

post '/user_profile_edit/:user_id' do 
    @errors = editing_profile(params[:name], params[:username], params[:email], params[:birthdate], params[:address], params[:phone], params[:user_id])

    # error photo variable check 
    photo = params['photo']
    # Validate only if a new photo is provided
    @errors += validate_photo(photo) if photo && photo[:tempfile] 

    photo_filename = nil 

    if @errors.empty? 
        # Handle file upload 
        if photo && photo[:tempfile]
            photo_filename = "#{Time.now.to_i}_#{photo[:filename]}"
            File.open("./public/uploads/users/#{photo_filename}", "wb") do |f|
                f.write(photo[:tempfile].read)
            end 
        end 

        # Flash message
        session[:success] = "Your Profile has been successfully updated"

        # Update the profile in the database
        DB.execute("UPDATE users SET name = ?, username = ?, email = ?, birthdate = ?, address = ?, phone = ?, photo = COALESCE(?, photo) WHERE user_id = ?", [params[:name], params[:username], params[:email], params[:birthdate], params[:address], params[:phone], photo_filename, params[:user_id]])

        # Fetch updated access level from DB 
        updated_user = DB.get_first_row("SELECT access FROM users WHERE user_id = ?", [params[:user_id]])

        if updated_user['access'].to_i == 1
            redirect '/account'
        elsif updated_user['access'].to_i == 2
            redirect '/account'
        else 
            redirect '/' #fallback
        end 

    else 
        # Handle validation errors and re-render the edit form 
        original_profile = DB.execute("SELECT * FROM users WHERE user_id = ?", [params[:user_id]]).first 

        # Merge user input with original data to retain user edit 
        @profile = {
            'user_id' => params[:user_id],
            'name' => params[:name] || original_profile['name'],
            'username' => params[:username] || original_profile['username'],
            'email' => params[:email] || original_profile['email'],
            'birthdate' => params[:birthdate] || original_profile['birthdate'],
            'address' => params[:address] || original_profile['address'],
            'phone' => params[:phone] || original_profile['phone'],
            'photo' => photo_filename || original_profile['photo']
        }
        erb :'user/profile/edit', layout: :'layouts/user/template'

    end 
end 

get '/seller_lists' do 
    redirect '/login' unless logged_in?

    @errors = []
    @title = "Seller Lists"
    @sellers = DB.execute <<-SQL
        SELECT 
            sellers.*,
            users.name,
            users.username,
            users.email,
            users.phone,
            users.photo,
            users.birthdate,
            users.address
        FROM sellers 
        JOIN users ON sellers.user_id = users.user_id
    SQL

    # calculate age for each seller 
    @sellers.each do |seller|
        if seller["birthdate"]
            birthdate = Date.parse(seller["birthdate"]) rescue nil 
            seller["age"] = ((Date.today - birthdate).to_i / 365) if birthdate
        else
            seller["age"] = nil 
        end 
    end 

    erb :'admin/seller_dashboard/seller_lists', layout: :'layouts/admin/layout'
end 

get '/view_seller/:user_id' do 
    redirect '/login' unless logged_in?

    @title = "View My Seller Profile"
    @profile = current_user

    # Get seller-specific information
    @seller_info = DB.execute("SELECT * FROM sellers WHERE user_id = ?", [params[:user_id]]).first

    if @profile && @profile['birthdate']
        birthdate = Date.parse(@profile['birthdate']) rescue nil 
        if birthdate
            today = Date.today 
            age = today.year - birthdate.year 
            @profile['age'] = age 
        else 
            @profile['age'] = 'Invalid birthdate'
        end 
    else 
        @profile['age'] = 'Not available'
    end 

    @errors = []
    erb :'seller/seller_profile/view_seller', layout: :'layouts/admin/layout'
end 

# DELETE a user
post '/delete_seller/:seller_id' do
    # Flash message
    session[:success] = "A seller has been successfully deleted."

    DB.execute("DELETE FROM sellers WHERE seller_id = ?", [params[:seller_id]])
    redirect '/seller_lists'
end 

get '/item_lists/:user_id' do 
    redirect '/login' unless logged_in?
    halt 403, "Unauthorized" unless current_user['user_id'].to_s == params[:user_id]

    @title = "View My Item Lists"

    @items = DB.execute(<<-SQL, [params[:user_id]]) 
        SELECT i.*
        FROM items i 
        JOIN stores s ON i.store_id = s.store_id 
        JOIN sellers se ON s.seller_id = se.seller_id 
        WHERE se.user_id = ?
    SQL

    # Check if the seller has at least one store
    @has_store = store_exists_for?(params[:user_id])

    erb :'seller/seller_items/item_lists', layout: :'layouts/admin/layout'
end 

get '/add_my_store/:user_id' do 
    redirect '/login' unless logged_in?

    @errors = []
    @title = "Add My Store"

    erb :'seller/store_panel/add_my_store', layout: :'layouts/admin/layout'
end 

post '/add_my_store/:user_id' do 

    @errors = validate_store(params[:store_name], params[:store_address], params[:store_status], params[:cs_number])

    store_photo = params['store_photo']
    store_banner = params['store_banner']

    # Add store_photo validation errors 
    @errors += validate_store_photo(store_photo)

    # Add store_banner validation errors 
    @errors += validate_store_banner(store_banner)

    # Get current seller for this seller 
    user = DB.execute("SELECT * FROM users WHERE user_id = ?", [params[:user_id]]).first 

    seller = DB.execute("SELECT * FROM sellers where user_id = ?", [user['user_id']]).first

    if seller.nil? 
        @errors << "Seller account not found for this user."
        return erb :'seller/store_panel/add_my_store', layout: :'layouts/admin/layout'
    end 

    store_photo_filename = nil 
    store_banner_filename = nil 

    if @errors.empty?
        # Handle file upload 
        if store_photo && store_photo[:tempfile]
            store_photo_filename = "#{Time.now.to_i}_#{store_photo[:filename]}"
            File.open("./public/uploads/stores/#{store_photo_filename}", 'wb') do |f|
                f.write(store_photo[:tempfile].read)
            end 
        end 

        if store_banner && store_banner[:tempfile]
            store_banner_filename = "#{Time.now.to_i}_#{store_banner[:filename]}"
            File.open("./public/uploads/stores/#{store_banner_filename}", 'wb') do |f|
                f.write(store_banner[:tempfile].read)
            end 
        end 

        # Insert store details
        DB.execute("INSERT INTO stores 
            (seller_id, store_name, store_photo, store_banner, store_address, store_status, cs_number)
                VALUES (?, ?, ?, ?, ?, ?, ?)", 
            [seller['seller_id'], params[:store_name], store_photo_filename, store_banner_filename, params[:store_address], params[:store_status], params[:cs_number]]
        )

        # Flash Message
        session[:success] = "Store created successfully!"

        # Redirect to seller dashboard
        redirect "/seller_dashboard/#{user['user_id']}"
    else 
        return erb :'seller/store_panel/add_my_store', layout: :'layouts/admin/layout'
    end 
end 

get '/add_an_item/:user_id' do 
    redirect '/login' unless logged_in?

    @errors = []

    @title = "Add An Item"

    erb :'seller/seller_items/add_item', layout: :'layouts/admin/layout'
end 

post '/add_an_item/:user_id' do 
    @errors = validate_item(params[:item_name], params[:item_brand], params[:item_description], params[:item_price], params[:item_stock], params[:item_category], params[:item_unit], params[:item_status])

    item_photo = params['item_photo']

    # Add item_photo validation errors 
    @errors += validate_item_photo(item_photo)

    # Get current store for this seller 
    seller = DB.execute("SELECT * FROM sellers WHERE user_id = ?", [params[:user_id]]).first 
    store = DB.execute("SELECT * FROM stores WHERE seller_id = ?", [seller['seller_id']]).first 

    photo_filename = nil

    if @errors.empty? 
        # Handle file upload 
        if item_photo && item_photo[:tempfile]
            photo_filename = "#{Time.now.to_i}_#{item_photo[:filename]}"
            File.open("./public/uploads/items/#{photo_filename}", 'wb') do |f|
                f.write(item_photo[:tempfile].read)
            end 
        end 

        # Flash Message
        session[:success] = "Item added successfully!"

        # Insert item details, including the photo, into the database
        DB.execute("INSERT INTO items 
            (store_id, item_name, item_brand, item_photo, item_description, item_price, item_stock, item_category, item_unit, item_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [store['store_id'], params[:item_name], params[:item_brand], photo_filename, params[:item_description], params[:item_price], params[:item_stock], params[:item_category], params[:item_unit], params[:item_status]]
        )
        redirect "/item_lists/#{params[:user_id]}"
    else 
        erb :'seller/seller_items/add_item', layout: :'layouts/admin/layout'
    end 
end 

get '/store_lists' do 
    redirect '/login' unless logged_in?

    @errors = []
    @title = "Store Lists"

    # Fetch store + seller + user data 
    @stores = DB.execute <<-SQL 
        SELECT 
            stores.store_id, 
            stores.store_name, 
            stores.store_photo,
            stores.store_banner,
            stores.store_address,
            stores.store_status,
            stores.cs_number,
            users.name AS owner_name,
            users.email AS owner_email
        FROM stores
        JOIN sellers ON stores.seller_id = sellers.seller_id
        JOIN users ON sellers.user_id = users.user_id
        ORDER BY stores.store_id DESC
    SQL

    erb :'admin/store_dashboard/store_lists', layout: :'layouts/admin/layout'
end 

# DELETE a user
post '/delete_store/:store_id' do
    # Flash message
    session[:success] = "A store has been successfully deleted."

    DB.execute("DELETE FROM stores WHERE store_id = ?", [params[:store_id]])
    redirect '/store_lists'
end 

get '/store_bio/:store_id' do 
    redirect '/login' unless logged_in?

    @errors = []

    # Fetch store details with associated user information 
    store_query = <<-SQL 
        SELECT s.*, u.name as owner_name, u.user_id
        FROM stores s 
        JOIN sellers sl ON s.seller_id = sl.seller_id 
        JOIN users u ON  sl.user_id = u.user_id
        WHERE s.store_id = ?
    SQL

    @store = DB.execute(store_query, [params[:store_id]]).first

    if @store.nil?
        flash[:error] = "Store not found!"
        redirect back
    end 

    @title = "View My Store"

    erb :'seller/store_panel/view_store', layout: :'layouts/admin/layout'
end 

get '/edit_my_store/:store_id' do 
    redirect '/login' unless logged_in?

    @errors = []
    
    # Fetch store details with associated user information 
    store_query = <<-SQL 
        SELECT s.*, u.name as owner_name, u.user_id
        FROM stores s 
        JOIN sellers sl ON s.seller_id = sl.seller_id 
        JOIN users u ON  sl.user_id = u.user_id
        WHERE s.store_id = ?
    SQL

    @store = DB.execute(store_query, [params[:store_id]]).first

    if @store.nil?
        flash[:error] = "Store not found!"
        redirect back
    end 

    @title = "Store Lists"
    erb :'seller/store_panel/edit_my_store', layout: :'layouts/admin/layout'
end 

post '/edit_my_store/:store_id' do 
    redirect '/login' unless logged_in?

    @errors = validate_store(
        params[:store_name], 
        params[:store_address], 
        params[:store_status], 
        params[:cs_number], 
        params[:store_id]
    )

    # store_photo
    store_photo = params['store_photo']

    # store_banner
    store_banner = params['store_banner']

    # store_photo validation errors
    @errors += validate_store_photo(store_photo) if store_photo && store_photo[:tempfile] 

    # store_banner validation errors
    @errors += validate_store_banner(store_banner) if store_banner && store_banner[:tempfile]
    
    store_photo_filename = nil
    store_banner_filename = nil

    if @errors.empty?
        # Handle file store_photo upload 
        if store_photo && store_photo[:tempfile]
            store_photo_filename = "#{Time.now.to_i}_#{store_photo[:filename]}"
            File.open("./public/uploads/stores/#{store_photo_filename}", 'wb') do |f|
                f.write(store_photo[:tempfile].read)
            end 
        end 

        # Handle file store_banner upload
        if store_banner && store_banner[:tempfile]
            store_banner_filename = "#{Time.now.to_i}_#{store_banner[:filename]}"
            File.open("./public/uploads/stores/#{store_banner_filename}", 'wb') do |f|
                f.write(store_banner[:tempfile].read)
            end 
        end 

        flash[:success] = "Store updated successfully!"

        # Update store record
        DB.execute(
            "UPDATE stores 
                SET store_name = ?, 
                    store_address = ?, 
                    store_status = ?, 
                    cs_number = ?,     
                    store_photo = COALESCE(?, store_photo),
                    store_banner = COALESCE(?, store_banner)
                WHERE store_id = ?",
                [
                    params[:store_name],
                    params[:store_address],
                    params[:store_status], 
                    params[:cs_number],
                    store_photo_filename, 
                    store_banner_filename,
                    params[:store_id] 
                ]
        )
        redirect "/store_bio/#{params[:store_id] }"

    else 
        original_store = DB.execute("SELECT * FROM stores WHERE store_id = ?", params[:store_id]).first

        # Pre-fill @store with submitted values
        @store = {
            'store_id' => params[:store_id],
            'store_name' => params[:store_name] || original_store['store_name'],
            'store_address' => params[:store_address] || original_store['store_address'],
            'store_status' => params[:store_status] || original_store['store_status'],
            'cs_number' => params[:cs_number] || original_store['cs_number'],
            # Keep old images if user didn't upload new ones 
            'store_photo' => store_photo_filename || original_store['store_photo'],
            'store_banner' => store_banner_filename || original_store['store_banner']
        }

        erb :'seller/store_panel/edit_my_store', layout: :'layouts/admin/layout'
    end 

end 

get '/edit_an_item/:item_id' do 
    redirect '/login' unless logged_in?

    @item = DB.execute("SELECT * FROM items WHERE item_id = ?", [params[:item_id]]).first 

    @errors = []
    @title = "View Detail An Item"

    # Handle Item where the item does not exist
    if @item.nil? 
        session[:error] = "The Item is not found !"
        redirect "/item_lists/#{current_user['user_id']}"
    end 

    erb :'seller/seller_items/edit_item', layout: :'layouts/admin/layout'
end 

# Update an item
post '/edit_an_item/:item_id' do 
    @errors = validate_item(params[:item_name], params[:item_brand], params[:item_description], params[:item_price], params[:item_stock], params[:item_category], params[:item_unit], params[:item_status], params[:item_id])

    # item_photo
    item_photo = params['item_photo']

    # Validate only if a new item_photo is provided 
    @errors += validate_item_photo(item_photo) if item_photo && item_photo [:tempfile]

    photo_filename = nil 

    if @errors.empty? 

        # Handle file item_photo upload 
        if item_photo && item_photo[:tempfile]
            photo_filename = "#{Time.now.to_i}_#{item_photo[:filename]}"
            File.open("./public/uploads/items/#{photo_filename}", 'wb') do |f|
                f.write(item_photo[:tempfile].read)
            end 
        end 

        # Flash message 
        session[:success] = "An Item has been successfully updated."

        # Upload the item in the database
        DB.execute("UPDATE items 
                    SET item_name = ?, 
                    item_brand = ?, 
                    item_photo = COALESCE(?, item_photo), 
                    item_description = ?, 
                    item_price = ?, 
                    item_stock = ?, 
                    item_category = ?, 
                    item_unit = ?, 
                    item_status = ?
                WHERE item_id = ?", 
            [params[:item_name], params[:item_brand], photo_filename, params[:item_description], params[:item_price], params[:item_stock], params[:item_category], params[:item_unit], params[:item_status], params[:item_id]])
        redirect "/item_lists/#{current_user['user_id']}"
    else 
        # Handle validation errors and re-render the edit form 
        original_item = DB.execute("SELECT * FROM items WHERE item_id = ?", [params[:item_id]]).first

        # Merge validation errors and re-render the edit form 
        @item = {
            'item_id' => params[:item_id],
            'item_name' => params[:item_name] || original_item['item_name'],
            'item_brand' => params[:item_brand] || original_item['item_brand'],
            'item_photo' => photo_filename || original_item['item_photo'],
            'item_description' => params[:item_description] || original_item['item_description'],
            'item_price' => params[:item_price] || original_item['item_price'],
            'item_stock' => params[:item_stock] || original_item['item_stock'],
            'item_category' => params[:item_category] || original_item['item_category'],
            'item_unit' => params[:item_unit] || original_item['item_unit'],
            'item_status' => params[:item_status] || original_item['item_status']
        }
        erb :'seller/seller_items/edit_item', layout: :'layouts/admin/layout'
    end 
end 

# Delete an item 
post '/delete_an_item/:item_id' do 
    # Flash message 
    session[:success] = "The Item has been successfully deleted."

    # Delete logic 
    DB.execute("DELETE FROM items WHERE item_id = ?", [params[:item_id]])

    redirect "/item_lists/#{current_user['user_id']}"
end 

get '/seller_item_lists' do 
    redirect '/login' unless logged_in?

    @errors = []
    @title = "Seller Item Lists"

    @seller_items = DB.execute <<-SQL 
        SELECT 
            u.name AS seller_name,
            u.photo AS seller_photo,
            s.store_name,
            s.store_photo,
            i.item_name,
            i.item_brand,
            i.item_category, 
            i.item_photo, 
            i.item_price 
        FROM items i 
        JOIN stores s ON i.store_id = s.store_id 
        JOIN sellers se ON s.seller_id = se.seller_id 
        JOIN users u ON se.user_id = u.user_id 
    SQL

    erb :'admin/seller_dashboard/seller_item_lists', layout: :'layouts/admin/layout'

end 

get '/view_seller_items/:seller_id' do 
    redirect '/login' unless logged_in?

    @seller = DB.execute("SELECT * FROM items WHERE seller_id = ?", [params[:seller_id]]).first 

    erb :'admin/seller_dashboard/view_seller_items', layout: :'layouts/admin/layout'
end 

# View Detail Item
get '/view_detail_item_no_user/:item_id' do 
    @errors = []
    @title = 'View Detail An Item'

    @item = DB.execute("SELECT * FROM items WHERE item_id = ?", [params[:item_id]]).first 
    if @item.nil?
        flash[:error] = "Item not found!"
        redirect '/'
    end 
    
    erb :'user/items/view_item_no_user', layout: :'layouts/no_user/template'
end 

# View Detail Item
get '/view_detail_item/:item_id' do 
    redirect '/login' unless logged_in?

    @errors = []
    @title = 'View Detail An Item'


    @item = DB.execute("SELECT * FROM items WHERE item_id = ?", [params[:item_id]]).first 
    if @item.nil?
        flash[:error] = "Item not found!"
        redirect '/'
    end 
    
    erb :'user/items/view_item', layout: :'layouts/user/template'
end 

# Services list
get '/service_lists' do 
    redirect '/login' unless logged_in?
    
    @errors = []
    @title = 'Services'

    @services = DB.execute("SELECT * FROM services")

    erb :'admin/services/service_lists', layout: :'layouts/admin/layout'
end 

# Add service form
get '/add_a_service' do 
    redirect '/login' unless logged_in?
    
    @errors = []
    @title = 'Add A Service'

    erb :'admin/services/add_service', layout: :'layouts/admin/layout'
end 

# Add service action
post '/add_a_service' do 
    @errors = validate_service(params[:service_name], params[:fee])

    if @errors.empty?
        # Insert service details into the database
        DB.execute("INSERT INTO services
            (service_name, fee)
            VALUES (?, ?)",
            [params[:service_name], params[:fee]]
        )

        # Flash Message
        flash[:success] = "Service added successfully!"
        redirect "/service_lists" 
    else 
        erb :'admin/services/add_service', layout: :'layouts/admin/layout'
    end
end 

# Edit service form
get '/edit_a_service/:service_id' do 
    redirect '/login' unless logged_in?

    @service = DB.execute("SELECT * FROM services WHERE service_id = ?", [params[:service_id]]).first 
    
    @errors = []
    @title = 'Edit A Service'

    erb :'admin/services/edit_service', layout: :'layouts/admin/layout'
end 

post '/edit_a_service/:service_id' do 
    redirect '/login' unless logged_in?

    @errors = validate_service(params[:service_name], params[:fee], params[:service_id])

    if @errors.empty? 

        # Upload the service in the database 
        DB.execute("UPDATE services 
                    SET service_name = ?, 
                    fee = ?
                WHERE service_id = ?",    
            [params[:service_name], params[:fee], params[:service_id]])

        # Flash Message 
        flash[:success] = "Service has been successfully updated."
        redirect "/service_lists"
    else 
        # Handle Validation errors and re-render the edit form 
        original_service = DB.execute("SELECT * FROM services WHERE service_id = ?", [params[:service_id]]).first 

        # Merge validation errors and re-render the edit form 
        @service = {
            'service_id' => params[:service_id], 
            'service_name' => params[:service_name] || original_service['service_name'], 
            'fee' => params[:fee] || original_service['fee']
        }
        erb :'admin/services/edit_service', layout: :'layouts/admin/layout'
    end 
end 

# Delete a service 
post '/delete_a_service/:service_id' do 
    # Flash message
    flash[:success] = "Service has been successfully deleted."

    # Delete logic 
    DB.execute("DELETE FROM services WHERE service_id = ?", [params[:service_id]])

    redirect "/service_lists"
end 

post '/add_to_buyer/:item_id' do 
    redirect '/login' unless logged_in?

    item = DB.execute("SELECT * FROM items WHERE item_id = ?", [params[:item_id]]).first
    halt 404, "Item not found" if item.nil?

    quantity = params[:quantity].to_i 
    note = params[:note].to_s.strip 

    item_id = params[:item_id].to_i 
    user_id = session[:user_id]
    action = params[:action]

    # Prevent seller from ordering their own product 
    if owns_item?(user_id, item_id)
        flash[:notice] = "You cannot order your product."
        redirect back
    end 

    # Prevent invalid quantity 
    if quantity < 1
        flash[:error] = "Minimum order is 1"
        redirect back 
    end 

    # Get numeric price safely
    item_price = item['item_price'].to_i 
    total_price = item_price * quantity

    if params[:action] == "cart"
        # Insert into basket
        DB.execute(<<-SQL, [item['item_id'], item['store_id'], current_user['user_id'], quantity, total_price, note])
            INSERT INTO baskets (item_id, store_id, user_id, quantity, total_price, note)
            VALUES (?, ?, ?, ?, ?, ?);
        SQL

        flash[:success] = "Item added to basket"
        redirect "/basket"
        
    elsif params[:action] == "buy"
        # Insert into transactions 
        sql = "
            INSERT INTO transactions (
                store_id, item_id, user_id,
                wishlist_id, basket_id, service_id,
                quantity, total_price,
                payment_method, account_number, payment_photo, payment_status,
                transaction_date, note
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        "

        DB.execute(sql, [
            item['store_id'], item['item_id'], current_user['user_id'],
            nil, nil, nil, quantity, total_price,
            nil, nil, nil, 'Waited', Date.today.to_s, note
        ])
        
        flash[:success] = "Transaction created successfully"
        redirect "/transaction"
    else 
        flash[:error] = "Invalid action"
        redirect back
    end 
end 

# Basket page
get '/basket' do 
    redirect '/login' unless logged_in? 

    @title = "My Basket"
    @basket_items = DB.execute("SELECT b.*, i.item_name, i.item_photo, i.item_price 
                                FROM baskets b 
                                JOIN items i ON b.item_id = i.item_id
                                WHERE b.user_id = ?", [current_user['user_id']])
    erb :'user/items/basket', layout: :'layouts/user/template'
end 

post '/checkout/:basket_id' do 
    redirect '/login' unless logged_in?
    basket_id = params[:basket_id]

    # Step 1: Get basket data 
    basket = DB.execute("SELECT * FROM baskets WHERE basket_id = ? AND user_id = ?", [basket_id, current_user['user_id']]).first 

    if basket.nil?
        flash[:error] = "Basket not found or access denied."
        redirect '/basket'
    end 

    # Step 2: Create new transaction record
    begin 
        DB.execute(
            <<-SQL,
            INSERT INTO transactions (
                store_id, item_id, user_id, wishlist_id, basket_id, service_id,
                quantity, total_price, payment_method, account_number,
                payment_photo, payment_status, transaction_date, note
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            SQL
            [
                basket['store_id'],
                basket['item_id'],
                basket['user_id'],
                basket['wishlist_id'],
                basket['basket_id'],
                nil,
                basket['quantity'],
                basket['total_price'],
                nil, 
                nil,
                nil,
                "Waited",
                Time.now.strftime("%Y-%m-%d %H:%M:%S"),
                basket['note']
            ]
        )

        # Step 3: Delete basket record after transaction created
        DB.execute("DELETE FROM baskets WHERE basket_id = ?", [basket_id])

        flash[:success] = "Checkout successful! Basket moved to transactions."
        redirect '/transaction'

        rescue SQLite3::Exception => e 
            flash[:error] = "Error processing checkout: #{e.message}"
            redirect '/basket'
    end 
end 

#  Transaction page
get '/transaction' do 
    redirect '/login' unless logged_in?

    @title = "My Transaction"
    @transactions = DB.execute(<<-SQL, [current_user['user_id']])
        SELECT 
            t.transaction_id,
            t.transaction_date,
            t.quantity,
            t.total_price,
            t.payment_status,
            t.note,
            i.item_name,
            i.item_photo,
            i.item_price,
            s.store_name
        FROM transactions t
        JOIN items i ON t.item_id = i.item_id
        JOIN stores s ON t.store_id = s.store_id
        WHERE t.user_id = ?
        ORDER BY t.transaction_id DESC
    SQL

    erb :'user/items/transaction', layout: :'layouts/user/template'
end 

get '/user_basket_lists/:user_id' do 
    redirect '/login' unless logged_in?

    @errors = []
    @title = "User Basket Lists"

    user_id = params[:user_id]

    @baskets = DB.execute(<<-SQL, [user_id])
        SELECT 
            b.basket_id,
            i.item_name,
            st.store_name,
            u.name AS user_name,
            b.quantity,
            i.item_price AS unit_price,
            b.total_price,
            b.note
        FROM baskets b
        JOIN items i ON b.item_id = i.item_id
        JOIN stores st ON b.store_id = st.store_id
        JOIN users u ON b.user_id = u.user_id
        WHERE b.user_id = ?
        ORDER BY b.basket_id DESC
    SQL

    erb :'seller/seller_items/user_basket_lists', layout: :'layouts/admin/layout'
end 

get '/user_transaction_lists/:user_id' do 
    redirect '/login' unless logged_in?

    @errors = []
    @title = "User Transaction Lists"
    user_id = params[:user_id]

    @transactions = DB.execute(<<-SQL, [user_id])
        SELECT 
            t.transaction_id,
            s.store_name,
            i.item_name,
            u.name AS user_name,
            t.quantity,
            i.item_price AS unit_price,
            t.total_price,
            t.payment_method,
            t.account_number,
            t.payment_photo,
            t.payment_status,
            t.transaction_date
        FROM transactions t 
        JOIN items i ON t.item_id = i.item_id
        JOIN stores s ON t.store_id = s.store_id
        JOIN users u ON t.user_id = u.user_id 
        WHERE t.user_id = ?
        ORDER BY t.transaction_id DESC
    SQL

    erb :'seller/seller_items/user_transaction_lists', layout: :'layouts/admin/layout'
end 

post '/add_to_wishlist/:item_id' do 
    redirect '/login' unless logged_in?

    item_id = params[:item_id].to_i 
    user_id = session[:user_id]

    # Prevent seller from wishlisting their own product 
    if owns_item?(user_id, item_id)
        flash[:notice] = "You cannot add to wishlish for your product."
        redirect back
    end 

    # Find store_id from the item 
    store = DB.get_first_row("SELECT store_id FROM items WHERE item_id = ?", [item_id])

    if store.nil?
        flash[:error] = "Item not found."
        redirect back
    end 

    store_id = store['store_id']

    # Check if the item is already in user's wishlist 
    existing = DB.get_first_row("SELECT * FROM wishlists WHERE user_id = ? AND item_id = ?", [user_id, item_id])
    if existing 
        flash[:notice] = "Item already in your wishlist."
    else 
        DB.execute("INSERT INTO wishlists (item_id, store_id, user_id) VALUES (?, ?, ?)", [item_id, store_id, user_id])
        flash[:success] = "Item added to your wishlist!"
    end 

    redirect back
end 

get '/my_wishlists/:user_id' do 
    redirect '/login' unless logged_in?

    user_id = session[:user_id]
    @title = "My Wishlist"

    @wishlists = DB.execute(<<-SQL, [user_id])
        SELECT 
            w.wishlist_id,
            i.item_id, 
            i.item_name,
            i.item_photo,
            i.item_price,
            s.store_name
        FROM wishlists w 
        JOIN items i ON w.item_id = i.item_id 
        JOIN stores s ON w.store_id = s.store_id 
        WHERE w.user_id = ? 
        ORDER BY w.wishlist_id DESC
    SQL

    erb :'user/items/wishlist', layout: :'layouts/user/template'
end 

get '/users_wishlist/:user_id' do 
    redirect '/login' unless logged_in?
    
    @title = "Users Wishlist"

    erb :'seller/seller_items/users_wishlist', layout: :'layouts/admin/layout'
end 

get '/chat_seller/:store_id' do 
    redirect '/login' unless logged_in?

    user_id = session[:user_id]
    store_id = params[:store_id].to_i

    # Check if this store belongs to the current user
    owns_store = DB.get_first_value(<<-SQL, [user_id, store_id])
        SELECT COUNT(*)
        FROM stores s 
        JOIN sellers se ON s.seller_id = se.seller_id 
        WHERE se.user_id = ? AND s.store_id = ?
    SQL

    if owns_store.to_i > 0
        flash[:notice] = "You cannot chat with your own store."
        redirect back
    end 
end 

post '/payment/:transaction_id' do 

    @errors = 

    # Check if transaction exists and belongs to this user 
    trx = DB.execute("SELECT * FROM transactions WHERE transaction_id = ? AND user_id = ?", [transaction_id, session[:user_id]]).first 
    halt 404, "Transaction not found" if trx.nil?

    # Validate inputs
    if account_number.empty? || payment_method.empty? || payment_photo.nil?
        flash[:error] = "Please fill all payment fields."
        redirect back 
    end 

    # Handle file upload 
    filename = nil 
    if payment_photo[:filename] && payment_photo[:tempfile]
        ext = File.extname(payment_photo[:filename])
        filename = "payment_#{transaction_id}_#{Time.now.to_i}#{ext}"
        save_path = File.join("public", "uploads", "payments", filename)
        Dir.mkdir("public/uploads/payments") unless Dir.exist?("public/uploads/payments")
        File.open(save_path, "wb") { |f| f.write(payment_photo[:tempfile].read) }
    end 

    # Update transaction record 
    DB.execute(<<-SQL, [payment_method, account_number, filename, 'Paid', transaction_id])
        UPDATE transactions 
        SET payment_method = ?,
            account_number = ?,
            payment_photo = ?,
            payment_status = ?
        WHERE transaction_id = ?;
    SQL

    flash[:success] = "Payment submitted successfully! Waiting for seller confirmation."
    redirect '/account'
end 