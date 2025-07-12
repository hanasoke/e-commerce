require 'sinatra'
require 'sinatra/flash'
require 'bcrypt'
require_relative 'database/e-commerce'
require 'prawn'
require 'rubyXL'
require 'prawn/table'
require 'write_xlsx'

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

def current_user 
    @current_user ||= DB.execute("SELECT * FROM users WHERE user_id = ?", [session[:user_id]]).first if logged_in?
end 

# validate email 
def validate_email(email, user_id = nil)
    errors = []

    # Regular expression for email validation
    email_regex = /\A[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\z/

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
    end

    # Validate Email 
    email_errors = validate_email(email, user_id)
    errors.concat(email_errors)

    errors
end 

def editing_user(name, username, email, birthdate, address, phone, access, id = nil)

    errors = []

    errors << "Name cannot be blank." if name.nil? || name.strip.empty?
    errors << "Username cannot be blank." if username.nil? || username.strip.empty?
    
    errors << "Birthdate cannot be blank." if birthdate.nil? || birthdate.strip.empty?

    errors << "Address cannot be blank." if address.nil? || address.strip.empty?

    errors << "Phone cannot be blank."if phone.nil? || phone.strip.empty?

    errors << "Access cannot be blank." if access.nil? || access.strip.empty?

    # Validate email 
    errors.concat(validate_email(email))
    errors
end 

def validate_user(name, username, email, password, birthdate, address, phone, access, user_id = nil)

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

        # Check file sizee (5MB max, 40KB min)
        max_size = 4 * 1024 * 1024 # 4MB in bytes
        min_size = 40 * 1024       # 40KB in bytes
        file_size = photo[:tempfile].size if photo[:tempfile] && photo[:tempfile].respond_to?(:size)

        if file_size.nil? 
            errors << "Photo file size could not be determined."
        elsif file_size > max_size 
            errors << "Photo size must be less than 4MB."
        elsif file_size < min_size 
            errors << "Photo size must be greater than 40KB."
        end 
    end 

    errors 
end 

# Routes 

# Homepage 
get '/' do 
    @errors = []
    @title = 'HomePage'
    erb :'user/index', layout: :'layouts/user/template'
end 

# Login
get '/login' do 
    @errors = []
    @title = 'Login'
    erb :'sign/login', layout: :'layouts/sign/template'
end 

post '/login' do
    @errors = []
    email = params[:email].to_s.strip
    password = params[:password]
    remember = params[:remember]
  
    # Find user by email
    user = DB.get_first_row("SELECT * FROM users WHERE LOWER(email) = ?", [email.downcase])
  
    if user && BCrypt::Password.new(user['password']) == password
        # Successful login
        session[:user_id] = user['user_id']
        session[:success] = "Login successful."

        if remember 
            response.set_cookie('remember_email', {
                value: email,
                path: '/',
                expires: Time.now + (60 * 60 * 24 * 30) # 30 days
            })
        else 
            response.delete_cookie('remember_email')
        end 

        redirect '/admin'
    else
        # Failed login
        @errors << "Invalid email or password."
        @title = 'Login'
        erb :'sign/login', layout: :'layouts/sign/template'
    end
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
    @errors = []
    @title = "Admin"
    @users = DB.execute("SELECT * FROM users")
    erb :'admin/index', layout: :'layouts/admin/layout'
end