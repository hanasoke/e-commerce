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
    end

    # Validate Email 
    email_errors = validate_email(email, user_id)
    errors.concat(email_errors)

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


# Routes 

# Homepage 
get '/' do 
    @errors = []
    @title = 'HomePage'
    erb :'user/no_account/index', layout: :'layouts/no_user/template'
end 

# Account 
get '/account' do 
    redirect '/login' unless logged_in?
    
    @errors = []
    @title = 'HomePage'
    erb :'user/index', layout: :'layouts/user/template'
end 

# Account 
get '/seller' do 
    redirect '/login' unless logged_in?
    
    @errors = []
    @title = 'Seller'
    erb :'seller/index', layout: :'layouts/user/template'
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
                redirect '/seller'
            elsif user['access'] == 3
                # Redirect to the admin page for admins
                redirect '/admin'
            else 
                @errors << "Invalid access level"
            end 

            if remember 
                response.set_cookie('remember_email', {
                    value: email,
                    path: '/account',
                    expires: Time.now + (60 * 60 * 24 * 30) # 30 days
                })
            else 
                response.delete_cookie('remember_email')
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
    @users = DB.execute("SELECT * FROM users")
    erb :'admin/index', layout: :'layouts/admin/layout'
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

        redirect '/admin'
    
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