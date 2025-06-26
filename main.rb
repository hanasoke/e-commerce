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
        if user_id 
            query = "SELECT user_id FROM users WHERE LOWER(email) = ? AND user_id != ?"
            existing_email = DB.get_first_row(query, [email.downcase, user_id])
        else 
            query = "SELECT user_id FROM users WHERE LOWER(email) = ?"
            existing_email = DB.get_first_row(query, [email.downcase])
        end 
    end 

    errors
end 

# validate user 
def validate_user(name, username, email, password, birthdate, address, phone, access, user_id = nil)
    errors = []

    # name validation
    errors << "Name cannot be blank." if name.nil? || name.strip.empty?

    #  username validation
    errors << "Username cannot be blank." if username.nil? || username.strip.empty?

    # name validation 
    errors << "Password cannot be blank." if password.nil? || password.strip.empty?

    # birthdate validation 
    errors << "Birthdate cannot be blank." if birthdate.nil? || birthdate.strip.empty?

    # address
    errors << "Address cannot be blank." if address.nil? || address.strip.empty?

    # phone validation 
    if phone.nil? || phone.strip.empty? 
        errors << "Phone Cannot be Blank."
    elsif phone.to_s !~ /\A\d+(\.\d{1,2})?\z/
        errors << "Phone must be a valid number."
    elsif phone.to_i <= 0
        errors << "Phone must be a positive number."
    end

    # validate email 
    email_errors = validate_email(email, user_id)
    errors.concat(email_errors)

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

before do 

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
  
    # Find user by email
    user = DB.get_first_row("SELECT * FROM users WHERE LOWER(email) = ?", [email.downcase])
  
    if user && BCrypt::Password.new(user['password']) == password
        # Successful login
        session[:user_id] = user['user_id']
        session[:success] = "Login successful."
        redirect '/'
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