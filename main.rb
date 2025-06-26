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

def current_profile 
    @current_profile ||= DB.execute("SELECT * FROM users WHERE user_id = ?", [session[:user_id]]).first if logged_in?
end 

# validate email 
def validate_email(email)
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
        #Check for Email fields 
        query = user_id ? "SELECT user_id FROM users WHERE LOWER (email) = ? AND user_id != ?" : "SELECT user_id FROM users WHERE LOWER(email) = ?"

        existing_email = DB.execute(query, id ? [email.downcase, id] : [email.downcase]).first
        errors << "Email already exist. Please choose a different name." if existing_email
    end 

    errors
end 

# validate user 
def validate_user(name, username, email, password, birthdate, address, phone, access, id = nil)
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
    email_errors = validate_email(email)
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

# Login
get '/' do 
    @errors = []
    @title = 'Login'
    erb :'sign/login', layout: :'layouts/sign/template'
end 

# Register 
get '/register' do 
    @errors = []
    @title = "Register Dashboard"
    erb :'sign/register', layout: :'layouts/sign/template'
end 

post '/register' do 
    # Validate inputs 
    @errors = validate_user(params[:name], params[:username], params[:email], params[:password], params[:birthdate], params[:address], params[:phone], params[:access])

    # Flash message
    session[:success] = "Your Account has been registered."

    photo = params['photo']
    @errors += validate_photo(photo) if photo # Add photo validation errors 

    photo_filename = nil 

    if @errors.empty?
        # Handle photo upload
        if photo && photo[:tempfile]
            photo_filename = "#{Time.now.to_i}_#{photo[:filename]}",
            File.open("./public/uploads/#{photo_filename}", 'wb') do |f|
                f.write(photo[:tempfile].read)
            end
        end 

        name = params[:name]
        username = params[:username]
        email = params[:email]
        password = BCrypt::Password.create(params[:password])
        birthdate = params[:birthdate]
        address = params[:address]
        phone = params[:phone]
        access = params[:access]

        begin
            DB.execute("INSERT INTO users (name, username, email, password, birthdate, address, phone, photo, access) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)", [name, username, email, password, birthdate, address, phone, photo_filename, access])

            redirect '/'
        
        rescue SQLite3::ConstraintException
            @errors << "Username already exists"
        end 

    end 
    erb :'sign/login', layout: :'layouts/sign/template'
end 

get '/reset_password' do 
    @errors = []
    @title = "Reset Password"
    erb :'sign/reset_password', layout: :'layouts/sign/template'
end 
