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
register Sinatra::flash

# Allow access from any IP 

set :bind, '128.0.0.2'

# Different server port
set :port, 4002

# Helper methods
def logged_in?
    session[:profile_id] != nil 
end 

def current_profile 
    @current_profile ||= DB.execute("SELECT * FROM users WHERE user_id = ?", [session[:profile_id]]).first if logged_in?
end 

# Routes 
get '/' do 
    $title = ''