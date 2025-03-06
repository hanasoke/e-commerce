require 'mysql2'
require 'bundler/setup'
Bundler.require(:default)

# Database connection
client = Mysql2::Client.new(
    host: "localhost",
    username: "root",
    password: "",
    database: "e-commerce"
)

puts "Connected to MySQL successfully!"

# Example Queary
result = client.query("SELECT NOW() as current_time")
result.each do |row|
    puts "Current Time: #{row['current_TIME']}"
end 

