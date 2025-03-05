require 'mysql2'

class MyClass
  def initialize
    @client = Mysql2::Client.new(
      host: 'localhost',
      username: 'root',
      password: '',
      database: 'e-commerce',
      port: 3319
    )
  end

  def fetch_data
    results = @client.query("SELECT * FROM sellers")
    results.each do |row|
      puts row 
    end 
  end 
end 