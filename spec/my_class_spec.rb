require_relative "../lib/my_class"

RSpec.describe MyClass do 
    it 'fetches data from the database' do 
        my_instance = MyClass.new 
        expect {my_instance.fetch_data }.to output.to_stdout
    end 
end 