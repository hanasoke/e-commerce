require_relative "../lib/my_class"

RSpec.describe MyClass do 
    it "returns a greeting" do 
        expect(MyClass.hanas).to eq("Hanas Bayu Pratama, B.Sc")
    end 
end 