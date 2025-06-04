# libraries/helper_methods.rb

module ReportResultHelper
  def report_result(description)
    begin
      yield
      puts "PASS: #{description}"
    rescue RSpec::Expectations::ExpectationNotMetError => e
      puts "FAIL: #{description} - #{e.message}"
      raise e
    rescue StandardError => e
      puts "ERROR: #{description} - #{e.message}"
      raise e
    end
  end
end

# Include the helper module in the InSpec DSL
class Inspec::ProfileContext
  include ReportResultHelper
end

# Include the helper module in RSpec example groups
RSpec.configure do |config|
  config.include ReportResultHelper
end
