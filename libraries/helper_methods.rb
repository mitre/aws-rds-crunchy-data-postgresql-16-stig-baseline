# libraries/helper_methods.rb

module CustomHelper
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

  class TableTypes
    MAPPING = {
      s: :sequence,
      v: :view,
      t: :table
    }.freeze

    class << self
      MAPPING.each do |short, full|
        define_method(short) { full }
      end

      def all
        MAPPING.values
      end

      def from_short(short)
        MAPPING[short.to_sym]
      end

      def to_short(name)
        MAPPING.key(name.to_sym)
      end
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
