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
      a: :aggregate,
      b: :base_type,      
      c: :composite_type,
      d: :domain,
      e: :event_trigger,      
      f: :foreign_table,
      i: :index,
      I: :partitioned_index,
      l: :language,
      m: :materialized_view,      
      n: :namespace,
      o: :operator,      
      p: :partitioned_table,
      r: :range_type,      
      s: :sequence,
      S: :sequence,
      t: :TOAST_table,
      u: :user_defined_type,      
      v: :view,
      x: :extension,
    }.freeze

    class << self
      # Create a new hash combining the original mapping with uppercase keys
      CASE_INSENSITIVE_MAPPING = MAPPING.merge(
        MAPPING.transform_keys { |key| key.to_s.upcase.to_sym }
      ).freeze

      # Return all full names from MAPPING
      def all
        MAPPING.values
      end

      # Get the full name from a short (case-insensitive)
      def from_short(short)
        CASE_INSENSITIVE_MAPPING[short.to_s.downcase.to_sym] || short.to_sym  # Return the original key if not found
      end

      # Get the short name from the full name (case-insensitive)
      def to_short(name)
        key = CASE_INSENSITIVE_MAPPING.key(name.to_sym)
        key || name.to_sym  # Return the original name if not found
      end
    end
  end
end

# Include the helper module in the InSpec DSL
class Inspec::ProfileContext
  include CustomHelper
end

# Include the helper module in RSpec example groups
RSpec.configure do |config|
  config.include CustomHelper
end
