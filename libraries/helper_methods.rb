# libraries/helper_methods.rb

module CustomHelper

  # Returns a hash mapping PostgreSQL log line escape sequences to their human-readable descriptions.
  #
  # @return [Hash{String => String}] a mapping of escape sequences (e.g., '%d', '%p') to their meanings
  #
  ESCAPE_LOOKUP = {
    '%d' => 'database name',
    '%p' => 'process ID',
    '%r' => 'remote host and port',
    '%t' => 'timestamp without milliseconds',
    '%u' => 'user name'
  }.freeze


  # TableTypes provides utility methods for mapping between PostgreSQL table type short codes
  # and their corresponding full names. The mapping is case-insensitive and supports both
  # conversion from short code to full name and vice versa.
  #
  # Constants:
  #   MAPPING - A frozen hash mapping single-character symbols (short codes) to full type names.
  #
  # Class Methods:
  #   all
  #     Returns an array of all full type names defined in the mapping.
  #
  #   from_short(short)
  #     Given a short code (single character, case-insensitive), returns the corresponding full type name.
  #     If the short code is not found, returns the symbolized input.
  #
  #   to_short(name)
  #     Given a full type name (case-insensitive), returns the corresponding short code symbol.
  #     If the name is not found, returns the symbolized input.
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
