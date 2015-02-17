# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "json"
require "digest"

# A general enrichment tool that adds fields to the event based on
# the contants of a dictionary file. As the value used for enrichment
# is defined as a JSON string, the event can be enriched with nested 
# structures.

class LogStash::Filters::FileEnrichment < LogStash::Filters::Base
  config_name "file_enrichment"
  milestone 1

  # The name of the logstash event field containing the value to be compared for a
  # match by the file enrichment filter (e.g. `userid`, `server`). 
  # 
  # If this field is an array, fields will be processed until a match is found.
  config :field, :validate => :string, :required => true

  # If the destination field already exists, this configuration item specifies
  # whether the filter should overwrite it or not with the enrichment value. 
  config :override, :validate => :boolean, :default => false

  # The full path of the external dictionary file. The format of the file
  # should be a standard YAML file, where the value must be a valid JSON string.
  # 
  # An example file could look like this:
  #
  # FR:{"capital":"Paris","currency":{"name":"Euro","abbreviation":"EUR"}}
  # GB:{"capital":"London","currency":{"name":"Pound","abbreviation":"GBP"}}
  config :dictionary_path, :validate => :path, :required => true

  # String used to separate the key from the JSON value in the dictionary file.
  # Defaults to ":".
  config :separator, :validate => :string, :default => ":"

  # This setting indicates how frequently (in seconds) logstash will check the
  # directory file for updates.
  config :refresh_interval, :validate => :number, :default => 300
  
  # The destination field you wish to populate with the enrichment data. If not 
  # specified, the filter will default to directly enriching the base event.
  config :destination, :validate => :string, :default => ""

  public
  def register
    if !load_dictionary_file(true)
      raise "Terminating due to error loading dictionary file: #{@dictionary_path}"
    else
      @checksum = calculate_dictionary_file_checksum()

      @logger.debug("Starting file_enrichment refresher thread")
      Thread.new { refresher() }
    end
  end # def register

  public
  def filter(event)
    return unless filter?(event)
    return unless event.include?(@field) # Skip enrichment in case event does not have @field defined.
    
    dict_handle = @dictionary
    begin
      keylist = event[@field].is_a?(Array) ? event[@field].map(&:to_s) : [event[@field].to_s]

      keylist.each do |key|
        if dict_handle.has_key?(key)
          merge_result_into_event(event, dict_handle[key])
          break
        end
      end
    end
  end # def filter

  private
  def calculate_dictionary_file_checksum()
    md5 = Digest::MD5.new
    File.open(@dictionary_path,'rb') do |ios|
      ios.each {|line| md5 << line }
    end
    return md5.hexdigest
  end # def calculate_file_checksum

  private
  def load_dictionary_file(initial)
    if !File.exists?(@dictionary_path)
      if initial
        @logger.error("Dictionary file not found, continuing with existing dictionary", :path => @dictionary_path)
      else
        @logger.error("Dictionary file not found.", :path => @dictionary_path)
      end
      return false 
    else
      new_dictionary = {}
      f = File.open(@dictionary_path, "r")
      linenum = 1
      f.each_line do |line|
        k = line.split(/#{@separator}/, 2).map(&:strip)

        if k.size() == 1
          @logger.error("Error parsing line number #{linenum}: #{line}", :path => @dictionary_path)
          f.close()
          return false
        else
          begin
            new_dictionary[k[0]] = JSON.parse(k[1])
          rescue JSON::ParserError
            @logger.error("Error parsing JSON on line number #{linenum}: #{line}", :path => @dictionary_path)
            f.close()
            return false
          end
        end
      end

      f.close()
      @logger.info("Loaded dictionary file containing #{linenum} entries.", :path => @dictionary_path)
      @dictionary = new_dictionary
    end

    return true
  end # def load_dictionary_file

  private
  def merge_result_into_event(event, result)
    if @destination == ""
      result.each do |field, value|
        if @override || !event.include?(field)
          event[field] = value
        end
      end
    elsif event.include?(@destination)
      result.each do |field, value|
        if @override || !event.include?(@destination)
          event[@destination] = result
        end
      end
    end
  end # def merge_result_into_event
  
  private
  def refresher()
    LogStash::Util::set_thread_name("<file_enrichment.refresher>")
    begin
      while true
        sleep(@refresh_interval)
 
        if File.exists?(@dictionary_path) 
          cs = calculate_dictionary_file_checksum()
          if @checksum == cs
            @logger.info("Dictionary file checksum has not changed. Check again in #{refresh_interval} seconds.", :path => @dictionary_path)
          else
            load_dictionary_file(false)
          end
        else
          @logger.error("Dictionary file not found, continuing with existing dictionary", :path => @dictionary_path)
        end
      end
    rescue => e
      @logger.error("Exception in refresher", "exception" => e, "backtrace" => e.backtrace)
    end
  end # def refresher

end # class LogStash::Filters::FileEnrichment
