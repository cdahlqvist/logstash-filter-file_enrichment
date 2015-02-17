require "logstash/devutils/rspec/spec_helper"
require "logstash/filters/file_enrichment"
require "tempfile"

describe LogStash::Filters::FileEnrichment do
  
  describe "default enrichment" do
    tmp_file = Tempfile.new('logstash-spec-filter-file_enrichment')

    File.open(tmp_file, "w") do |fd|
      fd.puts('A:{"field1":"valueA1","field2","valueA2"}')
      fd.puts('B:{"field1":"valueB1","field2","valueB2"}')
    end

    config <<-CONFIG
      filter {
        file_enrichment {
          field => "data"
          dictionary_path => "#{tmp_file.path}"
        }
      }
    CONFIG

    sample("data" => "B") do
      insist { subject["field1"] } == "valueB1"
      insist { subject["field2"] } == "valueB2"
    end
  end

  describe "enrichment against specific destination" do
    tmp_file = Tempfile.new('logstash-spec-filter-file_enrichment')

    File.open(tmp_file, "w") do |fd|
      fd.puts('A:{"field1":"valueA1","field2","valueA2"}')
      fd.puts('B:{"field1":"valueB1","field2","valueB2"}')
    end

    config <<-CONFIG
      filter {
        file_enrichment {
          field => "data"
          destination => "added"
          dictionary_path => "#{tmp_file.path}"
        }
      }
    CONFIG

    sample("data" => "B") do
      insist { subject }.include?("added")
      insist { subject["added"]["field1"] } == "valueB1"
      insist { subject["added"]["field2"] } == "valueB2"
    end
  end

end
