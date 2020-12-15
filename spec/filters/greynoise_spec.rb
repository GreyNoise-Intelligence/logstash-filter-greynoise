# encoding: utf-8
require_relative '../spec_helper'
require "logstash/filters/greynoise"

describe LogStash::Filters::Greynoise do
  describe "defaults" do
    let(:config) do
      api_key = ENV["GN_API_KEY"]
      <<-CONFIG
      filter {
        greynoise {
          ip => "%{ip}"          
          key => "#{api_key}"          
        }
      }
      CONFIG
    end

    sample("ip" => "8.8.8.8") do
      insist { subject }.include?("greynoise")
      expected_fields = %w(ip seen code)
      expected_fields.each do |f|
        insist { subject.get("greynoise") }.include?(f)
      end
      insist { subject.get("greynoise").get("code").equal?("0x05") }
    end

    sample("ip" => "4.2.1.A") do
      insist { subject.get("tags") }.include?("_greynoise_filter_invalid_ip")
    end
  end

  describe "invalid_key" do
    let(:config) do
      <<-CONFIG
      filter {
        greynoise {
          ip => "%{ip}"          
          key => "BAD_KEY"          
        }
      }
      CONFIG
    end

    sample("ip" => "8.8.8.8") do
      insist { subject.get("tags") }.include?("_greynoise_filter_invalid_api_key")
    end
  end
end
