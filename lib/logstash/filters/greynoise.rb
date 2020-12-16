# encoding: utf-8
require 'logstash/filters/base'
require "json"
require "logstash/namespace"
require "ipaddr"
require "lru_redux"
require 'net/http'
require 'uri'

VERSION = "1.0.0"

class InvalidAPIKey < StandardError
end

# This  filter will replace the contents of the default
# message field with whatever you specify in the configuration.
#
class LogStash::Filters::Greynoise < LogStash::Filters::Base

  # Setting the config_name here is required. This is how you
  # configure this filter from your Logstash config.
  #
  #  filter {
  #   greynoise {
  #     ip => "ip"
  #   }
  #  }

  config_name "greynoise"

  # ip address to use for greynoise query
  config :ip, :validate => :string, :required => true

  # whether or not to use full context endpoint
  config :full_context, :validate => :boolean, :default => false

  # greynoise enterprise api key
  config :key, :validate => :string, :required => true

  # target top level key of hash response
  config :target, :validate => :string, :default => "greynoise"

  # tag if ip address supplied is invalid
  config :tag_on_failure, :validate => :string, :default => '_greynoise_filter_invalid_ip'

  # tag if API key not valid or missing
  config :tag_on_auth_failure, :validate => :string, :default => '_greynoise_filter_invalid_api_key'

  # set the size of cache for successful requests
  config :hit_cache_size, :validate => :number, :default => 0

  # how long to cache successful requests (in seconds)
  config :hit_cache_ttl, :validate => :number, :default => 60

  public

  def register
    if @hit_cache_size > 0
      @hit_cache = LruRedux::TTL::ThreadSafeCache.new(@hit_cache_size, @hit_cache_ttl)
    end
  end


  private

  def lookup_ip(target_ip, api_key, context = false)
    endpoint = "quick/"
    if context
      endpoint = "context/"
    end

    uri = URI.parse("https://api.greynoise.io/v2/noise/" + endpoint + target_ip)
    request = Net::HTTP::Get.new(uri)
    request["Key"] = api_key
    request["User-Agent"] = "logstash-filter-greynoise " + VERSION
    req_options = {
        use_ssl: uri.scheme == "https",
    }
    response = Net::HTTP.start(uri.hostname, uri.port, req_options) { |http|
      http.request(request)
    }

    if response.is_a?(Net::HTTPSuccess)
      result = JSON.parse(response.body)
      unless context
        result["seen"] = result.delete("noise")
      end
      result
    elsif response.is_a?(Net::HTTPUnauthorized)
      raise InvalidAPIKey.new
    else
      nil
    end
  end

  public

  def filter(event)
    valid = nil
    begin
      IPAddr.new(event.sprintf(ip))
    rescue ArgumentError => e
      valid = e
    end

    if valid
      @logger.error("Invalid IP address, skipping", :ip => event.sprintf(ip), :event => event.to_hash)
      event.tag(@tag_on_failure)
      return
    end

    if @hit_cache
      gn_result = @hit_cache[event.sprintf(ip)]

      # use cached data
      if gn_result
        event.set(@target, gn_result)
        filter_matched(event)
        return
      end
    end

    # use GN API, since not found in cache
    begin
      gn_result = lookup_ip(event.sprintf(ip), event.sprintf(key), @full_context)
      unless gn_result.nil?
        if @hit_cache
          # store in cache
          @hit_cache[event.sprintf(ip)] = gn_result
        end

        event.set(@target, gn_result)
        # filter_matched should go in the last line of our successful code
        filter_matched(event)
      end
    rescue InvalidAPIKey => _
      @logger.error("unauthorized - check API key")
      event.tag(@tag_on_auth_failure)
    end
  end

end
