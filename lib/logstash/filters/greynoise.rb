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
  #     ip => "%{[source][ip]}"
  #   }
  #  }

  config_name "greynoise"

  # ip address to use for greynoise query
  config :ip, :validate => :string, :required => true

  # whether or not to use full context endpoint
  config :full_context, :validate => :boolean, :default => false

  # greynoise enterprise api key
  config :key, :validate => :string, :required => false

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

    api_base = "https://api.greynoise.io/v2/noise/" + endpoint

    # Switch to community API if an apikey was not provided
    if api_key.strip.empty?
      api_base = "https://api.greynoise.io/v3/community/"
      @logger.debug("Greynoise API Key was not specified, defaulting to community API: " + api_base)
    end

    @logger.debug("Greynoise API to use: " + api_base)

    uri = URI.parse(api_base + target_ip)
    request = Net::HTTP::Get.new(uri)
    if !api_key.strip.empty?
      @logger.debug("Found Greynoise API key")
      request["Key"] = api_key
    end
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
      @logger.warn("Invalid IP address, skipping", :ip => event.sprintf(ip), :event => event.to_hash)
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

    @logger.debug("Could not find IP in local Greynoise cache, checking API...", :ip => event.sprintf(ip), :event => event.to_hash)

    # use GN API, since not found in cache
    begin
      gn_result = lookup_ip(event.sprintf(ip), event.sprintf(key), @full_context)
      unless gn_result.nil?
        if @hit_cache
          # store in cache
          @hit_cache[event.sprintf(ip)] = gn_result
        end

        event.set(@target, gn_result)
        @logger.debug("Successfully retrieved IP from Greynoise API...", :ip => event.sprintf(ip), :gn_result => gn_result, :event => event.to_hash)
        # filter_matched should go in the last line of our successful code
        filter_matched(event)
      end
    rescue InvalidAPIKey => _
      @logger.error("Unauthorized request to Greynoise - check API key", :ip => event.sprintf(ip), :event => event.to_hash)
      event.tag(@tag_on_auth_failure)
    end
  end

end
