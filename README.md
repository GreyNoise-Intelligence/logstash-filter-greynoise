# Logstash Greynoise Filter 
This is a filter plugin for [Logstash](https://github.com/elastic/logstash).

It is fully free and fully open source. The license is Apache 2.0, meaning you are pretty much free to use it however you want in whatever way.

## Documentation

The GreyNoise filter adds information about IP addresses from logstash events via the GreyNoise API.

GreyNoise is a system that collects and analyzes data on Internet-wide scanners.
GreyNoise collects data on benign scanners such as Shodan.io, as well as malicious actors like SSH and telnet worms.

## Usage
### 1. Installation
You can use the built-in plugin tool of Logstash to install the filter:
```
$LS_HOME/bin/logstash-plugin install logstash-filter-greynoise
```

Or you can build it yourself:
```
git clone https://github.com/nicksherron/logstash-filter-greynoise.git
bundle install
gem build logstash-filter-greynoise.gemspec
$LS_HOME/bin/logstash-plugin install logstash-filter-greynoise-0.1.7.gem
```

### 2. Filter Configuration

```sh
filter {
  greynoise {
    ip             => "ip_value"              # string (required, reference to ip address field)
    full_context   => true                    # bool (optional, whether to use context lookup, default false)
    key            => "your_greynoise_key"    # string (required)
    target         => "greynoise"             # string (optional, default = greynoise)
    hit_cache_size => 100                     # number (optional, default = 0)
    hit_cache_ttl  => 6                       # number (optional, default = 60) 
  }
}
```
The GreyNoise Logstash filter plugin can be used in two different modes:

##### Quick IP Enrichment
In this mode documents (default) are enriched with a bool field `seen` which is true if GreyNoise has seen this IP or false otherwise. 

This mode is faster than doing full enrichment and should be used for better performance on high-volume/-throughput event streams.
If you have a data pipeline with multiple enrichment points, you can use the boolean field to later enrich the document with IP information from GreyNoise's context endpoint.

##### Full IP Enrichment

In this mode (`full_context => true`), documents are enriched with full context from GreyNoise API if the IP has been observed by GreyNoise. 

This mode is slower than doing quick IP enrichment and might be reasonable for low-volume/-throughput event streams. 

**NOTE**: Beware that the full context document from GreyNoise API can be large and as such the cache can grow quickly in size. Set the cache size accordingly to prevent high memory consumption by the cache.

Print plugin version:

``` bash
bin/logstash-plugin list --verbose | grep greynoise
```

Example for running logstash from `cli`:

``` bash
bin/logstash --debug -e \
'input {
    stdin {}
}


filter {
  greynoise {
    ip => "%{message}"
   }
}

output {
   stdout {
      codec => rubydebug {
          metadata => true
          }
      }
}'
```



## Contributing

All contributions are welcome: ideas, patches, documentation, bug reports, complaints, and even something you drew up on a napkin.

Programming is not a required skill. Whatever you've seen about open source and maintainers or community members  saying "send patches or die" - you will not see that here.

It is more important to the community that you are able to contribute.

For more information about contributing, see the [CONTRIBUTING](https://github.com/elasticsearch/logstash/blob/master/CONTRIBUTING.md) file.
