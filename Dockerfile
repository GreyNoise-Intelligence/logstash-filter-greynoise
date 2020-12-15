FROM jruby:9

WORKDIR /usr/src/app

COPY Rakefile Gemfile Gemfile.lock logstash-filter-greynoise.gemspec ./
COPY spec ./spec
COPY lib ./lib

RUN bundle install
