FROM jruby:9

WORKDIR /usr/src/app
RUN bundle config unset frozen

COPY Rakefile Gemfile logstash-filter-greynoise.gemspec ./
COPY spec ./spec
COPY lib ./lib

RUN bundle install
