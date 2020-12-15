# logstash-filter-greynoise

You can build this project on your machine locally or alternative use the docker file to build and run an environment in Docker.

To use Docker, run the following:

```
# build the docker container for local dev
make build-docker

# shell into docker environment
make shell-docker

# set GN key for tests
export GN_API_KEY=<GN key>

# run tests
bundle exec rspec
``` 
