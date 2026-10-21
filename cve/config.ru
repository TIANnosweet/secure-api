# Minimal Rack application that mounts Sprockets exactly the way
# sprockets-rails does in a Rails 5.0 development environment:
#   mount Sprockets::Environment => '/assets'
require 'sprockets'
require 'rack'

root = File.expand_path('app', __dir__)
environment = Sprockets::Environment.new(root)
environment.append_path 'assets/images'
environment.append_path 'assets/javascripts'
environment.logger.level = Logger::INFO

map '/assets' do
  run environment
end

map '/' do
  run lambda { |_env|
    [200, { 'Content-Type' => 'text/html' }, ["<h1>blog</h1>\n"]]
  }
end
