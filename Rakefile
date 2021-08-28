require 'rake'
require_relative 'lib/gollum/auth/version.rb'

def name
  @name ||= Dir['*.gemspec'].first.split('.').first
end

def version
  Gollum::Auth::VERSION
end

def gemspec_file
  "#{name}.gemspec"
end

def gem_file
  "#{name}-#{version}.gem"
end

task :default => :install

desc 'Build gem'
task :build do
  sh "mkdir -p pkg"
  sh "gem build #{gemspec_file}"
  sh "mv #{gem_file} pkg"
end

desc "Build and install"
task :install => :build do
  sh "gem install --local --no-document pkg/#{gem_file}"
end
