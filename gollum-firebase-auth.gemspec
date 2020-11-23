# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'gollum/auth/version'

Gem::Specification.new do |spec|
  spec.name          = 'gollum-firebase-auth'
  spec.version       = Gollum::Auth::VERSION
  spec.authors       = ['Nikita Ivanov']

  spec.summary       = "#{spec.name}-#{spec.version}"
  spec.description   = 'Firebase Authentication Middleware for Gollum Wiki'
  spec.homepage      = 'https://github.com/ViChyavIn/gollum-firebase-auth'
  spec.license       = 'MIT'
  spec.required_ruby_version = '>= 2.0.0'

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = 'exe'
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']

  spec.add_dependency 'rack'
  spec.add_dependency 'mustache'
  spec.add_dependency 'jwt'

  spec.add_development_dependency 'rake', '~> 10.0'
  spec.add_development_dependency 'rspec', '~> 3.0'
  spec.add_development_dependency 'rack-test', '~> 0.6'
  spec.add_development_dependency 'factory_bot', '~> 4.8'
  spec.add_development_dependency 'faker', '~> 1.7'
end
