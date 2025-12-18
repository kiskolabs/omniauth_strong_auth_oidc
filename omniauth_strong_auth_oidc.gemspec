# frozen_string_literal: true

require_relative "lib/omniauth_strong_auth_oidc/version"

Gem::Specification.new do |spec|
  spec.name          = "omniauth_strong_auth_oidc"
  spec.version       = OmniauthStrongAuthOidc::VERSION
  spec.authors       = ["Kisko Labs", "Dmitry Gusev"]
  spec.email         = ["dmitry@kiskolabs.com"]

  spec.summary       = %q{OmniAuth strategy for Strong Auth OIDC}
  spec.description   = "OmniAuth strategy for implementing strong authentication with Finnish Identification Broker Services via OpenID Connect (OIDC)."
  spec.homepage      = "https://github.com/kiskolabs/omniauth_strong_auth_oidc"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^spec/}) }
  spec.require_paths = ["lib"]

  spec.add_dependency "omniauth-oauth2", "~> 1.8"
  spec.add_dependency "jwt", "~> 2.10"
  spec.add_dependency "jwe", "~> 1.1"
  spec.add_dependency "http", "~> 5.0"

  spec.add_development_dependency "bundler"
  spec.add_development_dependency "rake"
  spec.add_development_dependency "rspec", "~> 3.0"
  spec.add_development_dependency "activesupport", "~> 7.0"

  spec.metadata = {
    "allowed_push_host" => "https://rubygems.org"
  }
end
