# OmniAuth Strong Auth OIDC

An OmniAuth strategy for implementing strong authentication with Finnish Identification Broker Services via OpenID Connect (OIDC).

## Overview

This gem provides an OmniAuth strategy that implements the OpenID Connect Federation protocol for strong authentication with Finnish identification providers. It supports:

- **Private Key JWT authentication** for client authentication
- **JWE (JSON Web Encryption)** for encrypted ID tokens
- **Entity Statements** for federation metadata discovery
- **Key rotation** with multiple storage backends
- **Signed authorization requests** using JWT

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'omniauth_strong_auth_oidc'
```

And then execute:

```bash
bundle install
```

## Configuration

### Environment Variables

Configure the following environment variables:

```bash
# Required
OIDC_CLIENT_ID=your_client_id
OIDC_ACR_VALUES="your_acr_value1 your_acr_value2"

# Optional - For production with static keys
OIDC_SIGNING_KEY_BASE64=base64_encoded_signing_key
OIDC_ENCRYPTION_KEY_BASE64=base64_encoded_encryption_key

# Optional - For key rotation
OIDC_KEY_ROTATION_ENABLED=true

# Optional - Federation metadata URL
OAUTH_ISSUER_URL=https://your-issuer-url.com
```

## Usage with Devise

### Enable OmniAuth in User Model

Add the OmniAuth provider to your User model:

```ruby
class User < ApplicationRecord
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable,
         :omniauthable, omniauth_providers: [:strong_auth_oidc]
end
```

### Add Required Fields to User

Generate a migration to add OmniAuth fields:

```bash
rails generate migration AddOmniauthToUsers provider:string uid:string identity_number:string
rails db:migrate
```

### Configure Devise Initializer

In `config/initializers/devise.rb`, configure the OmniAuth provider:

```ruby
Devise.setup do |config|
  # ... other Devise configuration ...

  # Configure entity statement fetcher
  provider_entity_statement_fetcher = OmniauthStrongAuthOidc::EntityStatementFetcher::FileFetcher.new(
    path_to_file: Rails.root.join("config", "oidc_test_entity_statement").to_s
  )

  if ENV["OAUTH_ISSUER_URL"].present?
    provider_entity_statement_fetcher = OmniauthStrongAuthOidc::EntityStatementFetcher::FederationUrlFetcher.new(
      issuer_url: ENV.fetch("OAUTH_ISSUER_URL")
    )
  end

  # Configure JWKS storage
  if ENV['OIDC_SIGNING_KEY_BASE64'].present? && ENV['OIDC_ENCRYPTION_KEY_BASE64'].present?
    relying_party_jwks_storage = OmniauthStrongAuthOidc::RelyingPartyJwksStorage::EnvStorage.new
  elsif ENV['OIDC_KEY_ROTATION_ENABLED'] == 'true'
    cache_store = Rails.cache
    # Use in-memory store in non-production environments if cache is NullStore
    # this is useful for development and testing
    # Use a more robust cache store in production (e.g., Memcached, Redis)
    if Rails.cache.is_a?(ActiveSupport::Cache::NullStore) && !Rails.env.production?
      cache_store = ActiveSupport::Cache::MemoryStore.new
    end
    relying_party_jwks_storage = OmniauthStrongAuthOidc::RelyingPartyJwksStorage::CacheStorage.new(
      cache_store: cache_store
    )
  else
    raise "OIDC signing and encryption keys are not configured. Please set OIDC_SIGNING_KEY_BASE64 and OIDC_ENCRYPTION_KEY_BASE64 environment variables, or enable key rotation with OIDC_KEY_ROTATION_ENABLED."
  end

  OmniauthStrongAuthOidc::RelyingPartyJwksStorage::Base.instance ||= relying_party_jwks_storage

  provider_jwks_fetcher = OmniauthStrongAuthOidc::JwksFetcher.new(
    entity_statement_fetcher: provider_entity_statement_fetcher
  )

  config.omniauth :strong_auth_oidc,
    client_id: ENV.fetch("OIDC_CLIENT_ID"),
    relying_party_jwks_storage: relying_party_jwks_storage,
    provider_jwks_loader: OmniauthStrongAuthOidc::JwksCache.new(provider_jwks_fetcher),
    provider_entity_statement_fetcher: provider_entity_statement_fetcher,
    authorize_params: {
      acr_values: ENV.fetch("OIDC_ACR_VALUES").split(' '),
      response_type: 'code',
      scope: 'openid'
    },
    client_options: {
      auth_scheme: :private_key_jwt
    }
end
```

### Create OmniAuth Callbacks Controller

```ruby
class Users::OmniauthCallbacksController < Devise::OmniauthCallbacksController
  def strong_auth_oidc
    @user = User.from_omniauth(request.env['omniauth.auth'])

    if @user.persisted?
      sign_in_and_redirect @user, event: :authentication
      set_flash_message(:notice, :success, kind: 'Strong Auth') if is_navigational_format?
    else
      session['devise.strong_auth_oidc_data'] = request.env['omniauth.auth'].except(:extra)
      redirect_to new_user_registration_url
    end
  end

  def failure
    redirect_to root_path, alert: "Authentication failed: #{failure_message}"
  end
end
```

### Add Class Method to User Model

```ruby
class User < ApplicationRecord
  # ... devise configuration ...

  def self.from_omniauth(auth)
    where(provider: auth.provider, uid: auth.uid).first_or_create do |user|
      user.email = "#{auth.uid}@strong-auth.local" # or handle email differently
      user.password = Devise.friendly_token[0, 20]
      user.identity_number = auth.info.identity_number
      # user.first_name = auth.info.first_name
      # user.last_name = auth.info.last_name
    end
  end
end
```

### Configure Routes

```ruby
Rails.application.routes.draw do
  devise_for :users, controllers: {
    omniauth_callbacks: 'users/omniauth_callbacks'
  }
end
```

### Add Login Link to View

```erb
<%= link_to "Sign in with Finnish Strong Authentication", user_strong_auth_oidc_omniauth_authorize_path %>
```

## Federation Endpoints Controller

To expose the required OIDC federation endpoints (entity statement, JWKS), use the Rails generator:

```bash
rails generate omniauth_strong_auth_oidc:install \
  --redirect_uris="https://example.com/users/auth/strong_auth_oidc/callback" \
  --org_name="Your Organization Name" \
  --iss="https://example.com"
```

**Generator options:**

| Option | Required | Description |
|--------|----------|-------------|
| `--redirect_uris` | Yes | Comma-separated list of OAuth callback URLs |
| `--org_name` | Yes | Your organization name for the entity statement |
| `--iss` | Yes | Issuer URL (your application's base URL) |

**Example with multiple redirect URIs:**

```bash
rails generate omniauth_strong_auth_oidc:install \
  --redirect_uris="https://example.com/users/auth/strong_auth_oidc/callback,https://staging.example.com/users/auth/strong_auth_oidc/callback" \
  --org_name="Acme Corporation" \
  --iss="https://example.com"
```

This will:
1. Create `app/controllers/relying_party_entity_statement_controller.rb`
2. Add the following routes to `config/routes.rb`:

```ruby
# OIDC Federation endpoints
get '/.well-known/openid-federation', to: 'relying_party_entity_statement#entity_statement', as: :openid_federation
get '/.well-known/jwks.json', to: 'relying_party_entity_statement#jwks', as: :jwks
get '/.well-known/signed-jwks.jwt', to: 'relying_party_entity_statement#signed_jwks', as: :signed_jwks
```

The generated controller provides the following endpoints:

| Endpoint | Content-Type | Description |
|----------|--------------|-------------|
| `/.well-known/openid-federation` | `application/entity-statement+jwt` | Signed entity statement JWT |
| `/.well-known/jwks.json` | `application/json` | Public JWKS for token encryption |
| `/.well-known/signed-jwks.jwt` | `application/jwks+jwt` | Signed JWKS JWT |

**Additional environment variable required:**

```bash
OIDC_CONFIGURATION_SIGNING_KEY_BASE64=base64_encoded_configuration_signing_key
```

This key is used to sign the entity statement and JWKS. It should be a separate RSA key pair from the signing/encryption keys used for tokens.

## Key Storage Options

### Environment Storage (EnvStorage)

Store static keys in environment variables:

```bash
OIDC_SIGNING_KEY_BASE64=<base64_encoded_private_key>
OIDC_ENCRYPTION_KEY_BASE64=<base64_encoded_private_key>
```

### Cache Storage (CacheStorage)

Enable automatic key rotation using Rails cache:

```bash
OIDC_KEY_ROTATION_ENABLED=true
```

Keys are automatically generated and rotated based on cache TTL.

## Entity Statement Fetchers

### File Fetcher

For testing and development, load entity statements from a local file:

```ruby
OmniauthStrongAuthOidc::EntityStatementFetcher::FileFetcher.new(
  path_to_file: Rails.root.join("config", "oidc_entity_statement.json").to_s
)
```

### Federation URL Fetcher

For production, fetch entity statements from the federation URL:

```ruby
OmniauthStrongAuthOidc::EntityStatementFetcher::FederationUrlFetcher.new(
  issuer_url: ENV.fetch("OAUTH_ISSUER_URL")
)
```

## User Attributes

The strategy returns the following user attributes:

- `uid`: Unique identifier (subject)
- `identity_number`: Finnish personal identity code (urn:oid:1.2.246.21)
- `first_name`: Given name (urn:oid:1.2.246.575.1.14)
- `last_name`: Family name (urn:oid:2.5.4.4)

Raw claims are available in `auth['extra']['raw_info']`.

## Development

After checking out the repo, run:

```bash
bundle install
bundle exec rspec
```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/kiskolabs/omniauth_strong_auth_oidc.

## License

The gem is available as open source under the terms of the [MIT License](LICENSE).
