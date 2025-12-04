require_relative 'relying_party_jwks_storage/base'
require_relative 'relying_party_jwks_storage/cache_storage'
require_relative 'relying_party_jwks_storage/env_storage'
module OmniauthStrongAuthOidc
  # Abstract interface for OpenID key storage
  # Implementations must provide a JWK set containing both signing and encryption keys
  module RelyingPartyJwksStorage

  end
end
