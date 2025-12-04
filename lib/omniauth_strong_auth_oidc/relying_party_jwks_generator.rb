module OmniauthStrongAuthOidc
  # Generates a signed JWKS JWT containing the client's public keys
  # This is separate from the plain JWKS endpoint and is signed by the entity statement key
  class RelyingPartyJwksGenerator
    attr_reader :relying_party_jwks_storage, :relying_party_configuration_jwks_storage, :issuer

    def initialize(relying_party_jwks_storage:, relying_party_configuration_jwks_storage:, issuer:)
      @relying_party_jwks_storage = relying_party_jwks_storage
      @relying_party_configuration_jwks_storage = relying_party_configuration_jwks_storage
      @issuer = issuer
    end

    # Generate the signed JWKS JWT
    # @return [String] Signed JWT containing JWKS
    def generate
      now = Time.now.to_i

      {
        iss: issuer,
        sub: issuer,
        iat: now
      }.merge(
        relying_party_jwks_storage.current_jwks.export,
      )
    end

    def generate_signed
      sign_jwks(generate)
    end

    private

    def sign_jwks(payload)
      # Use the entity statement key for signing
      entity_jwks = relying_party_configuration_jwks_storage.jwks
      signing_jwk = entity_jwks.select { |k| k[:use] == 'sig' }.first

      signing_key = signing_jwk.keypair
      kid = signing_jwk[:kid]

      headers = {
        typ: 'jwks+jwt',
        kid: kid,
        alg: 'RS256'
      }

      JWT.encode(payload, signing_key, 'RS256', headers)
    end
  end
end
