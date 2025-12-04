module OmniauthStrongAuthOidc
  # Generates OpenID Federation Entity Statement for the relying party (client)
  # This statement contains client metadata and a link to the client's JWKS
  class RelyingPartyEntityStatementGenerator
    attr_reader :iss, :org_name, :client_id, :jwks_uri, :signed_jwks_uri, :redirect_uris, :configuration_jwks_storage

    def initialize(iss:, org_name:, client_id:, jwks_uri:, signed_jwks_uri:, redirect_uris:, configuration_jwks_storage:)
      @iss = iss
      @org_name = org_name
      @client_id = client_id
      @jwks_uri = jwks_uri
      @signed_jwks_uri = signed_jwks_uri
      @redirect_uris = redirect_uris
      @configuration_jwks_storage = configuration_jwks_storage
    end

    # Generate the entity statement JWT
    # @return [String] Signed JWT entity statement
    def generate
      now = Time.now.to_i

      {
        iss: iss,
        sub: iss,
        iat: now,
        exp: now + (365 * 24 * 60 * 60), # Valid for 1 year
        metadata: {
          openid_relying_party: openid_relying_party_metadata
        },
        jwks: {
          keys: signing_keys_for_entity_statement
        }
      }
    end

    def generate_signed
      sign_entity_statement(generate)
    end

    private

    def openid_relying_party_metadata
      {
        client_name: org_name,
        application_type: "web",
        jwks_uri: jwks_uri,
        signed_jwks_uri: signed_jwks_uri,
        redirect_uris: redirect_uris,
        response_types: ['code'],
        grant_types: ['authorization_code'],
        token_endpoint_auth_method: 'private_key_jwt'
      }
    end

    def signing_keys_for_entity_statement
      # Export the entity statement signing key (public part)
      # This is the key used to verify the entity statement signature
        configuration_jwks_storage.current_jwks.export[:keys]
    end

    def sign_entity_statement(payload)
      # Use the separate entity statement signing key
      current_jwks = configuration_jwks_storage.current_jwks
      signing_jwk = current_jwks.select { |k| k[:use] == 'sig' }.first

      signing_key = signing_jwk.keypair
      kid = signing_jwk[:kid]

      headers = {
        typ: 'entity-statement+jwt',
        kid: kid,
        alg: 'RS256'
      }

      JWT.encode(payload, signing_key, 'RS256', headers)
    end
  end
end
