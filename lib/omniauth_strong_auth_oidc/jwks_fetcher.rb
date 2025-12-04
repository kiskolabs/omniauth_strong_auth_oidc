require 'http'
require 'jwt'

module OmniauthStrongAuthOidc
  # Service to fetch and verify Telia's JWKS
  class JwksFetcher
    attr_reader :signed_jwks_uri
    attr_reader :configuration_jwks
    attr_reader :entity_statement_fetcher

    def initialize(signed_jwks_uri: nil, configuration_jwks: nil, entity_statement_fetcher: nil)
      # either entity stament or signed_jwks_uri + configuration_jwks must be provided
      if entity_statement_fetcher && (signed_jwks_uri || configuration_jwks)
        raise ArgumentError, "Provide either entity_statement_fetcher or both signed_jwks_uri and configuration_jwks, not both"
      end

      if !entity_statement_fetcher && (!signed_jwks_uri || !configuration_jwks)
        raise ArgumentError, "Must provide either entity_statement_fetcher or both signed_jwks_uri and configuration_jwks"
      end

      @signed_jwks_uri = signed_jwks_uri
      @configuration_jwks = configuration_jwks
      @entity_statement_fetcher = entity_statement_fetcher
    end

    def jwks
      @jwks ||= fetch_and_verify_jwks
    end

    def reload!
      if entity_statement_fetcher
        entity_statement_fetcher.reload!
      end
      @jwks = nil
    end

    def signed_jwks_uri
      if entity_statement_fetcher
        return entity_statement_fetcher.entity_statement.signed_jwks_uri
      end
      @signed_jwks_uri
    end

    def configuration_jwks
      if entity_statement_fetcher
        return entity_statement_fetcher.entity_statement.configuration_jwks
      end
      @configuration_jwks
    end

    private

    def fetch_and_verify_jwks
      unless signed_jwks_uri
        raise "No signed_jwks_uri found in entity statement metadata"
      end

      # Fetch the signed JWKS
      signed_response = HTTP.get(signed_jwks_uri)

      unless signed_response.status.success?
        raise "Failed to fetch signed JWKS"
      end

      # Verify and extract JWKS from the signed JWT
      verify_signed_jwks(signed_response.body.to_s, configuration_jwks)
    end

    # Verify and extract JWKS from signed JWT
    # Uses the JWKS from the entity statement to verify the signature
    def verify_signed_jwks(signed_jwt, configuration_jwks)
      #TODO: Check if configuration_jwks can expire or be rotated
      decoded = nil

      # Decode and verify the signed JWKS JWT using entity statement's JWKS
      decoded = JWT.decode(
        signed_jwt,
        nil,
        true,
        algorithms: ['RS256'],
        jwks: configuration_jwks
      )

      JWT::JWK::Set.new(decoded.first)
    end
  end
end
