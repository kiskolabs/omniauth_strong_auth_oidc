module OmniauthStrongAuthOidc
  class EntityStatement
    attr_reader :entity_statement_data, :metadata_key

    def initialize(entity_statement_data, metadata_key: :openid_provider)
      @entity_statement_data = entity_statement_data
      @metadata_key = metadata_key
    end

    def openid_configuration
      entity_statement_data.dig(:metadata, metadata_key)
    end

    def signed_jwks_uri
      entity_statement_data.dig(:metadata, metadata_key, :signed_jwks_uri)
    end

    def configuration_jwks
      JWT::JWK::Set.new(entity_statement_data.dig(:jwks))
    end
  end
end
