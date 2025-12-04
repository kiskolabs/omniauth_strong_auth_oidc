module OmniauthStrongAuthOidc
  # Abstract interface for OpenID key storage
  # Implementations must provide a JWK set containing both signing and encryption keys
  module EntityStatementFetcher
    class Base
      attr_reader :entity_statement
      attr_reader :statement_type

      def initialize(statement_type: :openid_provider)
        @statement_type = statement_type
      end

      def entity_statement
        @entity_statement ||= EntityStatement.new(fetch_entity_statement, metadata_key: statement_type)
      end

      def reload!
        @entity_statement = nil
      end

      private def fetch_entity_statement
        raise NotImplementedError, "Subclasses must implement fetch_entity_statement"
      end

      private def decode_with_verification(signed_jwt, entity_statement)
        jwks = entity_statement['jwks']
        JWT.decode(
          signed_jwt,
          nil,
          true,
          algorithms: ['RS256'],
          jwks: jwks
        ).first.deep_symbolize_keys
      end
    end
  end
end
