module OmniauthStrongAuthOidc
  module EntityStatementFetcher
    class FederationUrlFetcher < Base
      attr_reader :entity_statement_url

      def initialize(issuer_url:, entity_statement_path: "/.well-known/openid-federation", statement_type: :openid_provider)
        @entity_statement_url = "#{issuer_url}#{entity_statement_path}"
        super(statement_type: statement_type)
      end

      # Fetch Telia's Entity Statement
      # The Entity Statement is a signed JWT containing metadata including JWKS
      # @return [Hash] Decoded entity statement payload
      private def fetch_entity_statement
        response = HTTP.get(entity_statement_url)

        unless response.status.success?
          raise "Failed to fetch entity statement: #{response.status}"
        end

        # Decode without verification (trusting HTTPS) to get the payload
        entity_statement_raw = response.body.to_s

        # Check signature with the embedded JWKS
        decode_with_verification(entity_statement_raw, JWT.decode(entity_statement_raw, nil, false).first)
      end
    end
  end
end
