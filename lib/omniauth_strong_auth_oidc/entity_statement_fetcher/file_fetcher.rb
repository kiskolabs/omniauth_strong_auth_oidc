module OmniauthStrongAuthOidc
  module EntityStatementFetcher
    class FileFetcher < Base
      attr_reader :entity_statement_url

      def initialize(path_to_file:, statement_type: :openid_provider)
        @path_to_file = path_to_file
        super(statement_type: statement_type)
      end

      # Fetch Telia's Entity Statement
      # The Entity Statement is a signed JWT containing metadata including JWKS
      # @return [Hash] Decoded entity statement payload
      private def fetch_entity_statement
        File.open(@path_to_file, 'r') do |file|
          entity_statement_raw = file.read
          decode_with_verification(entity_statement_raw, JWT.decode(entity_statement_raw, nil, false).first)
        end
      end
    end
  end
end
