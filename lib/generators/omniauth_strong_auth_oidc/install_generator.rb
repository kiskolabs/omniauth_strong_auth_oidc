# frozen_string_literal: true

if defined?(Rails::Generators::Base)
  module OmniauthStrongAuthOidc
    module Generators
      class InstallGenerator < Rails::Generators::Base
        source_root File.expand_path('templates', __dir__)

        class_option :redirect_uris,
                     type: :string,
                     required: true,
                     desc: 'Comma-separated list of redirect URIs (e.g., "https://example.com/users/auth/strong_auth_oidc/callback")'

        class_option :org_name,
                     type: :string,
                     required: true,
                     desc: 'Organization name for the entity statement'

        class_option :iss,
                     type: :string,
                     required: true,
                     desc: 'Issuer URL (e.g., "https://example.com")'

        desc 'Generates the RelyingPartyEntityStatementController for OIDC federation endpoints'

        def create_controller
          template 'relying_party_entity_statement_controller.rb.tt',
                   'app/controllers/relying_party_entity_statement_controller.rb'
        end

        def create_routes
          route_content = <<~ROUTES
            # OIDC Federation endpoints
            get '/.well-known/openid-federation', to: 'relying_party_entity_statement#entity_statement', as: :openid_federation
            get '/.well-known/jwks.json', to: 'relying_party_entity_statement#jwks', as: :jwks
            get '/.well-known/signed-jwks.jwt', to: 'relying_party_entity_statement#signed_jwks', as: :signed_jwks
          ROUTES

          route route_content
        end

        def show_post_install_message
          say ''
          say '============================================================', :green
          say 'OmniAuth Strong Auth OIDC controller installed successfully!', :green
          say '============================================================', :green
          say ''
          say 'Next steps:', :yellow
          say '1. Review the generated controller at app/controllers/relying_party_entity_statement_controller.rb'
          say '2. Ensure you have the required environment variables set:'
          say '   - OIDC_CLIENT_ID'
          say '   - OIDC_CONFIGURATION_SIGNING_KEY_BASE64'
          say '3. Update your Devise/OmniAuth configuration'
          say ''
        end

        private

        def redirect_uris_array
          options[:redirect_uris].split(',').map(&:strip)
        end

        def org_name
          options[:org_name]
        end

        def iss
          options[:iss]
        end
      end
    end
  end
end
