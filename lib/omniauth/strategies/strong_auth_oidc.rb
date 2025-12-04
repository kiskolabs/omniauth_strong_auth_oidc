require 'omniauth-oauth2'
require 'jwt'
require 'jwe'

module OmniAuth
  module Strategies
    class StrongAuthOidc < OmniAuth::Strategies::OAuth2
      option :name, :strong_auth_oidc

      # Custom options for Telia authentication
      option :scope, 'openid'
      option :response_type, 'code'
      option :relying_party_jwks_storage
      option :provider_jwks_loader
      option :provider_entity_statement_fetcher, nil
      option :redirect_uri, nil

      def redirect_uri
        return options.redirect_uri if options.redirect_uri.present?

        # omniauth adds query prarameters from the original request to the callback_url
        # if we don't strip them, the OIDC provider will reject the redirect_uri mismatch
        uri = URI(callback_url)
        uri.query = nil
        uri.to_s
      end

      # Override authorize_params to support signed request
      def authorize_params
        params = super.dup
        params[:request] = build_authorize_param_jwt_request(params)
        params[:redirect_uri] = redirect_uri

        # Remove parameters that are now in the signed request JWT
        # Keep client_id and optionally state/nonce outside the JWT
        params.delete(:scope)
        params.delete(:response_type)
        params.delete(:acr_values)
        params.delete(:audience)
        params
      end

      # Build signed request JWT for authorization
      def build_authorize_param_jwt_request(params)
        now = Time.now.to_i

        jwt_payload = {
          iss: options.client_id,
          aud: entity_statement ? entity_statement.openid_configuration.dig(:issuer) : options.authorize_params[:audience],
          client_id: options.client_id,
          response_type: options.response_type,
          scope: options.scope,
          redirect_uri: redirect_uri,
          jti: SecureRandom.uuid,
          exp: now + 900, # 15 minutes
          iat: now,
          nbf: now
        }

        # Add acr_values if present
        if params['acr_values']
          jwt_payload[:acr_values] = params['acr_values']
        end

        # Add state if present
        if params[:state]
          jwt_payload[:state] = params[:state]
        end

        # Add nonce for OIDC
        jwt_payload[:nonce] = SecureRandom.hex(16)

        JWT.encode(jwt_payload, signing_key.keypair, 'RS256', kid: signing_key.kid)
      end

      # Override token_params to use JWT bearer authentication
      def token_params
        super.tap do |params|
          params[:grant_type] = 'authorization_code'
          params[:redirect_uri] = redirect_uri
          params[:client_id] = options.client_id
          params[:client_assertion_type] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
          params[:client_assertion] = client_assertion
        end
      end

      # Build client assertion JWT for authentication
      def client_assertion
        now = Time.now.to_i

        jwt_payload = {
          iss: options.client_id,
          sub: options.client_id,
          aud: token_url,
          jti: SecureRandom.uuid,
          exp: now + 900, # 15 minutes
          iat: now
        }

        JWT.encode(jwt_payload, signing_key.keypair, 'RS256', kid: signing_key.kid)
      end

      # Get user info from ID token
      def raw_info
        @raw_info ||= begin
          # The ID token is returned in the token response
          id_token = access_token.params['id_token']

          if id_token
            # Decrypt and verify the ID token
            decrypt_and_verify_jwt(id_token)
          else
            raise "No id_token in token response"
          end
        end
      end

      def token_url
        if entity_statement
          return entity_statement.openid_configuration.dig(:token_endpoint)
        end
        client.connection.build_url(options.client_options.token_url)
      end

      # Decrypt and verify JWT response
      def decrypt_and_verify_jwt(jwt_string)
        # if key was rotated the first attempt can fail
        begin
          encryption_key_index = 0
          # Telia returns JWE (encrypted JWT) which contains a JWS (signed JWT)
          # If our private key was rotated, we may need to try multiple keys
          inner_jwt = JWE.decrypt(jwt_string, encryption_keys[encryption_key_index].keypair)

          # Then verify the inner JWT signature with JWKS
          jwt_data = JWT.decode(
            inner_jwt,
            nil,
            true,
            algorithms: ['RS256'],
            jwks: options.provider_jwks_loader
          )

          jwt_data.first
        rescue OpenSSL::PKey::RSAError => e
          encryption_key_index += 1
          if encryption_keys[encryption_key_index]
            retry
          else
            raise e
          end
        end
      end

      # Build auth hash
      uid { raw_info['sub'] }

      info do
        {
          identity_number: raw_info['urn:oid:1.2.246.21'],
          first_name: raw_info['urn:oid:1.2.246.575.1.14'],
          last_name: raw_info['urn:oid:2.5.4.4']
        }
      end

      extra do
        {
          raw_info: raw_info
        }
      end

      # Override client to use custom identifier
      # @return [OAuth2::Client]
      def client
        client_options = {}
        if entity_statement
          # Fetch OIDC provider configuration from entity statement
          oidc_provider_config = entity_statement.openid_configuration
          client_options[:site] = oidc_provider_config.dig(:issuer)
          client_options[:authorize_url] = oidc_provider_config.dig(:authorization_endpoint)
          client_options[:token_url] = oidc_provider_config.dig(:token_endpoint)
          client_options[:userinfo_url] = oidc_provider_config.dig(:userinfo_endpoint)
        else
          client_options = options.client_options.dup
        end
        ::OAuth2::Client.new(
          options.client_id,
          nil, # No client secret needed for JWT bearer
          client_options.deep_symbolize_keys
        )
      end

      private

      def entity_statement
        return nil unless options.provider_entity_statement_fetcher
        options.provider_entity_statement_fetcher.entity_statement
      end

      # Get signing key from key storage
      def signing_key
        options.relying_party_jwks_storage.current_jwks.select { |key| key[:use] == 'sig' }.first
      end

      # Get encryption key from key storage
      def encryption_keys
        options.relying_party_jwks_storage.jwks.select { |key| key[:use] == 'enc' }
      end
    end
  end
end
