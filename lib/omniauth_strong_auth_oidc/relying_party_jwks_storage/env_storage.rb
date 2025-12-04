module OmniauthStrongAuthOidc
  module RelyingPartyJwksStorage
    # Environment variable-based key storage for production deployments
    # Loads RSA keys from environment variables without rotation support
    # Keys should be base64-encoded PEM-encoded RSA private keys
    #
    # Default environment variables:
    # - OIDC_SIGNING_KEY_BASE64: Base64-encoded PEM RSA private key for signing
    # - OIDC_ENCRYPTION_KEY_BASE64: Base64-encoded PEM RSA private key for encryption
    #
    # Example with custom environment variable names:
    #   RelyingPartyJwksStorage::EnvStorage.new(
    #     signing_key_env: 'MY_SIGNING_KEY',
    #     encryption_key_env: 'MY_ENCRYPTION_KEY'
    #   )
    #
    # To create a storage with only signing key (no encryption):
    #   RelyingPartyJwksStorage::EnvStorage.new(
    #     signing_key_env: 'ENTITY_STATEMENT_SIGNING_KEY',
    #     encryption_key_env: nil
    #   )
    class EnvStorage < Base
      DEFAULT_SIGNING_KEY_ENV = 'OIDC_SIGNING_KEY_BASE64'
      DEFAULT_ENCRYPTION_KEY_ENV = 'OIDC_ENCRYPTION_KEY_BASE64'

      attr_reader :signing_key_env, :encryption_key_env

      def initialize(signing_key_env: DEFAULT_SIGNING_KEY_ENV, encryption_key_env: DEFAULT_ENCRYPTION_KEY_ENV)
        @signing_key_env = signing_key_env
        @encryption_key_env = encryption_key_env
        validate_env_keys!
      end

      def support_rotation?
        false
      end

      # Returns the JWK set containing both signing and encryption keys
      # @return [JWT::JWK::Set]
      def jwks
        @jwks ||= begin
          encryption_data = encryption_key_env && !ENV[encryption_key_env].nil? && !ENV[encryption_key_env].empty? ? [{ pem: encryption_key_pem }] : []

          create_jwk_set(
            signing_key_data: [{ pem: signing_key_pem }],
            encryption_key_data: encryption_data
          )
        end
      end

      # Rotation is not supported for environment-based keys
      # @raise [NotImplementedError]
      def rotate_signing_key!
        raise NotImplementedError, "Key rotation is not supported for EnvKeyStorage. Update environment variables instead."
      end

      # Rotation is not supported for environment-based keys
      # @raise [NotImplementedError]
      def rotate_encryption_key!
        raise NotImplementedError, "Key rotation is not supported for EnvKeyStorage. Update environment variables instead."
      end

      private

      def signing_key_pem
        Base64.decode64(ENV[signing_key_env])
      end

      def encryption_key_pem
        return nil unless encryption_key_env && !ENV[encryption_key_env].nil? && !ENV[encryption_key_env].empty?
        Base64.decode64(ENV[encryption_key_env])
      end

      def validate_env_keys!
        # Signing key is always required
        if ENV[signing_key_env].nil? || ENV[signing_key_env].empty?
          raise ArgumentError, "Missing required environment variable: #{signing_key_env}"
        end

        # Validate signing key
        begin
          OpenSSL::PKey::RSA.new(signing_key_pem)
        rescue OpenSSL::PKey::RSAError => e
          raise ArgumentError, "Invalid RSA key in #{signing_key_env}: #{e.message}"
        end

        signing_key = OpenSSL::PKey::RSA.new(signing_key_pem)
        if signing_key.n.num_bits < MINIMUM_KEY_LENGTH
          raise ArgumentError, "#{signing_key_env} must be at least #{MINIMUM_KEY_LENGTH} bits (got #{signing_key.n.num_bits} bits)"
        end

        # Return early if no encryption key is configured
        return unless encryption_key_env

        if ENV[encryption_key_env].nil? || ENV[encryption_key_env].empty?
          raise ArgumentError, "Missing required environment variable: #{encryption_key_env}"
        end

        begin
          OpenSSL::PKey::RSA.new(encryption_key_pem)
        rescue OpenSSL::PKey::RSAError => e
          raise ArgumentError, "Invalid RSA key in #{encryption_key_env}: #{e.message}"
        end

        encryption_key = OpenSSL::PKey::RSA.new(encryption_key_pem)
        if encryption_key.n.num_bits < MINIMUM_KEY_LENGTH
          raise ArgumentError, "#{encryption_key_env} must be at least #{MINIMUM_KEY_LENGTH} bits (got #{encryption_key.n.num_bits} bits)"
        end
      end
    end
  end
end
