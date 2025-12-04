module OmniauthStrongAuthOidc
  # Abstract interface for OpenID key storage
  # Implementations must provide a JWK set containing both signing and encryption keys
  module RelyingPartyJwksStorage
    class Base
        MINIMUM_KEY_LENGTH = 2048
        DEFAULT_KEY_LENGTH = 4096

        class << self
          attr_accessor :instance
        end

        def support_rotation?
          false
        end

        # Returns the JWK set containing all keys (signing + encryption, current + previous)
        # @return [JWT::JWK::Set]
        def jwks
          raise NotImplementedError, "#{self.class} must implement #jwks"
        end

        # Returns first signing and encryption keys only
        # Current keys alsways go first
        def current_jwks
          taken_keys = []
          current_jwks = jwks.select do |key|
            if (key[:use] == 'sig' && !taken_keys.include?('sig')) ||
              (key[:use] == 'enc' && !taken_keys.include?('enc'))
              taken_keys << key[:use]
              true
            else
              false
            end
          end
          JWT::JWK::Set.new(current_jwks)
        end

        # Rotates the signing key
        # @return [void]
        def rotate_signing_key!
          raise NotImplementedError, "#{self.class} must implement #rotate_signing_key!"
        end

        # Rotates the encryption key
        # @return [void]
        def rotate_encryption_key!
          raise NotImplementedError, "#{self.class} must implement #rotate_encryption_key!"
        end

        protected

        # Generates a new RSA key pair with the specified key length
        # @param key_length [Integer] The length of the key in bits (minimum 2048)
        # @return [OpenSSL::PKey::RSA]
        def generate_rsa_key(key_length = DEFAULT_KEY_LENGTH)
          raise ArgumentError, "Key length must be at least #{MINIMUM_KEY_LENGTH} bits" if key_length < MINIMUM_KEY_LENGTH

          OpenSSL::PKey::RSA.new(key_length)
        end

        # Converts an RSA key to a JWK with the specified parameters
        # Uses JWT's built-in kid generation if not provided
        # @param key [OpenSSL::PKey::RSA] The RSA key to convert
        # @param kid [String, nil] The key ID (optional, will auto-generate if nil)
        # @param use [String] The key use ('sig' for signing, 'enc' for encryption)
        # @return [JWT::JWK]
        def key_to_jwk(key, kid: nil, use:)
          if kid
            JWT::JWK.new(key, { use: use, kid: kid })
          else
            JWT::JWK.new(key, { use: use })
          end
        end

        # Creates a JWK set from signing and encryption key data
        # @param signing_key_data [Array<Hash>] Array of signing key data hashes
        # @param encryption_key_data [Array<Hash>] Array of encryption key data hashes
        # @return [JWT::JWK::Set]
        def create_jwk_set(signing_key_data:, encryption_key_data:)
          jwks = []

          # Add signing keys
          signing_key_data.each do |key_data|
            key = OpenSSL::PKey::RSA.new(key_data[:pem])
            # Use kid from key_data if available (for backward compatibility)
            jwks << key_to_jwk(key, kid: key_data[:kid], use: 'sig')
          end

          # Add encryption keys
          encryption_key_data.each do |key_data|
            key = OpenSSL::PKey::RSA.new(key_data[:pem])
            # Use kid from key_data if available (for backward compatibility)
            jwks << key_to_jwk(key, kid: key_data[:kid], use: 'enc')
          end

          JWT::JWK::Set.new(jwks)
        end
      end
  end
end
