module OmniauthStrongAuthOidc
  module RelyingPartyJwksStorage
    # Cached implementation of KeyStorage that stores keys in Rails cache
    # Returns a single JWT::JWK::Set containing both signing and encryption keys
    # Supports key rotation while keeping previous keys available
    class CacheStorage < Base
      CACHE_PREFIX = 'telia_oidc:keys'
      CURRENT_SIGNING_KEY = "#{CACHE_PREFIX}:signing:current"
      PREVIOUS_SIGNING_KEYS = "#{CACHE_PREFIX}:signing:previous"
      CURRENT_ENCRYPTION_KEY = "#{CACHE_PREFIX}:encryption:current"
      PREVIOUS_ENCRYPTION_KEYS = "#{CACHE_PREFIX}:encryption:previous"
      MAX_PREVIOUS_KEYS = 2 # Keep up to 2 previous keys for rotation

      attr_reader :cache_store

      # @param key_length [Integer] RSA key length in bits (default: 4096)
      # @param cache_store [ActiveSupport::Cache::Store] Cache store to use (Rails.cache for example)
      def initialize(key_length: DEFAULT_KEY_LENGTH, cache_store:)
        @key_length = key_length
        @cache_store = cache_store
        validate_key_length!
        ensure_keys_exist!
      end

      def support_rotation?
        true
      end

      # Returns the JWK set containing all keys (signing + encryption, current + previous)
      # @return [JWT::JWK::Set]
      def jwks
        @jwks ||= create_jwk_set(
          signing_key_data: all_signing_keys,
          encryption_key_data: all_encryption_keys
        )
      end

      # Rotates the signing key, moving current to previous
      # @return [JWT::JWK] The new signing JWK
      def rotate_signing_key!
        old_key_data = load_key_data(CURRENT_SIGNING_KEY)
        new_key = generate_rsa_key(@key_length)
        new_key_data = {
          pem: new_key.to_pem,
          created_at: Time.now.to_i
        }

        # Move current key to previous keys list
        add_to_previous_keys(PREVIOUS_SIGNING_KEYS, old_key_data)

        # Store new key as current
        store_key_data(CURRENT_SIGNING_KEY, new_key_data)

        # Clear cached JWK set
        clear_jwks_cache!

        JWT::JWK.new(new_key, use: 'sig')  # Return JWK representation of
      end

      # Rotates the encryption key, moving current to previous
      # @return [JWT::JWK] The new encryption JWK
      def rotate_encryption_key!
        old_key_data = load_key_data(CURRENT_ENCRYPTION_KEY)
        new_key = generate_rsa_key(@key_length)
        new_key_data = {
          pem: new_key.to_pem,
          created_at: Time.now.to_i
        }

        # Move current key to previous keys list
        add_to_previous_keys(PREVIOUS_ENCRYPTION_KEYS, old_key_data)

        # Store new key as current
        store_key_data(CURRENT_ENCRYPTION_KEY, new_key_data)

        # Clear cached JWK set
        clear_jwks_cache!

        JWT::JWK.new(new_key, use: 'enc')  # Return JWK representation of
      end

      # Clear cached JWK set (useful for testing or after rotation)
      # @return [void]
      def clear_jwks_cache!
        @jwks = nil
      end

      # Completely removes all keys from storage (use with caution!)
      # @return [void]
      def self.clear_all_keys!(cache_store)
        store = cache_store
        store.delete(CURRENT_SIGNING_KEY)
        store.delete(PREVIOUS_SIGNING_KEYS)
        store.delete(CURRENT_ENCRYPTION_KEY)
        store.delete(PREVIOUS_ENCRYPTION_KEYS)
      end

      private

      # Returns the current signing key (for internal use)
      # @return [OpenSSL::PKey::RSA]
      def current_signing_key
        load_key(CURRENT_SIGNING_KEY)
      end

      # Returns the current encryption key (for internal use)
      # @return [OpenSSL::PKey::RSA]
      def current_encryption_key
        load_key(CURRENT_ENCRYPTION_KEY)
      end

      # Returns all signing keys (current + previous) with their metadata
      # @return [Array<OpenSSL::PKey::RSA>]
      def all_signing_keys
        current_data = load_key_data(CURRENT_SIGNING_KEY)
        previous_data = load_previous_key_data(PREVIOUS_SIGNING_KEYS)

        [current_data] + previous_data
      end

      # Returns all encryption keys (current + previous) with their metadata
      # @return [Array<OpenSSL::PKey::RSA>]
      def all_encryption_keys
        current_data = load_key_data(CURRENT_ENCRYPTION_KEY)
        previous_data = load_previous_key_data(PREVIOUS_ENCRYPTION_KEYS)

        [current_data] + previous_data
      end

      def validate_key_length!
        raise ArgumentError, "Key length must be at least #{MINIMUM_KEY_LENGTH} bits" if @key_length < MINIMUM_KEY_LENGTH
      end

      def ensure_keys_exist!
        # Generate signing key if it doesn't exist
        unless cache_store.exist?(CURRENT_SIGNING_KEY)
          key_data = {
            pem: generate_rsa_key(@key_length).to_pem,
            created_at: Time.now.to_i
          }
          store_key_data(CURRENT_SIGNING_KEY, key_data)
        end

        # Generate encryption key if it doesn't exist
        unless cache_store.exist?(CURRENT_ENCRYPTION_KEY)
          key_data = {
            pem: generate_rsa_key(@key_length).to_pem,
            created_at: Time.now.to_i
          }
          store_key_data(CURRENT_ENCRYPTION_KEY, key_data)
        end

        # Initialize previous keys arrays if they don't exist
        cache_store.write(PREVIOUS_SIGNING_KEYS, []) unless cache_store.exist?(PREVIOUS_SIGNING_KEYS)
        cache_store.write(PREVIOUS_ENCRYPTION_KEYS, []) unless cache_store.exist?(PREVIOUS_ENCRYPTION_KEYS)
      end

      def load_key(cache_key)
        key_data = cache_store.read(cache_key)
        raise "Key not found in cache: #{cache_key}" unless key_data

        # Handle legacy PEM-only format
        if key_data.is_a?(String)
          return OpenSSL::PKey::RSA.new(key_data)
        end

        OpenSSL::PKey::RSA.new(key_data[:pem])
      end

      def load_key_data(cache_key)
        key_data = cache_store.read(cache_key)
        raise "Key not found in cache: #{cache_key}" unless key_data

        # Handle legacy PEM-only format
        if key_data.is_a?(String)
          return { pem: key_data, kid: nil, created_at: nil }
        end

        key_data
      end

      def store_key(cache_key, key)
        # This method is for backward compatibility
        pem_data = key.to_pem
        cache_store.write(cache_key, pem_data)
      end

      def store_key_data(cache_key, key_data)
        cache_store.write(cache_key, key_data)
      end

      def previous_signing_keys
        load_previous_keys(PREVIOUS_SIGNING_KEYS)
      end

      def previous_encryption_keys
        load_previous_keys(PREVIOUS_ENCRYPTION_KEYS)
      end

      def load_previous_keys(cache_key)
        key_data_list = cache_store.read(cache_key) || []
        key_data_list.map do |data|
          # Handle legacy PEM-only format
          if data.is_a?(String)
            OpenSSL::PKey::RSA.new(data)
          else
            OpenSSL::PKey::RSA.new(data[:pem])
          end
        end
      end

      def load_previous_key_data(cache_key)
        key_data_list = cache_store.read(cache_key) || []
        key_data_list.map do |data|
          # Handle legacy PEM-only format
          if data.is_a?(String)
            { pem: data, kid: nil, created_at: nil }
          else
            data
          end
        end
      end

      def add_to_previous_keys(cache_key, key_data)
        previous_keys = cache_store.read(cache_key) || []
        previous_keys.unshift(key_data)

        # Keep only the most recent keys
        previous_keys = previous_keys.first(MAX_PREVIOUS_KEYS)

        cache_store.write(cache_key, previous_keys)
      end
    end
  end
end
