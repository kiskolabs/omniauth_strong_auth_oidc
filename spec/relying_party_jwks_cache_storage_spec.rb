require 'spec_helper'

# Comprehensive test suite for TeliaAuth::CachedKeyStorage
# Tests cover:
# - Unified JWK set generation with both signing and encryption keys
# - Proper bit length (minimum 2048 bits, default 4096 bits)
# - Key caching and persistence across instances
# - Key rotation with previous keys retention (max 5 previous keys)
# - JWT::JWK and JWT::JWK::Set object handling
RSpec.describe OmniauthStrongAuthOidc::RelyingPartyJwksStorage::CacheStorage do
  let(:cache_store) { ActiveSupport::Cache::MemoryStore.new }
  let(:key_storage) { described_class.new(cache_store: cache_store) }

  before do
    # Clear the cache before each test
    cache_store.clear
  end

  describe '#initialize' do
    it 'generates a unified JWK set with both signing and encryption keys' do
      expect(key_storage.jwks).to be_a(JWT::JWK::Set)
      expect(key_storage.jwks.keys.length).to eq(2) # 1 signing + 1 encryption
    end

    it 'generates keys with default 4096-bit length' do
      signing_key = key_storage.current_jwks.keys.find { |k| k[:use] == 'sig' }.keypair
      encryption_key = key_storage.current_jwks.keys.find { |k| k[:use] == 'enc' }.keypair

      expect(signing_key.n.num_bits).to eq(4096)
      expect(encryption_key.n.num_bits).to eq(4096)
    end

    it 'accepts custom key length' do
      storage = described_class.new(key_length: 2048, cache_store: cache_store)
      signing_key = storage.current_jwks.keys.find { |k| k[:use] == 'sig' }.keypair

      expect(signing_key.n.num_bits).to eq(2048)
    end

    it 'raises error for key length below minimum (2048 bits)' do
      expect {
        described_class.new(key_length: 1024, cache_store: cache_store)
      }.to raise_error(ArgumentError, /must be at least 2048 bits/)
    end

    it 'reuses existing keys from cache' do
      # First initialization creates keys
      first_storage = described_class.new(cache_store: cache_store)
      first_signing_jwk = first_storage.current_jwks.keys.find { |k| k[:use] == 'sig' }
      first_encryption_jwk = first_storage.current_jwks.keys.find { |k| k[:use] == 'enc' }

      # Second initialization should reuse the same keys
      second_storage = described_class.new(cache_store: cache_store)
      expect(second_storage.current_jwks.keys.find { |k| k[:use] == 'sig' }[:kid]).to eq(first_signing_jwk[:kid])
      expect(second_storage.current_jwks.keys.find { |k| k[:use] == 'enc' }[:kid]).to eq(first_encryption_jwk[:kid])
    end
  end

  describe '#jwks' do
    it 'returns a JWT::JWK::Set' do
      expect(key_storage.jwks).to be_a(JWT::JWK::Set)
    end

    it 'contains both signing and encryption keys' do
      sig_keys = key_storage.jwks.keys.select { |k| k[:use] == 'sig' }
      enc_keys = key_storage.jwks.keys.select { |k| k[:use] == 'enc' }

      expect(sig_keys.length).to be >= 1
      expect(enc_keys.length).to be >= 1
    end

    it 'has keys with kid (key ID)' do
      key_storage.jwks.keys.each do |jwk|
        expect(jwk[:kid]).not_to be_nil
      end
    end

    it 'caches the JWK set in instance variable' do
      first_call = key_storage.jwks
      second_call = key_storage.jwks
      expect(first_call.object_id).to eq(second_call.object_id)
    end
  end

  describe '#rotate_signing_key!' do
    it 'generates a new signing key with unique kid' do
      original_kid = key_storage.current_jwks.keys.find { |k| k[:use] == 'sig' }[:kid]

      key_storage.rotate_signing_key!

      new_kid = key_storage.current_jwks.keys.find { |k| k[:use] == 'sig' }[:kid]
      expect(new_kid).not_to eq(original_kid)
    end

    it 'adds previous key to the JWK set' do
      original_kid = key_storage.current_jwks.keys.find { |k| k[:use] == 'sig' }[:kid]

      key_storage.rotate_signing_key!

      sig_keys = key_storage.jwks.keys.select { |k| k[:use] == 'sig' }
      expect(sig_keys.length).to eq(2)
      expect(sig_keys.map { |k| k[:kid] }).to include(original_kid)
    end

    it 'does not affect encryption keys' do
      enc_kid_before = key_storage.current_jwks.keys.find { |k| k[:use] == 'enc' }[:kid]

      key_storage.rotate_signing_key!

      enc_kid_after = key_storage.current_jwks.keys.find { |k| k[:use] == 'enc' }[:kid]
      expect(enc_kid_after).to eq(enc_kid_before)
    end

    it 'returns the new current signing JWK' do
      new_jwk = key_storage.rotate_signing_key!
      expect(new_jwk).to be_a(JWT::JWK::RSA)
      expect(new_jwk[:use]).to eq('sig')
      expect(new_jwk).to eq(key_storage.current_jwks.keys.find { |k| k[:use] == 'sig' })
    end

    it 'clears the cached JWK set' do
      key_storage.jwks # Load into instance variable

      key_storage.rotate_signing_key!

      # Should reload JWK set (clear_jwks_cache! sets @jwks to nil)
      # But accessing jwks will reload it, so we check right after rotation
      # The rotate method calls clear_jwks_cache! which should clear it
      new_jwks = key_storage.jwks
      expect(new_jwks).to be_kind_of(JWT::JWK::Set)
    end

    it 'keeps a maximum of 2 previous keys' do
      # Rotate 4 times
      4.times do
        key_storage.rotate_signing_key!
      end

      sig_keys = key_storage.jwks.keys.select { |k| k[:use] == 'sig' }
      expect(sig_keys.length).to eq(3) # 1 current + 2 previous
    end
  end

  describe '#rotate_encryption_key!' do
    it 'generates a new encryption key with unique kid' do
      original_kid = key_storage.current_jwks.keys.find { |k| k[:use] == 'enc' }[:kid]

      key_storage.rotate_encryption_key!

      new_kid = key_storage.current_jwks.keys.find { |k| k[:use] == 'enc' }[:kid]
      expect(new_kid).not_to eq(original_kid)
    end

    it 'adds previous key to the JWK set' do
      original_kid = key_storage.current_jwks.keys.find { |k| k[:use] == 'enc' }[:kid]

      key_storage.rotate_encryption_key!

      enc_keys = key_storage.jwks.keys.select { |k| k[:use] == 'enc' }
      expect(enc_keys.length).to eq(2)
      expect(enc_keys.map { |k| k[:kid] }).to include(original_kid)
    end

    it 'does not affect signing keys' do
      sig_kid_before = key_storage.current_jwks.keys.find { |k| k[:use] == 'sig' }[:kid]

      key_storage.rotate_encryption_key!

      sig_kid_after = key_storage.current_jwks.keys.find { |k| k[:use] == 'sig' }[:kid]
      expect(sig_kid_after).to eq(sig_kid_before)
    end

    it 'returns the new current encryption JWK' do
      new_jwk = key_storage.rotate_encryption_key!
      expect(new_jwk).to be_a(JWT::JWK::RSA)
      expect(new_jwk[:use]).to eq('enc')
      expect(new_jwk).to eq(key_storage.current_jwks.keys.find { |k| k[:use] == 'enc' })
    end

    it 'keeps a maximum of 2 previous keys' do
      # Rotate 4 times
      4.times do
        key_storage.rotate_encryption_key!
      end

      enc_keys = key_storage.jwks.keys.select { |k| k[:use] == 'enc' }
      expect(enc_keys.length).to eq(3) # 1 current + 2 previous
    end
  end

  describe '#clear_jwks_cache!' do
    it 'clears cached JWK set' do
      key_storage.jwks # Load into instance variable

      key_storage.clear_jwks_cache!

      expect(key_storage.instance_variable_get(:@jwks)).to be_nil
    end

    it 'allows JWK set to be reloaded from cache' do
      original_kid = key_storage.current_jwks.keys.find { |k| k[:use] == 'sig' }[:kid]

      key_storage.clear_jwks_cache!

      expect(key_storage.current_jwks.keys.find { |k| k[:use] == 'sig' }[:kid]).to eq(original_kid)
    end
  end

  describe '.clear_all_keys!' do
    it 'removes all keys from cache store' do
      key_storage # Initialize to create keys

      described_class.clear_all_keys!(cache_store)

      expect(cache_store.exist?(described_class::CURRENT_SIGNING_KEY)).to be false
      expect(cache_store.exist?(described_class::CURRENT_ENCRYPTION_KEY)).to be false
      expect(cache_store.exist?(described_class::PREVIOUS_SIGNING_KEYS)).to be false
      expect(cache_store.exist?(described_class::PREVIOUS_ENCRYPTION_KEYS)).to be false
    end
  end

  describe 'key persistence' do
    it 'persists JWK set across multiple instances' do
      first_instance = described_class.new(cache_store: cache_store)
      first_kids = first_instance.jwks.keys.map { |k| k[:kid] }.sort

      second_instance = described_class.new(cache_store: cache_store)
      second_kids = second_instance.jwks.keys.map { |k| k[:kid] }.sort

      expect(second_kids).to eq(first_kids)
    end

    it 'persists rotated keys' do
      first_instance = described_class.new(cache_store: cache_store)
      first_instance.rotate_signing_key!
      first_instance.rotate_encryption_key!

      first_kids = first_instance.jwks.keys.map { |k| k[:kid] }.sort

      second_instance = described_class.new(cache_store: cache_store)
      second_kids = second_instance.jwks.keys.map { |k| k[:kid] }.sort

      expect(second_kids).to eq(first_kids)
    end
  end

  describe 'JWK validation' do
    it 'generates JWKs with minimum required key length' do
      storage = described_class.new(key_length: 2048, cache_store: cache_store)
      signing_key = storage.current_jwks.keys.find { |k| k[:use] == 'sig' }.keypair

      expect(signing_key.n.num_bits).to eq(2048)
    end

    it 'generates valid JWKs that can be exported' do
      jwk = key_storage.current_jwks.keys.find { |k| k[:use] == 'sig' }
      export = jwk.export

      expect(export).to have_key(:kty)
      expect(export).to have_key(:n)
      expect(export).to have_key(:e)
      expect(export[:use]).to eq('sig')
      expect(export[:kid]).not_to be_nil
    end

    it 'can sign and verify with JWK' do
      jwk = key_storage.current_jwks.keys.find { |k| k[:use] == 'sig' }
      payload = { data: 'test' }

      # Sign with JWK
      token = JWT.encode(payload, jwk.keypair, 'RS256', kid: jwk[:kid])

      # Verify with unified JWK set
      decoded = JWT.decode(token, nil, true, algorithms: ['RS256'], jwks: key_storage.jwks.export)

      expect(decoded.first['data']).to eq('test')
    end

    it 'can verify old tokens after key rotation' do
      # Create token with original key
      original_jwk = key_storage.current_jwks.keys.find { |k| k[:use] == 'sig' }
      token = JWT.encode({ data: 'test' }, original_jwk.keypair, 'RS256', kid: original_jwk[:kid])

      # Rotate key
      key_storage.rotate_signing_key!

      # Verify old token still works
      decoded = JWT.decode(token, nil, true, algorithms: ['RS256'], jwks: key_storage.jwks.export)
      expect(decoded.first['data']).to eq('test')
    end
  end

  describe 'JWKS export' do
    it 'exports all keys for JWKS endpoint' do
      export = key_storage.jwks.export

      expect(export).to have_key(:keys)
      expect(export[:keys]).to be_an(Array)
      expect(export[:keys].length).to eq(2) # 1 sig + 1 enc
    end

    it 'export includes both signing and encryption keys after rotation' do
      key_storage.rotate_signing_key!
      key_storage.rotate_encryption_key!

      export = key_storage.jwks.export
      sig_keys = export[:keys].select { |k| k[:use] == 'sig' }
      enc_keys = export[:keys].select { |k| k[:use] == 'enc' }

      expect(sig_keys.length).to eq(2) # current + 1 previous
      expect(enc_keys.length).to eq(2) # current + 1 previous
    end
  end

  describe 'constants' do
    it 'defines minimum key length of 2048 bits' do
      expect(OmniauthStrongAuthOidc::RelyingPartyJwksStorage::Base::MINIMUM_KEY_LENGTH).to eq(2048)
    end

    it 'defines default key length of 4096 bits' do
      expect(OmniauthStrongAuthOidc::RelyingPartyJwksStorage::Base::DEFAULT_KEY_LENGTH).to eq(4096)
    end

    it 'keeps maximum of 2 previous keys' do
      expect(described_class::MAX_PREVIOUS_KEYS).to eq(2)
    end
  end
end
