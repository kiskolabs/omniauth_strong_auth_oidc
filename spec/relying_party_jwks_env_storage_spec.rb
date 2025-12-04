require 'spec_helper'

RSpec.describe OmniauthStrongAuthOidc::RelyingPartyJwksStorage::EnvStorage do
  let(:signing_key) { OpenSSL::PKey::RSA.new(4096) }
  let(:encryption_key) { OpenSSL::PKey::RSA.new(4096) }
  let(:signing_key_pem) { signing_key.to_pem }
  let(:encryption_key_pem) { encryption_key.to_pem }

  before do
    ENV['OIDC_SIGNING_KEY_BASE64'] = Base64.strict_encode64(signing_key_pem)
    ENV['OIDC_ENCRYPTION_KEY_BASE64'] = Base64.strict_encode64(encryption_key_pem)
  end

  after do
    ENV.delete('OIDC_SIGNING_KEY_BASE64')
    ENV.delete('OIDC_ENCRYPTION_KEY_BASE64')
    ENV.delete('CUSTOM_SIGNING_KEY')
    ENV.delete('CUSTOM_ENCRYPTION_KEY')
  end

  describe '#initialize' do
    it 'validates environment variables are present' do
      ENV.delete('OIDC_SIGNING_KEY_BASE64')

      expect {
        described_class.new
      }.to raise_error(ArgumentError, /Missing required environment variable: OIDC_SIGNING_KEY_BASE64/)
    end

    it 'validates signing key is valid RSA key' do
      ENV['OIDC_SIGNING_KEY_BASE64'] = 'invalid key'
      expect {
        described_class.new
      }.to raise_error(ArgumentError, /Invalid RSA key in OIDC_SIGNING_KEY_BASE64/)
    end

    it 'validates encryption key is valid RSA key' do
      ENV['OIDC_ENCRYPTION_KEY_BASE64'] = 'invalid key'
      expect {
        described_class.new
      }.to raise_error(ArgumentError, /Invalid RSA key in OIDC_ENCRYPTION_KEY_BASE64/)
    end

    it 'validates signing key meets minimum length requirement' do
      small_key = OpenSSL::PKey::RSA.new(1024)
      ENV['OIDC_SIGNING_KEY_BASE64'] = Base64.strict_encode64(small_key.to_pem)

      expect {
        described_class.new
      }.to raise_error(ArgumentError, /OIDC_SIGNING_KEY_BASE64 must be at least 2048 bits/)
    end

    it 'validates encryption key meets minimum length requirement' do
      small_key = OpenSSL::PKey::RSA.new(1024)
      ENV['OIDC_ENCRYPTION_KEY_BASE64'] = Base64.strict_encode64(small_key.to_pem)

      expect {
        described_class.new
      }.to raise_error(ArgumentError, /OIDC_ENCRYPTION_KEY_BASE64 must be at least 2048 bits/)
    end

    it 'succeeds with valid keys' do
      expect { described_class.new }.not_to raise_error
    end

    context 'with custom environment variable names' do
      before do
        ENV['CUSTOM_SIGNING_KEY'] = Base64.strict_encode64(signing_key_pem)
        ENV['CUSTOM_ENCRYPTION_KEY'] = Base64.strict_encode64(encryption_key_pem)
      end

      it 'uses custom environment variable names' do
        expect {
          described_class.new(
            signing_key_env: 'CUSTOM_SIGNING_KEY',
            encryption_key_env: 'CUSTOM_ENCRYPTION_KEY'
          )
        }.not_to raise_error
      end

      it 'validates custom environment variables are present' do
        ENV.delete('CUSTOM_SIGNING_KEY')

        expect {
          described_class.new(
            signing_key_env: 'CUSTOM_SIGNING_KEY',
            encryption_key_env: 'CUSTOM_ENCRYPTION_KEY'
          )
        }.to raise_error(ArgumentError, /Missing required environment variable: CUSTOM_SIGNING_KEY/)
      end

      it 'validates custom signing key is valid RSA key' do
        ENV['CUSTOM_SIGNING_KEY'] = 'invalid key'

        expect {
          described_class.new(
            signing_key_env: 'CUSTOM_SIGNING_KEY',
            encryption_key_env: 'CUSTOM_ENCRYPTION_KEY'
          )
        }.to raise_error(ArgumentError, /Invalid RSA key in CUSTOM_SIGNING_KEY/)
      end

      it 'returns correct keys with custom env names' do
        key_storage = described_class.new(
          signing_key_env: 'CUSTOM_SIGNING_KEY',
          encryption_key_env: 'CUSTOM_ENCRYPTION_KEY'
        )

        sig_keys = key_storage.jwks.keys.select { |k| k[:use] == 'sig' }
        enc_keys = key_storage.jwks.keys.select { |k| k[:use] == 'enc' }

        expect(sig_keys.length).to eq(1)
        expect(enc_keys.length).to eq(1)
      end

      it 'works with only signing key (no encryption key)' do
        ENV.delete('CUSTOM_ENCRYPTION_KEY')

        key_storage = described_class.new(
          signing_key_env: 'CUSTOM_SIGNING_KEY',
          encryption_key_env: nil
        )

        sig_keys = key_storage.jwks.keys.select { |k| k[:use] == 'sig' }
        enc_keys = key_storage.jwks.keys.select { |k| k[:use] == 'enc' }

        expect(sig_keys.length).to eq(1)
        expect(enc_keys.length).to eq(0)
      end
    end
  end

  describe '#jwks' do
    let(:key_storage) { described_class.new }

    it 'returns a JWT::JWK::Set' do
      expect(key_storage.jwks).to be_a(JWT::JWK::Set)
    end

    it 'contains both signing and encryption keys' do
      sig_keys = key_storage.jwks.keys.select { |k| k[:use] == 'sig' }
      enc_keys = key_storage.jwks.keys.select { |k| k[:use] == 'enc' }

      expect(sig_keys.length).to eq(1)
      expect(enc_keys.length).to eq(1)
    end

    it 'generates kid for each key' do
      key_storage.jwks.keys.each do |jwk|
        expect(jwk[:kid]).not_to be_nil
      end
    end

    it 'caches the JWK set' do
      first_call = key_storage.jwks
      second_call = key_storage.jwks
      expect(first_call.object_id).to eq(second_call.object_id)
    end
  end

  describe '#rotate_signing_key!' do
    let(:key_storage) { described_class.new }

    it 'raises NotImplementedError' do
      expect {
        key_storage.rotate_signing_key!
      }.to raise_error(NotImplementedError, /Key rotation is not supported for EnvKeyStorage/)
    end
  end

  describe '#rotate_encryption_key!' do
    let(:key_storage) { described_class.new }

    it 'raises NotImplementedError' do
      expect {
        key_storage.rotate_encryption_key!
      }.to raise_error(NotImplementedError, /Key rotation is not supported for EnvKeyStorage/)
    end
  end

  describe 'JWT operations' do
    let(:key_storage) { described_class.new }

    it 'can sign and verify tokens' do
      jwk = key_storage.jwks.keys.find { |k| k[:use] == 'sig' }
      payload = { data: 'test' }

      token = JWT.encode(payload, jwk.keypair, 'RS256', kid: jwk[:kid])
      decoded = JWT.decode(token, nil, true, algorithms: ['RS256'], jwks: key_storage.jwks.export)

      expect(decoded.first['data']).to eq('test')
    end

    it 'exports JWKS correctly' do
      export = key_storage.jwks.export

      expect(export).to have_key(:keys)
      expect(export[:keys]).to be_an(Array)
      expect(export[:keys].length).to eq(2)
    end
  end
end
