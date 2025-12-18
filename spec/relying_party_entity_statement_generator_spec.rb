require 'spec_helper'

RSpec.describe OmniauthStrongAuthOidc::RelyingPartyEntityStatementGenerator do
  let(:signing_key) { OpenSSL::PKey::RSA.new(4096) }
  let(:encryption_key) { OpenSSL::PKey::RSA.new(4096) }

  # Separate entity statement signing key
  let(:entity_statement_signing_key_pem) { OpenSSL::PKey::RSA.new(4096).to_pem }
  let(:configuration_jwks_storage) do
    storage = OmniauthStrongAuthOidc::RelyingPartyJwksStorage::EnvStorage.new(
      signing_key_env: 'ENTITY_STATEMENT_SIGNING_KEY_BASE64',
      encryption_key_env: nil
    )
    storage
  end

  let(:iss) { "https://example.com" }
  let(:org_name) { "Test Organization" }
  let(:jwks_uri) { 'https://example.com/oauth2/telia/jwks' }
  let(:signed_jwks_uri) { 'https://example.com/oauth2/telia/signed_jwks.jwt' }
  let(:redirect_uris) { ['https://example.com/callback'] }

  before do
    ENV['ENTITY_STATEMENT_SIGNING_KEY_BASE64'] = Base64.strict_encode64(entity_statement_signing_key_pem)
  end

  after do
    ENV.delete('ENTITY_STATEMENT_SIGNING_KEY_BASE64')
  end

  subject do
    described_class.new(
      iss: iss,
      org_name: org_name,
      jwks_uri: jwks_uri,
      signed_jwks_uri: signed_jwks_uri,
      redirect_uris: redirect_uris,
      configuration_jwks_storage: configuration_jwks_storage
    )
  end

  describe '#generate_signed' do
    let(:entity_statement_jwt) { subject.generate_signed }
    let(:decoded_payload) { JWT.decode(entity_statement_jwt, nil, false).first }
    let(:decoded_header) { JWT.decode(entity_statement_jwt, nil, false).last }

    it 'generates a valid JWT' do
      expect(entity_statement_jwt).to be_a(String)
      expect(entity_statement_jwt.split('.').length).to eq(3)
    end

    it 'has correct JWT header type' do
      expect(decoded_header['typ']).to eq('entity-statement+jwt')
    end

    it 'has correct algorithm' do
      expect(decoded_header['alg']).to eq('RS256')
    end

    it 'has kid in header' do
      expect(decoded_header['kid']).not_to be_nil
    end

    it 'has correct issuer and subject' do
      expect(decoded_payload['iss']).to eq(iss)
      expect(decoded_payload['sub']).to eq(iss)
    end

    it 'has iat and exp claims' do
      expect(decoded_payload['iat']).to be_a(Integer)
      expect(decoded_payload['exp']).to be_a(Integer)
      expect(decoded_payload['exp']).to be > decoded_payload['iat']
    end

    it 'includes openid_relying_party metadata' do
      metadata = decoded_payload['metadata']
      expect(metadata).to have_key('openid_relying_party')

      rp_metadata = metadata['openid_relying_party']
      expect(rp_metadata['client_name']).to eq(org_name)
      expect(rp_metadata['jwks_uri']).to eq(jwks_uri)
      expect(rp_metadata['signed_jwks_uri']).to eq(signed_jwks_uri)
      expect(rp_metadata['redirect_uris']).to eq(redirect_uris)
    end

    it 'includes correct authentication and signing methods' do
      rp_metadata = decoded_payload['metadata']['openid_relying_party']

      expect(rp_metadata['token_endpoint_auth_method']).to eq('private_key_jwt')
    end

    it 'includes jwks with signing key' do
      jwks = decoded_payload['jwks']
      expect(jwks).to have_key('keys')
      expect(jwks['keys']).to be_an(Array)
      expect(jwks['keys'].length).to be >= 1

      signing_key = jwks['keys'].find { |k| k['use'] == 'sig' }
      expect(signing_key).not_to be_nil
      expect(signing_key['kty']).to eq('RSA')
      expect(signing_key['n']).not_to be_nil
      expect(signing_key['e']).not_to be_nil
    end

    it 'can be verified with the entity statement signing key' do
      entity_jwks = configuration_jwks_storage.jwks
      signing_jwk = entity_jwks.select { |k| k[:use] == 'sig' }.first
      public_key = signing_jwk.keypair.public_key

      expect {
        JWT.decode(entity_statement_jwt, public_key, true, algorithm: 'RS256')
      }.not_to raise_error
    end

    it 'includes response_types and grant_types' do
      rp_metadata = decoded_payload['metadata']['openid_relying_party']

      expect(rp_metadata['response_types']).to eq(['code'])
      expect(rp_metadata['grant_types']).to eq(['authorization_code'])
    end
  end
end
