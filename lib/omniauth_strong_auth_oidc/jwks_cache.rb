module OmniauthStrongAuthOidc
  class JwksCache
    # Implmlement call method for use as a JWK loader in JWT.decode
    # Example:
    #  JWT.decode(token, nil, true, { jwks: OmniauthStrongAuthOidc::JwksCache.new(jwks_source) })
    #  where jwks_source responds to .jwks and .reload! (optional)
    def initialize(jwks_source, timeout_sec = 300)
      @jwks_source = jwks_source
      @timeout_sec = timeout_sec
      @cache_last_update = 0
    end

    def call(options = {})
      # The jwk loader would fetch the set of JWKs from a trusted source.
      # To avoid malicious requests triggering cache invalidations there needs to be
      # some kind of grace time or other logic for determining the validity of the invalidation.
      # This example only allows cache invalidations every 5 minutes.
      # and at least once a day.
      if (options[:kid_not_found] && @cache_last_update < Time.now.to_i - @timeout_sec)
        @cached_keys = nil
        @jwks_source.reload! if @jwks_source.respond_to?(:reload!)
      end
      @cached_keys ||= begin
        @cache_last_update = Time.now.to_i
        # Replace with your own JWKS fetching routine
        jwks = @jwks_source.jwks
        jwks.select { |key| key[:use] == 'sig' } # Signing Keys only
      end
    end
  end
end
