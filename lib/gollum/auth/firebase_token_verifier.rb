# Original stolen from here:
# https://github.com/soulfly/firebase-id-tokens-verifier/blob/master/verifier.rb

require 'jwt'
require 'net/http'

module Gollum::Auth

  module Firebase

    # Verifies Firebase ID token according to Firebase validation rules:
    # https://firebase.google.com/docs/auth/admin/verify-id-tokens#verify_id_tokens_using_a_third-party_jwt_library

    class IDTokenVerifier

      # VALID_JWT_PUBLIC_KEYS_RESPONSE_CACHE_KEY = "firebase_phone_jwt_public_keys_cache_key"
      JWT_ALGORITHM = 'RS256'

      ID_TOKEN_ISSUER_PREFIX = 'https://securetoken.google.com/'
      ID_TOKEN_CERT_URI = 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com'

      def initialize(firebase_project_id)
        @firebase_project_id = firebase_project_id
      end

      def verify_session_cookie(cookie)
        payload, header = cookie

        issuer = payload['iss']
        audience = payload['aud']
        subject = payload['sub']

        algorithm = header['alg']
        key_id = header['kid']

        expected_issuer = ID_TOKEN_ISSUER_PREFIX + @firebase_project_id

        if algorithm != JWT_ALGORITHM
          return false
        elsif key_id.nil?
          return false
        elsif audience != @firebase_project_id
          return false
        elsif issuer != expected_issuer
          return false
        elsif (! subject) || (! subject.instance_of?(String))
          return false
        elsif subject.length > 128
          return false
        end

        return true
      end

      def get_key_id
        valid_public_keys = retrieve_and_cache_jwt_valid_public_keys
        valid_public_keys.keys.sample
      end

      def encode_claims(rsa_private)

        payload = { :exp => Time.now.getutc.to_i+60*60, :iat => Time.now.getutc.to_i-60*60,
                    :aud => @firebase_project_id, :iss => 'https://session.firebase.google.com/'+@firebase_project_id,
                    :sub => "325230123348"}
        headers = {:alg => JWT_ALGORITHM, :kid => get_key_id}

        encode(headers, payload, rsa_private)
      end

      def encode(headers, payload, rsa_private)
        valid_public_keys = retrieve_and_cache_jwt_valid_public_keys
        kid = valid_public_keys.keys.sample
        headers['kid'] = get_key_id
        JWT.encode payload, rsa_private, JWT_ALGORITHM, headers
      end

      def decode(id_token, public_key)
        decoded_token, error = IDTokenVerifier.decode_jwt_token(id_token, @firebase_project_id, public_key)
        unless error.nil?
          raise Error.new(error)
        end

        # Decoded data example:
        # [
        #   {"data"=>"test"}, # payload
        #   {"typ"=>"JWT", "alg"=>"none"} # header
        # ]
        payload = decoded_token[0]
        headers = decoded_token[1]

        # validate headers

        alg = headers['alg']
        if alg != JWT_ALGORITHM
          raise Error.new("Invalid access token 'alg' header (#{alg}). Must be '#{JWT_ALGORITHM}'.")
        end

        valid_public_keys = retrieve_and_cache_jwt_valid_public_keys
        kid = headers['kid']
        unless valid_public_keys.keys.include?(kid)
          raise Error.new("Invalid access token 'kid' header, do not correspond to valid public keys.")
        end

        # validate payload

        # We are going to validate Subject ('sub') data only
        # because others params are validated above via 'resque' statement,
        # but we can't do the same with 'sub' there.
        # Must be a non-empty string and must be the uid of the user or device.
        sub = payload['sub']
        if sub.nil? || sub.empty?
          raise Error.new("Invalid access token. 'Subject' (sub) must be a non-empty string.")
        end

        # validate signature
        #
        # for this we need to decode one more time, but now with cert public key
        # More info: https://github.com/jwt/ruby-jwt/issues/216
        #
        decoded_token, error = IDTokenVerifier.decode_jwt_token(id_token, @firebase_project_id, public_key)
        if decoded_token.nil?
          raise Error.new(error)
        end

        decoded_token
      end

      def self.decode_jwt_token(firebase_jwt_token, firebase_project_id, public_key)
        # Now we decode JWT token and validate
        # Validation rules:
        # https://firebase.google.com/docs/auth/admin/verify-id-tokens#verify_id_tokens_using_a_third-party_jwt_library

        custom_options = {:verify_iat => true,
          :verify_aud => true, :aud => firebase_project_id,
          :verify_iss => true, :iss => "https://securetoken.google.com/"+firebase_project_id }

        unless public_key.nil?
          custom_options[:algorithm] = JWT_ALGORITHM
        end

        begin
          decoded_token = JWT.decode(firebase_jwt_token, public_key, !public_key.nil?, custom_options)
        rescue JWT::ExpiredSignature
          # Handle Expiration Time Claim: bad 'exp'
          return nil, "Invalid access token. 'Expiration time' (exp) must be in the future."
        rescue JWT::InvalidIatError
          # Handle Issued At Claim: bad 'iat'
          return nil, "Invalid access token. 'Issued-at time' (iat) must be in the past."
        rescue JWT::InvalidAudError
          # Handle Audience Claim: bad 'aud'
          return nil, "Invalid access token. 'Audience' (aud) must be your Firebase project ID, the unique identifier for your Firebase project."
        rescue JWT::InvalidIssuerError
          # Handle Issuer Claim: bad 'iss'
          return nil, "Invalid access token. 'Issuer' (iss) Must be 'https://securetoken.google.com/<projectId>', where <projectId> is your Firebase project ID."
        rescue JWT::VerificationError
          # Handle Signature verification fail
          return nil, "Invalid access token. Signature verification failed."
        end

        return decoded_token, nil
      end

      def retrieve_and_cache_jwt_valid_public_keys
        # Get valid JWT public keys and save to cache
        #
        # Must correspond to one of the public keys listed at
        # https://www.googleapis.com/identitytoolkit/v3/relyingparty/publicKeys

        valid_public_keys = cached_public_keys
        if valid_public_keys.nil?
          uri = URI(ID_TOKEN_CERT_URI)
          https = Net::HTTP.new(uri.host, uri.port)
          https.use_ssl = true
          req = Net::HTTP::Get.new(uri.path)
          response = https.request(req)
          if response.code != '200'
            raise Error.new("Something went wrong: can't obtain valid JWT public keys from Google.")
          end
          valid_public_keys = JSON.parse(response.body)

          cc = response["cache-control"] # format example: Cache-Control: public, max-age=24442, must-revalidate, no-transform
          max_age = cc[/max-age=(\d+?),/m, 1] # get something between 'max-age=' and ','

          cache_public_keys(valid_public_keys, max_age.to_i)
        end

        return valid_public_keys

      end

      private

      def cached_public_keys
        return nil if @cached_public_keys.nil?

        # Return nothing if keys are expired
        return nil if Time.now > @cached_public_keys_expire_at

        @cached_public_keys
      end

      def cache_public_keys(keys, expire_in)
        @cached_public_keys = keys
        @cached_public_keys_expire_at = Time.now + expire_in
      end

    end

  end

end
