require 'net/http'
require 'gollum/auth/firebase_token_verifier'

module Gollum::Auth

  module Firebase

    class Error < StandardError
    end

    class Firebase

      ID_TOOLKIT_URL = 'https://identitytoolkit.googleapis.com/v1'
      COOKIE_EXPIRES_IN = 'cxp'

      def initialize(firebase_project_id)
        @firebase_project_id = firebase_project_id
        @verifier = IDTokenVerifier.new(firebase_project_id)

        @private_key = OpenSSL::PKey::RSA.generate 2048
        @public_key = @private_key.public_key

        @base_url = "#{ID_TOOLKIT_URL}/projects/#{@firebase_project_id}"
      end

      def decode_id_token(id_token)
        @verifier.decode(id_token, nil)
      end

      def encode_claims(headers, payload, private_key)
        @verifier.encode(headers, payload, private_key)
      end

      def create_session_cookie(token_id, expires_in)
        payload, headers = decode_id_token(token_id)
        encode_claims(headers, payload.merge({ COOKIE_EXPIRES_IN => expires_in }), @private_key)
      end

      def decode_session_cookie(cookie)
        @verifier.decode(cookie, @public_key)
      end

    end

  end

end
