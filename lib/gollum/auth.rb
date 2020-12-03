require 'jwt'
require 'time'
require 'rack'
require 'gollum/auth/version'
require 'gollum/auth/request'
require 'gollum/auth/user'
require 'gollum/auth/response'
require 'gollum/auth/firebase'

module Gollum
  module Auth
    def self.new(*args)
      App.new(*args)
    end

    class App

      def initialize(app, firebase_config, opts = { })
        @app = app
        @firebase = Firebase::Firebase.new(firebase_config[:projectId])
        @firebase_config = firebase_config

        @opts = { allow_unauthenticated_readonly: false }.merge(opts)
      end

      def call(env)
        request = Request.new(env, base_path('/%s'))

        # Login user
        return session_login(request) if request.wiki_path == '/gollum/session_login'

        session_cookie = request.session_cookie
        decoded_claims = nil

        # Verify token and get claims
        unless session_cookie.nil?
          begin
            decoded_claims = verify_session_cookie(session_cookie)
          rescue Firebase::Error, JWT::EncodeError, JWT::DecodeError
          end
        end

        # Restrict users to access page if unauthorized
        if request.requires_authentication?(@opts[:allow_unauthenticated_readonly])
          return login if session_cookie.nil? || decoded_claims.nil?
        end

        # Set commit author
        unless decoded_claims.nil?
          user = get_user_from_claims(decoded_claims)
          request.store_author_in_session(user)
        end

        @app.call(env)
      end

      private

      def base_path(format='%s')
        return '' if ! @opts[:base_path]
        format % @opts[:base_path]
      end

      def get_user_from_claims(claims)
        headers = claims[0]
        User.new(headers['sub'], headers['email'])
      end

      def verify_session_cookie(cookie)
        @firebase.decode_session_cookie(cookie)
      end

      def session_login(request)
        id_token = request.data['idToken']
        expires_in = 14*24*60*60  # session cookie will expire in 2 weeks
        begin
          # Create the session cookie. This will also verify the ID token in the process.
          # The session cookie will have the same claims as the ID token.
          session_cookie = @firebase.create_session_cookie(id_token, expires_in)
        rescue Firebase::Error, JWT::EncodeError, JWT::DecodeError
          return Response::error(401, 'Failed to authorize')
        end

        response = Rack::Response.new 'OK', 200, {}
        # Set cookie policy for session cookie.
        expires = Time.now + expires_in
        response.set_cookie('session', {
          :value => session_cookie, :expires => expires,
          :httponly => true, :secure => false, :path => '/' + base_path
        })
        response.finish
      end

      def not_authorized
        Response::not_authorized
      end

      def login
        Response::login(@firebase_config, @opts[:login_layout])
      end

      def auth
        Response::auth
      end

      def success
        Response::success
      end

    end
  end
end
