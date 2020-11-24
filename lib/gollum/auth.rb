require 'jwt'
require 'time'
require 'digest'
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

      def initialize(app, firebase_project_id, firebase_config, opts = { })
        @app = app
        @firebase = Firebase::Firebase.new(firebase_project_id)
        @firebase_config = firebase_config
        @opts = { allow_unauthenticated_readonly: false, base_path: '/' }.merge(opts)
        @opts[:base_path] =  '/' + @opts[:base_path]
      end

      def call(env)
        request = Request.new(env)
        path_info = request.path_info

        if path_info == "/gollum/session_login"
          return session_login(request)
        end

        if request.requires_authentication?(@opts[:allow_unauthenticated_readonly])
          session_cookie = request.session_cookie
          if session_cookie.nil?
            return login
          end

          begin
            decoded_claims = verify_session_cookie(session_cookie)
          rescue Firebase::Error, JWT::EncodeError, JWT::DecodeError
            decoded_claims = nil
          end

          if decoded_claims.nil?
            return login
          end

          user = get_user_from_claims(decoded_claims)
          request.store_author_in_session(user)
        end

        @app.call(env)
      end

      private

      def get_user_from_claims(cookie)
        headers = cookie[0]
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
          :value => session_cookie.to_json, :expires => expires,
          :httponly => true, :secure => false, :path => @opts[:base_path]
        })
        response.finish
      end

      def not_authorized
        Response::not_authorized
      end

      def login
        Response::login(@firebase_config)
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
