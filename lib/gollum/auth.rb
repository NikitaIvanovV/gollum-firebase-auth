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
    LOGIN_PATH = '/gollum/login'

    def self.new(*args)
      App.new(*args)
    end

    class App

      def initialize(app, firebase_config, opts = { })
        @app = app
        @firebase = Firebase::Firebase.new(firebase_config[:projectId])
        @firebase_config = firebase_config

        @opts = {
          allow_unauthenticated_readonly: false,
          secure_cookie: false
        }.merge(opts)
      end

      def call(env)
        request = Request.new(env, base_path('/%s'), @opts[:email_placeholder])

        # Login user
        if request.wiki_path == LOGIN_PATH
          if request.get?
            return login request
          elsif request.post?
            return session_login request
          else
            return server_error
          end
        end

        session_cookie = request.session_cookie
        decoded_claims = nil

        # Verify token and get claims
        unless session_cookie.nil?
          begin
            decoded_claims = verify_session_cookie(session_cookie)
          rescue Firebase::Error, JWT::EncodeError, JWT::DecodeError
          end
        end

        # Set commit author
        user = nil
        unless decoded_claims.nil?
          user = get_user_from_claims(decoded_claims)
          request.store_author_in_session(user)
        end

        is_admin = admin? user
        request.session['fancade_wiki.is_admin'] = is_admin

        # Restrict users to access page if unauthorized
        if request.requires_authentication?(@opts[:allow_unauthenticated_readonly])
          protect_page = protected_page?(request.page) && !is_admin && !user.nil?
          return permission_denied if protect_page || banned?(user)

          if session_cookie.nil? || decoded_claims.nil?
            if request.get?
              path = base_path('/%s') + LOGIN_PATH
              response = Rack::Response.new
              response.redirect("#{path}?page=#{CGI.escape request.url}", 302)
              return response.finish
            else
              return permission_denied
            end
          end
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
          decoded_claims = @firebase.decode_id_token(id_token)
          session_cookie = @firebase.create_session_cookie(decoded_claims, expires_in)
        rescue Firebase::Error, JWT::EncodeError, JWT::DecodeError
          return not_authorized
        end

        user = get_user_from_claims(decoded_claims)

        return not_authorized if banned? user

        response = Rack::Response.new

        # Set cookie policy for session cookie.
        expires = Time.now + expires_in
        response.set_cookie('session', {
          :value => session_cookie, :expires => expires,
          :httponly => true, :secure => @opts[:secure_cookie], :path => '/' + base_path
        })

        # Save author info
        request.store_author_in_session(user)

        response.finish
      end

      def banned?(user)
        banned = @opts[:banned]
        return false if banned.nil? || user.nil?
        in_provided_list?(banned, user.name)
      end

      def admin?(user)
        admins = @opts[:admins]
        return false if admins.nil? || user.nil?
        in_provided_list?(admins, user.name)
      end

      def protected_page?(page_name)
        protected = @opts[:protected_pages]
        return false if protected.nil? || page_name.nil?
        in_provided_list?(protected, page_name)
      end

      def in_provided_list?(list_or_method, element)
        if list_or_method.is_a? Method
          list_or_method.call element
        else
          list_or_method.include? element
        end
      end

      def not_authorized
        Response::error(401, 'Failed to authorize')
      end

      def permission_denied
        Response::error(403, 'Forbidden')
      end

      def login request
        Response::login(@firebase_config, request, @opts[:login_layout])
      end

      def auth
        Response::auth
      end

      def success
        Response::success
      end

      def server_error
        Response::server_error
      end

    end
  end
end
