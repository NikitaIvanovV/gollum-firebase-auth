require 'json'

module Gollum::Auth
  class Request < Rack::Request

    WIKI_URL_RE = %r{
      ^/
      (gollum/(?:create|edit|delete|rename|revert|revert_commit|upload_file)/?)?
      (.*)
    }x

    def initialize(env, base_path = '', email_placeholder = nil)
      super(env)
      @data_string = @env['rack.input'].read
      @base_path = base_path
      @email_placeholder = email_placeholder
    end

    def requires_authentication?(allow_unauthenticated_readonly)
      !allow_unauthenticated_readonly || is_write_path?
    end

    def store_author_in_session(user)
      email = @email_placeholder.nil? ? user.email : @email_placeholder
      session['gollum.author'] = { name: user.name, email: email }
    end

    def data
      return {} if @data_string == ''
      JSON.parse(@data_string)
    end

    def session_cookie
      cookies["session"]
    end

    def wiki_path
      path = path_info.dup
      path.slice! @base_path
      return path
    end

    def page
      match = wiki_path.match WIKI_URL_RE
      return nil if match.nil?
      match[2]
    end

    private

    # Returns true if path is a write path that would change the wiki.
    def is_write_path?
      match = wiki_path.match WIKI_URL_RE
      return false if match.nil?
      ! match[1].nil?
    end

  end
end
