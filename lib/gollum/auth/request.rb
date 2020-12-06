require 'json'

module Gollum::Auth
  class Request < Rack::Request

    WRITE_PATH_RE = %r{
      ^/
      (?:gollum/)? # This path prefix was introduced in Gollum 5
      (create/|edit/|delete/|rename/|revert/|uploadFile$|upload_file$)
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
      if @email_placeholder.nil?
        email = user.email
      else
        email = @email_placeholder
      end

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

    def edited_page
      match = wiki_path.match WRITE_PATH_RE
      match[2]
    end

    private

    # Returns true if path is a write path that would change the wiki.
    def is_write_path?
      !!(wiki_path =~ WRITE_PATH_RE)
    end

  end
end
