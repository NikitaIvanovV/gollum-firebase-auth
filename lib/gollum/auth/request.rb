require 'json'

module Gollum::Auth
  class Request < Rack::Request

    WRITE_PATH_RE = %r{
      ^/
      (gollum/)? # This path prefix was introduced in Gollum 5
      (create/|edit/|delete/|rename/|revert/|uploadFile$|upload_file$)
    }x

    def initialize(env, base_path='')
      super(env)
      @data_string = @env['rack.input'].read
      @base_path = base_path
    end

    def requires_authentication?(allow_unauthenticated_readonly)
      !allow_unauthenticated_readonly || is_write_path?
    end

    def store_author_in_session(user)
      session['gollum.author'] = { name: user.name, email: user.email }
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

    private

    # Returns true if path is a write path that would change the wiki.
    def is_write_path?
      !!(wiki_path =~ WRITE_PATH_RE)
    end

  end
end
