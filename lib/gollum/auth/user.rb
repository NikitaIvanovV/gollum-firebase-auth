module Gollum::Auth
  class InvalidUserError < StandardError
  end

  class User

    attr_accessor :name
    attr_accessor :email

    def initialize(name, email)
      @name = name
      @email = email
    end

  end
end
