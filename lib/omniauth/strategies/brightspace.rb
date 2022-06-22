# frozen_string_literal: true

require 'omniauth-oauth2'
require 'net/https'

module OmniAuth
  module Strategies
    class Brightspace < OmniAuth::Strategies::OAuth2
      option :name, 'brightspace'

      option :client_options,
             authorize_url: 'https://auth.brightspace.com/oauth2/auth',
             token_url: 'https://auth.brightspace.com/core/connect/token'

      uid { id_info['sub'] }

      def callback_url
        options[:redirect_uri] || (full_host + script_name + callback_path)
      end

      def request_phase
        if request.env['omniauth.error.type']
          redirect options[:redirect_path_on_failure]
        else
          super
        end
      end

      private

      def id_info
        id_token = access_token.token
        payload, _header = ::JWT.decode(id_token, nil, false)
        payload
      end

      extra do
        { 'raw_info' => raw_info }
      end

      def raw_info
        whoami_url = "#{session['referrer']}/d2l/api/lp/1.31/users/whoami"
        @raw_info ||= access_token.get(whoami_url).parsed
      end
    end
  end
end
