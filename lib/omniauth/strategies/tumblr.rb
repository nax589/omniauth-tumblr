require 'omniauth-oauth'
require 'multi_json'

module OmniAuth
  module Strategies
    class Tumblr < OmniAuth::Strategies::OAuth

      option :name, 'tumblr'
      option :client_options, {:site => 'https://www.tumblr.com',
                               :request_token_path => "/oauth/request_token",
                               :access_token_path  => "/oauth/access_token",
                               :authorize_path     => "/oauth/authorize"}

      uid { raw_info['name'] }

      info do
        {
          :nickname => raw_info['name'],
          :name => raw_info['name'],
          :blogs => raw_info['blogs'].map do |b|
            { :name => b['name'], :url => b['url'], :title => b['title'] }
          end,
          :avatar => avatar_url
        }
      end

      extra do
        { :raw_info => raw_info.merge({ :avatar => avatar_url }) }
      end

      def user
        tumblelogs = user_hash['tumblr']['tumblelog']
        if tumblelogs.kind_of?(Array)
          @user ||= tumblelogs[0]
        else
          @user ||= tumblelogs
        end
      end

      def raw_info
        url = 'http://api.tumblr.com/v2/user/info'
        @raw_info ||= MultiJson.decode(access_token.get(url).body)['response']['user']
      end

      def avatar_url
        url = "http://api.tumblr.com/v2/blog/#{ raw_info['blogs'].first['url'].sub(%r|^https?://|, '').sub(%r|/?$|, '') }/avatar"
        res = access_token.get(url).body
        @avatar_url ||= MultiJson.decode(res)['response']['avatar_url']
      end

      alias :old_callback_phase :callback_phase

      def callback_phase # rubocop:disable MethodLength
        fail(OmniAuth::NoSessionError, "Session Expired") if session["oauth"].nil?

        request_token = ::OAuth::RequestToken.new(consumer, session["oauth"][name.to_s].delete("request_token"), session["oauth"][name.to_s].delete("request_secret"))

        opts = {}
        if session["oauth"][name.to_s]["callback_confirmed"]
          opts[:oauth_verifier] = request["oauth_verifier"].gsub('#_=_', '')
        else
          opts[:oauth_callback] = callback_url
        end
        @access_token = request_token.get_access_token(opts)
        # old_callback_phase
        env['omniauth.auth'] = auth_hash
        call_app!
      rescue ::Timeout::Error => e
        fail!(:timeout, e)
      rescue ::Net::HTTPFatalError, ::OpenSSL::SSL::SSLError => e
        fail!(:service_unavailable, e)
      rescue ::OAuth::Unauthorized => e
        fail!(:invalid_credentials, e)
      rescue ::OmniAuth::NoSessionError => e
        fail!(:session_expired, e)
      end

      credentials do
        {"token" => access_token.token, "secret" => access_token.secret}
      end

      extra do
        {"access_token" => access_token}
      end
    end
  end
end
