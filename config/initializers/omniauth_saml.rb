# config/initializers/omniauth_saml.rb
require 'omniauth'
require 'omniauth-saml'
require 'yaml'

begin
  # 1. Check the actual environment
  current_env = Rails.env.to_s
  Rails.logger.info "🔍 Loading SAML configuration for environment: #{current_env}"

  # 2. Load config from configuration.yml file
  config_path = Rails.root.join('config', 'configuration.yml')
  if File.exist?(config_path)
    config = YAML.load_file(config_path)

    # Find config for actual environment, fallback to default or the first available
    saml_config = config[current_env]&.dig('saml') ||
    config['default']&.dig('saml') ||
    config.values.first&.dig('saml')
  end

  # 3. Verify if SAML is enabled
  unless saml_config && saml_config['enabled']
    Rails.logger.info "ℹ️ SAML authentication disabled for environment: #{current_env}"
    return
  end

  Rails.logger.info "✅ SAML enabled for environment: #{current_env}"

  # 4. Validate required configuration keys
  required_keys = ['assertion_consumer_service_url', 'issuer', 'idp_sso_target_url', 'idp_cert']
  missing_keys = required_keys.select { |key| saml_config[key].blank? }

  if missing_keys.any?
    raise "SAML configuration missing for #{current_env}: #{missing_keys.join(', ')}"
  end

  # 5. Logging config (without sensible data)
  Rails.logger.info "📋 SAML Config - Issuer: #{saml_config['issuer']}"
  Rails.logger.info "📋 SAML Config - IdP URL: #{saml_config['idp_sso_target_url']}"

  # 6. Create personalized middleware
  class SamlMiddleware
    def initialize(app, strategy_config)
      @app = app
      @strategy_config = strategy_config
    end

    def call(env)
      # Create a fresh strategy for each request
      strategy = OmniAuth::Strategies::SAML.new(@app, @strategy_config)

      case env['PATH_INFO']
      when '/auth/saml'
        handle_request_phase(strategy)
      when '/auth/saml/callback'
        handle_callback_phase(strategy, env)
      else
        @app.call(env)
      end
    end

    private

    def handle_request_phase(strategy)
      result = strategy.request_phase
      if result.is_a?(Array) && result.size == 3
        result
      else
        redirect_url = extract_redirect_url(result)
        [302, {'Location' => redirect_url}, []]
      end
    rescue => e
      Rails.logger.error "SAML request error: #{e.message}"
      [500, {'Content-Type' => 'text/plain'}, ['SAML authentication failed']]
    end

    def handle_callback_phase(strategy, env)
      Rails.logger.info "🔄 Processing SAML callback..."

      begin
        status, headers, response = strategy.call!(env)

        if env['omniauth.auth']
          auth_hash = env['omniauth.auth']
          Rails.logger.info "✅ SAML authentication SUCCESS: #{auth_hash['uid']}"
          return [status, headers, response]
        else
          Rails.logger.error "❌ No auth hash despite successful HTTP response"
          return redirect_to_failure("Authentication data missing")
        end
      rescue => e
        Rails.logger.error "❌ SAML Callback Error: #{e.message}"
        return redirect_to_failure("Callback processing failed: #{e.message}")
      end
    end

    def extract_redirect_url(result)
      case result
      when Array
        result[1]['Location'] if result[1] && result[1]['Location']
      when Hash
        result['Location']
      else
        '/auth/failure'
      end
    end

    def redirect_to_failure(error_message = nil)
      if error_message
        [302, {'Location' => "/auth/failure?message=#{URI.encode_www_form_component(error_message)}"}, []]
      else
        [302, {'Location' => '/auth/failure'}, []]
      end
    end
  end

  # 7. Add personalized middleware
  Rails.application.config.middleware.use SamlMiddleware, {
    :assertion_consumer_service_url => saml_config['assertion_consumer_service_url'],
    :issuer                         => saml_config['issuer'],
    :idp_sso_target_url             => saml_config['idp_sso_target_url'],
    :idp_cert                       => saml_config['idp_cert'].to_s.delete('|').strip,
    :name_identifier_format         => saml_config['name_identifier_format'] || "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    :attribute_statements           => saml_config['attribute_statements'] || {
      :email      => ['email', 'mail'],
      :name       => ['name', 'displayName'],
      :first_name => ['first_name', 'firstName'],
      :last_name  => ['last_name', 'lastName']
    },

    :allowed_clock_drift => 5.seconds,
    :security => {
      authn_requests_signed: false,
      want_assertions_signed: false,
      want_assertions_encrypted: false,
      check_idp_cert_expiry: true,
      check_sp_cert_expiry: false,
      metadata_signed: false
    },
    :idp_sso_service_binding => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
    :idp_slo_service_binding => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
  }

  # 8. Add routes manually for SAML endpoints
  Rails.application.routes.draw do
    get '/auth/saml', to: ->(env) { [302, {'Location' => '/auth/saml'}, []] }
    get '/auth/saml/callback', to: 'account#omniauth_callback'
    get '/auth/failure', to: 'account#omniauth_failure'
  end

  Rails.logger.info "✅ SAML authentication configured for environment: #{current_env}"
rescue => e
  Rails.logger.error "❌ SAML configuration error in #{current_env}: #{e.message}"
end
