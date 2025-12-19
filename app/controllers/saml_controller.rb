# app/controllers/saml_controller.rb
class SamlController < ApplicationController
  skip_before_action :check_if_login_required
  skip_before_action :verify_authenticity_token, only: [:callback]

  def callback
    Rails.logger.info "🎉 SAML callback received!"

    # OmniAuth data is on request.env['omniauth.auth']
    auth = request.env['omniauth.auth']

    if auth
      Rails.logger.info "✅ SAML Authentication Successful!"
      Rails.logger.info "🔍 User: #{auth['uid']}"
      Rails.logger.info "🔍 Email: #{auth['info']['email']}"
      Rails.logger.info "🔍 Name: #{auth['info']['name']}"
      Rails.logger.info "🔍 All auth data: #{auth.inspect}"

      user = find_or_create_user_from_saml(auth)

      if user && user.active?
        # Successful authentication in Redmine

        # session[:user_id] = user.id
        # User.current = user

        # Register successful login
        Rails.logger.info "✅ SAML Login Successful: #{user.login} (#{user.mail})"

        successful_saml_login(user)

        # Redirect to the main page
        if session[:user_id] == user.id
          # Rails.logger.info "✅ SESIÓN CONFIRMADA - Redirigiendo a my_page"
          # redirect_to my_page_path # , notice: "SAML Authentication Successful! Welcome, #{user.firstname}."
          successful_saml_authentication(user)
        else
          Rails.logger.error "❌ SESSION NOT PERSISTED - session[:user_id]: #{session[:user_id]}, expected: #{user.id}"
          handle_authentication_failure("Session error")
        end
      elsif user && !user.active?
        handle_authentication_failure("User account is inactive")
      else
        # Can't create/authenticate user
        handle_authentication_failure("Could not authenticate user")
        # render plain: "SAML Authentication Successful but could not log into Redmine. User data: #{auth['info']}"
      end

      # render plain: "SAML Authentication Successful!<br>User: #{auth['uid']}<br>Email: #{auth['info']['email']}<br>Name: #{auth['info']['name']}"
    else
      Rails.logger.error "❌ No auth data in SAML callback"
      # render plain: "No authentication data received in SAML callback"
      handle_authentication_failure("No authentication data received")
    end
  end

  def failure
    Rails.logger.error "❌ SAML Authentication Failed: #{params.inspect}"
    render plain: "SAML Authentication Failed: #{params[:message]}"
  end

  private

  def find_or_create_user_from_saml(auth)
    email = auth['info']['email']
    first_name = auth['info']['first_name'] || 'SAML'
    last_name = auth['info']['last_name'] || 'User'

    # Normalizar login (email sin dominio, solo caracteres válidos)
    login = email.split('@').first.gsub(/[^a-z0-9_]/i, '_').downcase

    Rails.logger.info "🔍 Searching user: #{email}"

    # 1. FIRST search by EMAIL (safer)
    user = User.find_by_mail(email)

    # 2. If not found, search by LOGIN
    user ||= User.find_by_login(login)

    if user
      Rails.logger.info "✅ Existing user found: #{user.login} (#{user.mail})"

      # Update user info if changed
      update_user_info(user, first_name, last_name)

    else
      Rails.logger.info "📝 Creating NEW user: #{login} (#{email})"

      # 3. CREATE new user
      user = create_saml_user(login, first_name, last_name, email)
    end

    user
  end

  def update_user_info(user, first_name, last_name)
    # Update first name if different
    if user.firstname != first_name || user.lastname != last_name
      Rails.logger.info "📝 Updating user info: #{user.firstname} #{user.lastname} -> #{first_name} #{last_name}"
      user.update_columns(firstname: first_name, lastname: last_name)
    end
  end

  def create_saml_user(login, first_name, last_name, email)
    # Verify that the login does not exist (just in case)
    counter = 1
    original_login = login
    while User.find_by_login(login)
      login = "#{original_login}_#{counter}"
      counter += 1
    end

    user = User.new(
      login: login,
      firstname: first_name,
      lastname: last_name,
      mail: email,
      language: Setting.default_language,
      status: User::STATUS_ACTIVE,
      auth_source_id: nil
    )

    # Password insecure (can't be used - just for validation)
    password = SecureRandom.hex(32)
    user.password = password
    user.password_confirmation = password
    user.must_change_passwd = false  # 🔥 IMPORTANT: Do not require password change

    if user.save
      Rails.logger.info "✅ New user created: #{user.login}"

      # Activate user immediately
      user.activate

      # Assign default role
      assign_default_role(user)

      user
    else
      Rails.logger.error "❌ Error creating user: #{user.errors.full_messages.join(', ')}"
      nil
    end
  end

  def assign_default_role(user)
    # Assign "Non member" role or the one you prefer
    default_role = Role.non_member || Role.find_by_name('Usuario SAML') || Role.first

    if default_role && !user.roles.include?(default_role)
      member = Member.new(
        project: Project.default,  # Default project
        user: user,
        roles: [default_role]
      )

      if member.save
        Rails.logger.info "✅ Role assigned: #{default_role.name}"
      else
        Rails.logger.error "❌ Error assigning role: #{member.errors.full_messages.join(', ')}"
      end
    end
  end

  def successful_saml_login(user)
    # Reset the session to prevent session fixation
    reset_session

    # Start the session
    start_user_session(user)

    # Update last login time
    user.update_last_login_on!

    # Set logged user
    self.logged_user = user

    # Generate autologin cookie if autologin is enabled
    if Setting.autologin?
      set_autologin_cookie(user)
    end

    Rails.logger.info "✅ SAML authentication successful for '#{user.login}'"
  end

  def start_user_session(user)
    session[:user_id] = user.id
    session[:updated_at] = Time.now
    session[:tk] = user.generate_session_token
  end

  # Method for setting the logged user (as ApplicationController does)
  def logged_user=(user)
    if user && user.is_a?(User)
      User.current = user
      start_user_session(user)
    else
      User.current = User.anonymous
    end
  end

  def successful_saml_authentication(user)
    logger.info "Successful SAML authentication for '#{user.login}' from #{request.remote_ip} at #{Time.now.utc}"

    # 1. Set logged user (KEY METHOD)
    self.logged_user = user

    # 2. Generate autologin cookie if enabled
    if Setting.autologin?
      set_autologin_cookie(user)
    end

    # 3. Call Redmine hooks if they exist
    call_hook(:controller_account_success_authentication_after, {:user => user}) if respond_to?(:call_hook)

    # 4. Redirect (AS AccountController does)
    redirect_back_or_default my_page_path
  end

  def successful_authentication(user)
    logger.info "Successful authentication for '#{user.login}' from #{request.remote_ip} at #{Time.now.utc}"
    # Valid user
    self.logged_user = user
    # generate a key and set cookie if autologin
    if params[:autologin] && Setting.autologin?
      set_autologin_cookie(user)
    end
    call_hook(:controller_account_success_authentication_after, {:user => user})
    redirect_back_or_default my_page_path
  end

  def set_autologin_cookie(user)
    token = user.generate_autologin_token
    secure = Redmine::Configuration['autologin_cookie_secure']
    if secure.nil?
      secure = request.ssl?
    end
    cookie_options = {
      :value => token,
      :expires => 1.year.from_now,
      :path => (Redmine::Configuration['autologin_cookie_path'] || RedmineApp::Application.config.relative_url_root || '/'),
      :same_site => :lax,
      :secure => secure,
      :httponly => true
    }
    cookies[autologin_cookie_name] = cookie_options
  end
end
