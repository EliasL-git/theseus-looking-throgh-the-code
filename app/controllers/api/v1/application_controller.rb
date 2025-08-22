module API
  module V1
    class ApplicationController < ActionController::API
      prepend_view_path Rails.root.join("app/views/api/v1")
      attr_reader :current_user

      before_action :authenticate!
      before_action :set_expand
      before_action :set_pii

      include Pundit::Authorization
      include ActionController::HttpAuthentication::Token::ControllerMethods

      rescue_from Pundit::NotAuthorizedError do |e|
        render json: { error: "not_authorized" }, status: :forbidden
      end

      rescue_from ActiveRecord::RecordNotFound do |e|
        render json: { error: "resource_not_found", message: ("Couldn't locate that #{e.model.constantize.model_name.human}." if e.model) }.compact_blank, status: :not_found
      end

      rescue_from ActiveRecord::RecordInvalid do |e|
        render json: { error: "validation_error", messages: e.record.errors.full_messages }, status: :bad_request
      end

      rescue_from ActiveRecord::RecordNotUnique do |e|
        render json: { error: "idempotency_error", messages: ["a record by that idempotency key already exists!"] }, status: :bad_request
      end

      rescue_from ActionController::ParameterMissing do |e|
        render json: { error: "missing_parameter", messages: [e.message] }, status: :bad_request
      end

      private

      def set_expand
        @expand = params[:expand].to_s.split(",").map { |e| e.strip.to_sym }
      end

      def set_pii = @pii = current_token&.pii?

      def authenticate!
        @current_token = authenticate_with_http_token { |t, _options| APIKey.find_by(token: t) }
        unless @current_token&.active?
          return render json: { error: "invalid_auth" }, status: :unauthorized
        end
        @current_user = if current_token&.may_impersonate? && params[:impersonate].present?
            begin
              target_user = User.find_by!(slack_id: params[:impersonate])
              
              # Security check: Only allow impersonation if the API key owner is an admin
              # or if there are explicit authorization rules in place
              unless authorize_impersonation(current_token.user, target_user)
                Rails.logger.warn "Unauthorized impersonation attempt: #{current_token.user.username} (#{current_token.user.id}) attempted to impersonate #{target_user.username} (#{target_user.id})"
                
                # Report unauthorized attempts to security monitoring
                Honeybadger.notify("Unauthorized API impersonation attempt", {
                  impersonator_user_id: current_token.user.id,
                  impersonator_username: current_token.user.username,
                  target_user_id: target_user.id,
                  target_username: target_user.username,
                  api_key_id: current_token.id,
                  api_key_name: current_token.name,
                  remote_ip: request.remote_ip,
                  user_agent: request.user_agent
                })
                
                return render json: { error: "impersonate_unauthorized", message: "not authorized to impersonate this user" }, status: :forbidden
              end
              
              # Log successful impersonation for audit trail
              Rails.logger.info "API impersonation: #{current_token.user.username} (#{current_token.user.id}) impersonating #{target_user.username} (#{target_user.id}) with API key #{current_token.id}"
              
              # Report to monitoring for security audit
              Honeybadger.notify("API impersonation", {
                impersonator_user_id: current_token.user.id,
                impersonator_username: current_token.user.username,
                target_user_id: target_user.id,
                target_username: target_user.username,
                api_key_id: current_token.id,
                api_key_name: current_token.name
              })
              
              target_user
            rescue ActiveRecord::RecordNotFound
              render json: { error: "impersonate_error", message: "couldn't find that user" }, status: :bad_request
            end
          else
            current_token&.user
          end
      end

      attr_reader :current_token

      # Define authorization rules for API key impersonation
      # This method determines whether the impersonator_user can impersonate the target_user
      def authorize_impersonation(impersonator_user, target_user)
        # Rule 1: Only admins can impersonate other users by default
        return true if impersonator_user.admin?
        
        # Rule 2: Users cannot impersonate themselves (redundant but explicit)
        return false if impersonator_user == target_user
        
        # Rule 3: Add additional business logic here as needed
        # For example: users in the same organization, team leads impersonating team members, etc.
        # For now, we default to false for maximum security
        
        false
      end
    end
  end
end
