module Public
  class ImpersonationsController < ApplicationController
    def new
      authorize Impersonation
      @impersonation = Impersonation.new
    end

    def create
      @impersonation = Impersonation.new(impersonation_params.merge(user: current_user))

      authorize @impersonation

      if @impersonation.save
        public_user = Public::User.find_or_create_by!(email: impersonation_params[:target_email])
        
        # Log public user impersonation for audit trail
        Rails.logger.info "Public user impersonation: #{current_user.username} (#{current_user.id}) impersonating #{public_user.email} (#{public_user.id})"
        Honeybadger.notify("Public user impersonation", {
          impersonator_user_id: current_user.id,
          impersonator_username: current_user.username,
          target_email: public_user.email,
          target_user_id: public_user.id,
          justification: impersonation_params[:justification]
        })
        
        session[:public_user_id] = public_user.id
        session[:public_impersonator_user_id] = current_user.id
        redirect_to public_root_path
      else
        render :new
      end
    end

    def stop_impersonating
      session[:public_user_id] = nil
      session[:public_impersonator_user_id] = nil
      redirect_to public_root_path
    end

    def impersonation_params
      params.require(:public_impersonation).permit(:target_email, :justification)
    end
  end
end