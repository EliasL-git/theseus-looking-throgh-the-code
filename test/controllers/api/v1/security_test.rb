require 'test_helper'

class API::V1::SecurityTest < ActionDispatch::IntegrationTest
  def setup
    # Create test users
    @admin_user = User.create!(
      slack_id: "admin_test_001",
      email: "admin@example.com", 
      username: "admin_user",
      is_admin: true
    )
    
    @regular_user = User.create!(
      slack_id: "user_test_001",
      email: "user@example.com",
      username: "regular_user", 
      is_admin: false
    )
    
    @target_user = User.create!(
      slack_id: "target_test_001",
      email: "target@example.com",
      username: "target_user",
      is_admin: false
    )
    
    # Create API keys
    @admin_api_key = APIKey.create!(
      user: @admin_user,
      name: "admin_test_key",
      may_impersonate: true
    )
    
    @user_api_key = APIKey.create!(
      user: @regular_user, 
      name: "user_test_key",
      may_impersonate: true
    )
  end

  test "admin can impersonate other users via API" do
    get "/api/v1/me", 
        params: { impersonate: @target_user.slack_id },
        headers: { 'Authorization' => "Bearer #{@admin_api_key.token}" }
    
    assert_response :success
    response_data = JSON.parse(response.body)
    # The response should show the target user's data, not the admin's
    assert_equal @target_user.slack_id, response_data['slack_id']
  end

  test "regular user cannot impersonate other users via API" do
    get "/api/v1/me",
        params: { impersonate: @target_user.slack_id },
        headers: { 'Authorization' => "Bearer #{@user_api_key.token}" }
    
    assert_response :forbidden
    response_data = JSON.parse(response.body)
    assert_equal "impersonate_unauthorized", response_data['error']
    assert_includes response_data['message'], "not authorized to impersonate"
  end

  test "impersonation attempt with non-existent user returns error" do
    get "/api/v1/me",
        params: { impersonate: "non_existent_user" },
        headers: { 'Authorization' => "Bearer #{@admin_api_key.token}" }
    
    assert_response :bad_request
    response_data = JSON.parse(response.body)
    assert_equal "impersonate_error", response_data['error']
    assert_includes response_data['message'], "couldn't find that user"
  end

  test "API key without impersonation permission cannot impersonate" do
    no_impersonate_key = APIKey.create!(
      user: @admin_user,
      name: "no_impersonate_key", 
      may_impersonate: false
    )
    
    get "/api/v1/me",
        params: { impersonate: @target_user.slack_id },
        headers: { 'Authorization' => "Bearer #{no_impersonate_key.token}" }
    
    assert_response :success
    response_data = JSON.parse(response.body)
    # Should return the API key owner's data, not the target user's
    assert_equal @admin_user.slack_id, response_data['slack_id']
  end

  test "non-admin users cannot create API keys with impersonation privileges" do
    api_key = APIKey.new(
      user: @regular_user,
      name: "test_key",
      may_impersonate: true
    )
    
    assert_not api_key.valid?
    assert_includes api_key.errors[:may_impersonate], "can only be enabled by admin users"
  end

  test "admin users can create API keys with impersonation privileges" do
    api_key = APIKey.new(
      user: @admin_user,
      name: "admin_impersonate_key",
      may_impersonate: true
    )
    
    assert api_key.valid?
  end
end